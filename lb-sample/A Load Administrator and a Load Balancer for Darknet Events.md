## A Load Administrator and a Load Balancer for Darknet Events

Sebastian Jin (rongjin@umich.edu)

Created 08/2021



### Overview

This document introduces a producer-consumer model and a load balancer for balancing the consumers' works in Go. It aims to motivate future work that meets specific requirements for the Darknet project. This document first breaks down the skeleton of the model architecture into several components. Then, there is a section for the detail of the requirements. Finally, we have a discussion section for discussing how to adjust the code skeleton for those requirements and the things we need to take care of.



### Model Architecture

Here is a visualization of the model architecture:

```
|---------|                    |--------|                   |-------| 
|         | --[1]request-----> |        | <-[3]workerDone-- |       | 
|         |                    |Balancer|                   |       |
|Requester| --[5]requestDone-> |        | --[2]work-------> |Workers|
|         |                    |--------|                   |       |
|         | <------------------[4]response----------------- |       |
|---------|                                                 |-------|
```

- [1] The `Requester` initiates a work request to the `Balancer` via the `request` channel.

- [2] The `Balancer` selects the top `Worker` in the worker pool and assigns the work to it via the `work` channel. The pool is a priority queue ordered by the number of pending works for each worker.
- [3] A `Worker` has done the work and notifies the `Balancer` via the `workerDone` channel to re-order the worker pool.
- [4] In the meantime, the `Worker` gives a response back to the `Requester` via the `response` channel. The response would contain the result of the work so that the `Requester` can enter into the next phase of processing with this result as an input.
- [5] Finally, once all the requests are done, the `Requester` notifies the `Balancer` via the `requesterDone` channel. After receiving this message, the `Balancer` shuts down.

The most important part for such communications are the channels in play. Generically, there are

- one `request` channel,
- $n$ `workerDone` channels corresponding to $n$ workers and a worker pool with a size of $n$,
- $k$​ `work` channels for each worker to receive requests from the balancer and send the result to $k$​ requesters,
- and $k$​​​ `requesterDone` channels for knowing how many requesters become inactive and deciding when to terminate the balancer.

This generic model can have multiple variants depending on specific program requirements. All the types and number of channels are subject to change.

The architecture has five main components: the requester(s), the request, the workers, the worker pool, and the balancer.

#### Requester(s)

The requester(s) are not necessarily of the `struct` type. They can be of the function type that runs in separate goroutines. In the example code, a requester is a function that has a signature of `func requester(req chan Request, input chan *os.File, pcapFile *os.File)`. The `req` channel is shared with the balancer, and the `input` channel is used for notifying the balancer that the pcap file has been processed. The `pcapFile` is the pcap file that needs to be processed.

#### Request

The request is defined as

```go
type Request struct {
	data []byte
	response chan []byte
}
```

in the example code. Generically, it can be

```go
type Request struct {
	data dataStructType
	response chan ResponseStructType
}
```

where both the `data` field and the `response` field are of the `struct` type that carry all the inputs and outputs.

#### Workers

A worker is defined as

```go
type Worker struct {
    // heap index
    idx        int
    // work channel
    work chan Request // {input, output}
    // number of pending request this worker is working on
    pending  int
}
```

with a main function of doing the work

```go
func (w *Worker) doWork(done chan *Worker) {
    // worker works indefinitely
    for {
        // extract request from the work channel
        req := <- w.work
        // do the work
        req.response <- req.data
        // write to the done channel
        done <- w
    }
}
```

#### Worker Pool

A worker pool is a slice of workers that implements the heap interface so that it can be used to prioritize the next available worker to do the work.

```go
type Pool []*Worker

func (p Pool) Len() int { return len(p) }

func (p Pool) Less(i, j int) bool {
    return p[i].pending < p[j].pending
}

func (p *Pool) Swap(i, j int) {
    a := *p
    a[i], a[j] = a[j], a[i]
    a[i].idx = i
    a[j].idx = j
}

func (p *Pool) Push(x interface{}) {
    n := len(*p)
    item := x.(*Worker)
    item.idx = n
    *p = append(*p, item)
}

func (p *Pool) Pop() interface{} {
    old := *p
    n := len(old)
    item := old[n-1]
    // safely remove the next available worker
    item.idx = -1
    *p = old[0 : n-1]

    return item
}
```

#### Balancer

The balancer is defined as

```go
type Balancer struct {
    // a pool of workers
    pool Pool
    workerDone chan *Worker
    // these two variables are for shutting down the balancer
    requesterDone chan *os.File
   	numRequesters int
}
```

We initialize all the workers and the worker pool when initializing the balancer

```go
func InitBalancer(numRequesters int, input chan *os.File) *Balancer {
    // runtime.GOMAXPROCS(0) helps us decide the ideal number of workers
    numWorkers := runtime.GOMAXPROCS(0)
   	workerDone := make(chan *Worker, numWorkers)
    b := &Balancer{
        make(Pool, 0, numWorkers),
        workerDone,
        input,
        numRequesters,
    }

    for i := 0; i < numWorkers; i++ {
        w := &Worker{
            idx: i,
            work: make(chan Request, numRequesters),
            pending: 0,
        }
        // put them in heap
        heap.Push(&b.pool, w)
        go w.doWork(b.workerDone)
    }

    return b
}
```

and maintain the load in the balance function

```go
func (b *Balancer) balance(req chan Request) {
    remainingRequests := b.numRequesters
    for remainingRequests > 0 {
        select {
            // when there is a new job
            case request := <- req:
            b.dispatch(request)
            // when a worker has done the job
            case w := <- b.workerDone:
            b.completed(w)
            // when a request is completely done
            case _ = <- b.requesterDone:
            remainingRequests -= 1
            break
        }
        // print the stats
        b.print()
    }
}

func (b *Balancer) dispatch(req Request) {
    // not checking for nullity as the pool is maintained by ourselves
    // grab least loaded worker
    w := heap.Pop(&b.pool).(*Worker)
    w.work <- req
    w.pending++
    // put it back into heap while it is working
    heap.Push(&b.pool, w)
}

func (b *Balancer) completed(w *Worker) {
    w.pending--
    // remove from heap
    heap.Remove(&b.pool, w.idx)
    // put it back
    heap.Push(&b.pool, w)
}
```

We can also have a print function in the balancer to monitor the stats of the loads

```go
func (b *Balancer) print() {
    sum := 0
    sumsq := 0
    // print pending stats for each worker
    for _, w := range b.pool {
        fmt.Printf("%d ", w.pending)
        sum += w.pending
        sumsq += w.pending * w.pending
    }
    // print avg for worker pool
    avg := float64(sum) / float64(len(b.pool))
    variance := float64(sumsq)/float64(len(b.pool)) - avg*avg
    fmt.Printf(" %.2f %.2f\n", avg, variance)
}
```



### Requirements

A scanner scans endlessly and relentlessly. For a specific time period (1-hour slot, 2-hour slot, 12-hour slot, etc.), we want to keep track of the activities of a scanner to better understand its actions. Therefore, we require our parse program to have some features such that the decoded and annotated pcap files can always group the results of certain scanners into one file. A simple grouping scheme could be that we group together all the scanners who have an odd number of their IPv4 addresses after translating their IPs into integers. The workflow could be summarized as follows:

- Read a pcap file as a requester.
- For each entry of the pcap file, send the entry to the balancer.
- The balancer applies a defined scheme such that makes the balancer always distribute the activity of a certain scanner to a certain worker.
- The worker decode and annotate the entry.
- The worker writes the intermediate result to a global cache.
- The worker writes the results to a file.
- (If necessary) use the cache for the next round's (i.e., next time slot's) processing and read the next pcap file to go through the work flow again.



### Discussions

Based on the requirements, we need to review the model architecture and modify some parts of our original modules.

The first thing is **defining a scheme in the balancer**. The balancer is not distributing works based on loads (we will call it `Admin` in the following graph); it is distributing works based on the defined scheme. The scheme might involve hashing functions that deterministically assign the pcap entry of certain scanners to particular workers.

The second modification is **fitting the decoder module and the annotator module into the worker**. For example, we now need some light preprocessing to know the IP address of scanners for the balancing scheme. Also, we need to take care of some concurrency issues when caching intermediate results and doing annotations.

Last but not the least, **balancing the loads** might still be necessary. Chances are that specific workers will have more work to do on average than other workers. We can add another layer of load-balancing for each worker where we instantiate an actual load-balancer with a sub-worker pool for that specific worker.

```
                        |-----|                 |--------|                  |----------|                |------|
                        |     |                 |        | --workerReq----> |Balancer 1| <--workComm--> |      | 
                        |     | --workGroup---> |Worker 1|                  |----------|                |Pool 1|
|---------|             |     |                 |        | <--workResp--------------------------------- |      |
|         | --Req-----> |     |                 |--------|                                              |------|
|Requester|             |Admin| --workGroup---> |   :    |
|         | --ReqDone-> |     |                 |   :    |
|---------|             |     |                 |--------|
                        |     |                 |        |
                        |     | <--workerDone-- |Worker N|
                        |     |                 |        |
                        |-----|                 |--------|
```

