package main

import (
	"container/heap"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
)

// Config is a struct containing the program's configuration info.
type Config struct {
	SenderExpiry          int
	MinUniques            int
	MinScanRate           float64
	NumSamples            int
	CacheInPath           string
	CacheOutPath          string
	EventOutPrefix        string
	OngoingEventOutPrefix string
	MMASNInPath           string
	MMGeoInPath           string
	Pfx2asInPath          string
	DNSServers            []string
	PcapPaths             []string
	ProfileCPUPath        string
	ProfileMemPath        string
	Newdl                 bool
}

// config loads configuration information from the given flags. It is expected
// that this slice is os.Args.
func config() *Config {
	var cfg Config

	threshold := flag.Int("threshold", 0, "Number of seconds that "+
		"must elapse before an event is considered over.")
	minUniques := flag.Int("uniques", 1, "Minimum number of unique "+
		"destinations that must be hit for an event to be considered (must " +
		"be a positive number).")
	minScanRate := flag.Float64("rate", 0, "Minimum global packet rate for "+
		"an event to be considered.")
	numSamples := flag.Int("samples", 0, "Number of packet samples "+
		"to save from each event.")
	mmASNInPathString := flag.String("asnin", "", "Path to the MaxMind ASN "+
		"database.")
	mmGeoInPathString := flag.String("geoin", "", "Path to the MaxMind "+
		"location database.")
	pfx2asInPathString := flag.String("pfx2asin", "", "Path to the pfx2as "+
		"database.")
	dnsServersString := flag.String("dns", "", "DNS server IP address(es).")
	cacheInPathString := flag.String("cachein", "", "Path to load cache "+
		"entries from before analysis starts.")
	cacheOutPathString := flag.String("cacheout", "", "Path to dump  "+
		"remaining cache entries to for later use.")
	eventOutPrefixString := flag.String("eventout", "", "Prefix of path to "+
		"save captured event data to.")
	ongoingEventOutPrefixString := flag.String("ongoingout", "", "Prefix of "+
		"path to save captured event data to.")
	pcapPathsString := flag.String("pcap", "", "Path to pcap files. Multiple "+
		"paths must be separated by a space.")
	profileCPUPathString := flag.String("cpu", "", "Output path for CPU "+
		"profile. No profiling if not included.")
	profileMemPathString := flag.String("mem", "", "Output path for memory "+
		"profile. No profiling if not included.")
	newdlBool := flag.Bool("newdl", false, "True if JSON output needs to be "+
		"newline-delimited.")
	flag.Parse()

	// Ensure that all non-optional flags are set.
	if *threshold == 0 {
		log.Fatal("Must specify a threshold timeout.")
	}
	if *numSamples == 0 {
		log.Fatal("Must specify how many samples to take.")
	}
	if *eventOutPrefixString == "" {
		log.Fatal("Must specify a location to write event data to.")
	}
	if *pcapPathsString == "" {
		log.Fatal("Must specify at least one pcap file.")
	}
	if *minUniques <= 0 {
		log.Fatal("Must specify a positive uniques number.")
	}

	// Process and save parameters.
	cfg.SenderExpiry = *threshold
	cfg.MinUniques = *minUniques
	cfg.MinScanRate = *minScanRate
	cfg.NumSamples = *numSamples
	cfg.CacheInPath = *cacheInPathString
	cfg.CacheOutPath = *cacheOutPathString
	cfg.EventOutPrefix = *eventOutPrefixString
	cfg.OngoingEventOutPrefix = *ongoingEventOutPrefixString
	cfg.MMASNInPath = *mmASNInPathString
	cfg.MMGeoInPath = *mmGeoInPathString
	cfg.Pfx2asInPath = *pfx2asInPathString
	if *dnsServersString != "" {
		cfg.DNSServers = strings.Split(*dnsServersString, " ")
	} else {
		cfg.DNSServers = make([]string, 0, 0)
	}
	cfg.PcapPaths = strings.Split(*pcapPathsString, " ")
	cfg.ProfileCPUPath = *profileCPUPathString
	cfg.ProfileMemPath = *profileMemPathString
	cfg.Newdl = *newdlBool

	return &cfg
}

type Request struct {
	data []byte
	response chan []byte
}

func requester(req chan Request, input chan *os.File, pcapFile *os.File) {
	response := make(chan []byte)

	handle, err := pcapgo.NewReader(pcapFile)
	if err != nil {
		log.Fatal("Failed to open pcap file: ", err)
	}
	// spawn requests indefinitely
	for {
		read, _, err := handle.ReadPacketData()

		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal("Could not read packet data: ", err)
		}
		// wait before next request
		req <- Request{read, response}
		// read value from RESP channel
		<- response // output
		// future processing, e.g., write to the cache
	}

	input <- pcapFile

	err = pcapFile.Close()
	if err != nil {
		log.Printf("An error occurred when closing file %s.\n", pcapFile.Name())
	}
}

type Worker struct {
	// heap index
	idx        int
	// work channel
	work chan Request // {input, output}
	// number of pending request this worker is working on
	pending  int
}

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

type Balancer struct {
	// a pool of workers
	pool Pool
	workerDone chan *Worker
	// these two variables are for shutting down the balancer
	requesterDone chan *os.File
	numRequesters int
}

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

func main() {
	cfg := config()
	numRequesters := len(cfg.PcapPaths)
	work := make(chan Request)
	input := make(chan *os.File, numRequesters)

	for _, path := range cfg.PcapPaths {
		pcapFile, _ := os.Open(path)

		go requester(work, input, pcapFile)
	}
	InitBalancer(numRequesters, input).balance(work)
}
