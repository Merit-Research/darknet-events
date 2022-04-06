package cache

//go:generate msgp

import (
	"github.com/clarkduvall/hyperloglog"
	"io"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/tinylib/msgp/msgp"

	"darknet-events/internal/analysis"
)

// Cache is a time-to-live cache that tracks packet data keyed on certain
// characteristics.
//
// Note: Several members are exported due to gob's inability to gob unexported
// members. These members should nevertheless not be directly accessed outside
// of this package.
type Cache struct {
	// The cache itself.
	Cache map[analysis.EventSignature]*analysis.EventPackets `msg:"-"`
	// Last time the cache was cleared.
	Cleared time.Time
	// Timestamp of first entry in cache.
	First time.Time
	// Timestamp of latest entry in cache.
	Now time.Time
	// Reservoir sampler.
	sampler *Sampler
	// Num. events to accept w/o sampling.
	sampleMargin int
	// How long before entries expire.
	timeout time.Duration
	// File path to write new cache state to.
	outPath string
	// The channel to send expired events to.
	eventChannel chan *analysis.Event
	// The channel to send ongoing events to (can be nil).
	ongoingEventChannel chan *analysis.Event
}

// NewCache allocates and initialises a new Cache with a packet expiry time of
// timeout. The Cache will set its expiry timout to the given timeout, load a
// previously saved state from inPath (if given), and create an output state at
// outPath (if given).
func NewCache(timeout int, inPath string, outPath string,
	eventChannel chan *analysis.Event,
	ongoingEventChannel chan *analysis.Event,
	numSamples int, minUniques int) *Cache {

	c := new(Cache)
	c.sampler = newSampler(numSamples)
	c.sampleMargin = minUniques - 1
	c.timeout = time.Duration(timeout) * time.Second
	c.eventChannel = eventChannel
	c.ongoingEventChannel = ongoingEventChannel

	// Load in the old state if a path is given.
	if inPath != "" {
		log.Println("Loading in old entries from cache input file.")

		in, err := os.Open(inPath)
		if err != nil {
			log.Fatalf("Couldn't open cache input file: %s.\n", err)
		}
		defer in.Close()

		c.load(in)
	} else {
		c.Cache = make(map[analysis.EventSignature]*analysis.EventPackets)
	}

	// Check that an output state file can be created if given. This only
	// serves to check that the file can be created so that the user doesn't
	// have to wait for all cache processing to occur before realising that
	// they can't save the state at the end. Note that if the path's conditions
	// change during runtime, the write could still fail later.
	if outPath != "" {
		out, err := os.Create(outPath)
		if err != nil {
			log.Fatalf("Couldn't create cache output file: %s.\n", err)
		}
		defer out.Close()
		c.outPath = outPath
	}

	return c
}

// Add adds a new entry to the cache keyed on k. Any previous cache on the same
// key will be expired beforehand if they have exceeded their timeout. Add may
// also add the raw bytes of the packet as a sample.
func (c *Cache) Add(es analysis.EventSignature,
	ip uint32, t time.Time, raw []byte) {

	// If we don't have a known first packet time, this is the first packet.
	if c.First.IsZero() {
		c.First = t
	}

	// If it is time to clear expired entries, stop the world and do so. If
	// stw doesn't neet to run but the key exists and is expired, expire it.
	if c.Now.Sub(c.Cleared) > c.timeout {
		c.stw()
	} else if _, ok := c.Cache[es]; ok && c.check(es, t) {
		c.expire(es)
	}

	// Add the new packet data to the cache.
	if _, ok := c.Cache[es]; !ok {
		c.Cache[es] = analysis.NewEventPackets()
	}
	i := c.Cache[es].Add(ip, uint64(len(raw)), t)

	// If this packet should be sampled, do so.
	// NOTE: We only sample once there have been enough packets to possibly
	// meet the MinUniques threshold.
	if i >= c.sampleMargin {
		sampleIndex := c.sampler.sample(i - c.sampleMargin)
		if sampleIndex != -1 {
			c.Cache[es].AddSample(sampleIndex, raw)
		}
	}

	c.Now = t
}

// Size calculates the total memory consumed by the c.Cache, including its
// members.
//
// NOTE: This doesn't account for internal parts of the map maintained by the
// runtime, such as the map's collision handling structures.
func (c *Cache) Size() uintptr {
	var size uintptr
	for k, v := range c.Cache {
		size += unsafe.Sizeof(k)
		size += v.Size()
	}
	return size
}

// Close tears down a cache and all its data structures. This function also
// saves the state of the Cache so that it can be loaded in at a later point.
// This is useful if the Cache needs to be initialised to have packet data
// before receiving more.
func (c *Cache) Close() {
	// Clear the cache of any expired entries.
	c.stw()

	// If given, write out all ongoing scans to the ongoing output file.
	if c.ongoingEventChannel != nil {
		log.Println("Writing ongoing events.")
		c.annotateOngoing()

		// Close the ongoing event channel to signify that there are no more
		// events coming.
		close(c.ongoingEventChannel)
	}

	// Write the state out to the output state file. If no output state is
	// given, flush the cache.
	if c.outPath != "" {
		out, err := os.Create(c.outPath)
		if err != nil {
			log.Printf("Couldn't create cache output file: %s.\n", err)
			return
		}
		defer out.Close()

		c.dump(out)
	} else {
		c.flush()
	}

	// Close the event channel to signify that there are no more events coming.
	close(c.eventChannel)

	log.Println("Cache closed.")
}

// check checks if the cache entry at the given key k is expired by the time t
// and returns true if so.
func (c *Cache) check(es analysis.EventSignature, t time.Time) bool {
	return t.Sub(c.Cache[es].Latest) > c.timeout
}

// expire removes the entry at a given key k. The key and entry will be passed
// off to the cache's out channel for further processing.
func (c *Cache) expire(es analysis.EventSignature) {
	event := analysis.NewEvent(es, c.Cache[es])
	c.eventChannel <- event
	delete(c.Cache, es)
}

// stw goes through every entry in the cache and expires any entries that have
// timed out. This function "stops the world" in the process, not allowing any
// other operations to take place.
func (c *Cache) stw() {
	for e := range c.Cache {
		if c.check(e, c.Now) {
			c.expire(e)
		}
	}
	c.Cleared = c.Now
	log.Printf("Entries through %s have entered cache.", c.Now.String())
}

// annotateOngoing sends all currently ongoing events to the ongoingAnnotator.
// The caller is responsible for ensuring that this field has been set prior
// to calling.
func (c *Cache) annotateOngoing() {
	log.Printf("%d ongoing to annotate.\n", len(c.Cache))
	for es := range c.Cache {
		event := analysis.NewEvent(es, c.Cache[es])
		c.ongoingEventChannel <- event
	}
}

// flush flushes all entries from the cache.
func (c *Cache) flush() {
	for es := range c.Cache {
		c.expire(es)
	}
}

// load loads cache state from a given state file.
func (c *Cache) load(in io.Reader) {
	// Capture and log the time it took to load the state file.
	log.Println("Loading cache state from input file.")
	loadStart := time.Now()
	defer func() {
		loadEnd := time.Now()
		log.Printf("Loaded cache state from input file in %s.\n",
			loadEnd.Sub(loadStart).String())
	}()

	c.Cache = make(map[analysis.EventSignature]*analysis.EventPackets)

	r := msgp.NewReader(in)
	var err error
	err = c.DecodeMsg(r)
	if err != nil {
		log.Fatal("Failed to decode cache metadata")
	}
	i := 0
	for err == nil {
		k := analysis.EventSignature{}
		err = k.DecodeMsg(r)
		if err != nil {
			break
		}
		v := analysis.EventPackets{}
		err = v.DecodeMsg(r)
		if err != nil {
			break
		}

		capbytes, err := r.ReadInt()
		if err != nil {
			log.Fatal("Could not decode number of bytes: ", err)
		}

		buf := make([]byte, capbytes)
		buf, err = r.ReadBytes(buf)
		if err != nil {
			err = msgp.WrapError(err, "Dest bytes", buf)
			return
		}

		v.Dests, _ = hyperloglog.NewPlus(5)
		err = v.Dests.GobDecode(buf)
		if err != nil {
			log.Fatal("Could not Decode Dests", err)
		}

		c.Cache[k] = &v
		i++
	}
	if err != nil && msgp.Cause(err) != io.EOF {
		log.Printf("%T\n", msgp.Cause(err))
		log.Fatal("Could not decode cache: ", msgp.Cause(err))
	}

	log.Printf("Cache size at load is %d.\n", c.Size())
}

// dump writes the cache state to the given state file.
func (c *Cache) dump(out io.Writer) {
	// Capture and log the time it took to save the state file.
	log.Println("Saving cache state to output file.")
	dumpStart := time.Now()
	defer func() {
		dumpEnd := time.Now()
		log.Printf("Saved cache state to output file in %s.\n",
			dumpEnd.Sub(dumpStart).String())
		log.Printf("Cache size at dump is %d.\n", c.Size())
	}()

	w := msgp.NewWriter(out)
	var err error
	err = c.EncodeMsg(w)
	if err != nil {
		log.Fatal("Failed to encode cache metadata: ", err)
	}
	for k, v := range c.Cache {
		err = k.EncodeMsg(w)
		if err != nil {
			log.Fatal("Failed to encode cache key: ", err)
		}
		err = v.EncodeMsg(w)
		if err != nil {
			log.Fatal("Failed to encode cache value: ", err)
		}

		bytes, err2 := v.Dests.GobEncode()
		if err2 != nil {
			log.Fatal("Failed to encode cache value for Dests", err)
		}

		// Save how many bytes we will encode; needed for the decoding phase
		var capbytes int = cap(bytes)
		err = w.WriteInt(capbytes)
		if err != nil {
			log.Fatal("Failed to encode int value for Dests", err)
		}

		err = w.WriteBytes(bytes)
		if err != nil {
			log.Fatal("Failed to write encoded value for Dests", err)
		}

	}
	err = w.Flush()
	if err != nil {
		log.Fatal("Failed to flush cache state: ", err)
	}
}
