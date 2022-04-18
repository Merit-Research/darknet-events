//
// All software tools within this package are Copyright (c) 2020 Merit Network, Inc.,
// and Stanford University. All Rights Reserved.
//

package main

import (
	"darknet-events/internal/annotate"
	"darknet-events/internal/cache"
	"darknet-events/internal/decode"
	"github.com/OneOfOne/xxhash"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"hash"

	"flag"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/google/gopacket/pcapgo"
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

var h32 hash.Hash32 = xxhash.New32()

// config loads configuration information from the given flags. It is expected
// that this slice is os.Args.
func config() *Config {
	var cfg Config

	threshold := flag.Int("threshold", 0, "Number of seconds that "+
		"must elapse before an event is considered over.")
	minUniques := flag.Int("uniques", 1, "Minimum number of unique "+
		"destinations that must be hit for an event to be considered (must "+
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

func main() {
	// Capture and log the amount of time the entire program took.
	runStart := time.Now()
	defer func() {
		runEnd := time.Now()
		log.Printf("Executed in %s.\n", runEnd.Sub(runStart).String())
	}()

	cfg := config()

	// Start CPU profiling if necessary.
	if cfg.ProfileCPUPath != "" {
		f, err := os.Create(cfg.ProfileCPUPath)
		if err != nil {
			log.Fatal("Could not create CPU profile file:", err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	// Create memory profile if necessary.
	if cfg.ProfileMemPath != "" {
		f, err := os.Create(cfg.ProfileMemPath)
		if err != nil {
			log.Fatal("Could not create memory profile file:", err)
		}
		defer func() {
			defer f.Close()
			runtime.GC()
			err = pprof.WriteHeapProfile(f)
			if err != nil {
				log.Fatal("Could not write memory profile: ", err)
			}
		}()
	}

	// Start an annotator (two if ongoing events are desired) and cache.
	a := annotate.NewAnnotator(cfg.EventOutPrefix, cfg.MMASNInPath,
		cfg.MMGeoInPath, cfg.Pfx2asInPath, cfg.DNSServers,
		cfg.MinUniques, cfg.MinScanRate, cfg.Newdl)
	var oa *annotate.Annotator
	var c *cache.Cache
	if cfg.OngoingEventOutPrefix != "" {
		log.Println("Creating annotator for ongoing events.")
		oa = annotate.NewAnnotator(cfg.OngoingEventOutPrefix, cfg.MMASNInPath,
			cfg.MMGeoInPath, cfg.Pfx2asInPath, cfg.DNSServers,
			cfg.MinUniques, cfg.MinScanRate, cfg.Newdl)
		c = cache.NewCache(cfg.SenderExpiry, cfg.CacheInPath, cfg.CacheOutPath,
			a.EventChannel, oa.EventChannel, cfg.NumSamples, cfg.MinUniques)
	} else {
		c = cache.NewCache(cfg.SenderExpiry, cfg.CacheInPath, cfg.CacheOutPath,
			a.EventChannel, nil, cfg.NumSamples, cfg.MinUniques)
	}

	// TODO: Remove the temporal dependence on cache and annotator close order.
	defer a.Close()
	if cfg.OngoingEventOutPrefix != "" {
		defer oa.Close()
	}
	defer c.Close()

	d := decode.NewDecoder()
	defer d.Close()

	// Check that all given pcap files exist before running main loop.
	for _, path := range cfg.PcapPaths {
		pfile, err := os.Open(path)
		if err != nil {
			log.Fatal("Failed to open pcap file: ", err)
		}
		pfile.Close()
	}

	// Run analysis loop.
	for _, path := range cfg.PcapPaths {
		pfile, _ := os.Open(path)
		defer pfile.Close()
		handle, err := pcapgo.NewReader(pfile)
		if err != nil {
			log.Fatal("Failed to open pcap file: ", err)
		}

		for {
			read, meta, err := handle.ReadPacketData()
			// TODO: Check sampling with:
			// read, meta, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Fatal("Could not read packet data: ", err)
			}

			ethP := gopacket.NewPacket(read, layers.LayerTypeEthernet, gopacket.Default)
			source := ethP.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
			h32.Write([]byte(source)[:4])
			//fmt.Println(h32.Sum32() >> 30, source.To4())
			h32.Reset()

			// TODO: Is meta.CaptureLength == len(read)?
			event, dest, time := d.Decode(read, meta)
			c.Add(*event, dest, time, read)
		}

		log.Printf("Decoded %s, cache size is %d bytes.\n", path, c.Size())
	}
}
