package main

import (
	"darknet-events/internal/annotate"
	"darknet-events/internal/cache"
	"darknet-events/internal/decode"

	"flag"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Config is a struct containing the program's configuration info.
type Config struct {
	SenderExpiry   int
	MinUniques     int
	MinScanRate    float64
	NumSamples     int
	CacheInPath    string
	CacheOutPath   string
	EventOutPrefix string
	MMASNInPath    string
	MMGeoInPath    string
	Pfx2asInPath   string
	DNSServers     []string
	InterfaceName  string
	ProfileCPUPath string
	ProfileMemPath string
	Newdl          bool
}

// config loads configuration information from the given flags. It is expected
// that this slice is os.Args.
func config() *Config {
	var cfg Config

	threshold := flag.Int("threshold", 0, "Number of seconds that "+
		"must elapse before an event is considered over.")
	minUniques := flag.Int("uniques", 0, "Minimum number of unique "+
		"destinations that must be hit for an event to be considered.")
	minScanRate := flag.Float64("rate", 0, "Minimum global packet rate for an "+
		"event to be considered.")
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
	interfaceNameString := flag.String("interface", "", "Name of interface "+
		"to read from")
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
	if *interfaceNameString == "" {
		log.Fatal("Must specify an interface to read from.")
	}

	// Process and save parameters.
	cfg.SenderExpiry = *threshold
	cfg.MinUniques = *minUniques
	cfg.MinScanRate = *minScanRate
	cfg.NumSamples = *numSamples
	cfg.CacheInPath = *cacheInPathString
	cfg.CacheOutPath = *cacheOutPathString
	cfg.EventOutPrefix = *eventOutPrefixString
	cfg.MMASNInPath = *mmASNInPathString
	cfg.MMGeoInPath = *mmGeoInPathString
	cfg.Pfx2asInPath = *pfx2asInPathString
	if *dnsServersString != "" {
		cfg.DNSServers = strings.Split(*dnsServersString, " ")
	} else {
		cfg.DNSServers = make([]string, 0, 0)
	}
	cfg.InterfaceName = *interfaceNameString
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

	// Start an annotator and cache.
	a := annotate.NewAnnotator(cfg.EventOutPrefix, cfg.MMASNInPath,
		cfg.MMGeoInPath, cfg.Pfx2asInPath, cfg.DNSServers,
		cfg.MinUniques, cfg.MinScanRate, cfg.Newdl)
	c := cache.NewCache(cfg.SenderExpiry, cfg.CacheInPath,
		cfg.CacheOutPath, a.EventChannel, cfg.NumSamples, cfg.MinUniques)

	// TODO: Remove the temporal dependence on cache and annotator close order.
	defer a.Close()
	defer c.Close()

	d := decode.NewDecoder()
	defer d.Close()

	// Run analysis loop.
	dev, err := pcap.OpenLive(cfg.InterfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Could not open interface: ", err)
	}
	source := gopacket.NewPacketSource(dev, dev.LinkType())
	for packet := range source.Packets() {
		read := packet.Data()
		meta := packet.Metadata().CaptureInfo

		event, dest, time := d.Decode(read, meta)
		c.Add(*event, dest, time, read)
	}
}
