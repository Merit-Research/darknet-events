package annotate

import (
	"darknet-events/internal/analysis"
	"darknet-events/internal/seqjson"
	"darknet-events/internal/set"

	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"github.com/zmap/go-iptree/iptree"
)

// TODO: These  globals were copied from count.go - they should have a
// permanent home in an internal package where they can be accessed everywhere.

// DarknetSize is the number of IP addresses in the darknet.
var DarknetSize uint32 = 475136

// SmallScanMargin is the number of unique destinations below which a scan is
// considered "small".
var SmallScanMargin int = int(DarknetSize) / 10

// DarknetFactor is the multiplier to extrapolate darknet event values to
// global values.
var DarknetFactor float64 = float64(4294967296) / float64(DarknetSize)

// Output is the data structure that encapsulates the output for each event.
type Output struct {
	SourceIP      string
	Port          uint16
	Traffic       uint16
	First         time.Time
	Last          time.Time
	Packets       uint64
	Bytes         uint64
	UniqueDests   int
	UniqueDest24s int
	Lat           float64
	Long          float64
	Country       string
	City          string
	ASN           int
	Org           string
	Prefix        string
	RDNS          []string
	Zmap          bool
	Masscan       bool
	Mirai         bool
	Samples       []string
	TCP           string
	ICMP          string
}

type ipOutput struct {
	ip     net.IP
	output *Output
}

// Annotator is designed to annotate darknet events by launching reader
// goroutines that tag events based on their characteristics. Annotator's
// EventChannel is used to receive events.
type Annotator struct {
	EventChannel     chan *analysis.Event
	dnsResults       *os.File
	dnsWriter        *seqjson.Writer
	asns             *geoip2.Reader
	locations        *geoip2.Reader
	prefixes         *iptree.IPTree
	minUniques       int
	minScanRate      float64
	dnsServers       []string
	dnsClient        dns.Client
	dnsChannel       chan ipOutput
	packetsAnnotated uint64
	packetsIgnored   uint64
	eventsAnnotated  uint32
	eventsIgnored    uint32
	packetStats      map[int]uint64 // Temp.
	eventStats       map[int]uint32 // Temp.
	wg               sync.WaitGroup
	dnsWG            sync.WaitGroup
}

// NewAnnotator initialises and returns an Annotator.
func NewAnnotator(resultsOutPath string, mmASNInPath string,
	mmGeoInPath string, pfx2asInPath string, dnsServers []string,
	minUniques int, minScanRate float64, newdl bool) *Annotator {

	a := new(Annotator)
	var err error

	// Open the results files.
	a.dnsResults, err = os.Create(resultsOutPath)
	if err != nil {
		log.Fatalf("Could not create event results file: %s.\n", err)
	}

	// Create a JSON writer for results.
	a.dnsWriter = seqjson.NewWriter(a.dnsResults, newdl)

	// Open the ASN and geography databases.
	if mmASNInPath != "" {
		a.asns, err = geoip2.Open(mmASNInPath)
		if err != nil {
			log.Fatalf("Could not open ASN database: %s.\n", err)
		}
	}

	if mmGeoInPath != "" {
		a.locations, err = geoip2.Open(mmGeoInPath)
		if err != nil {
			log.Fatalf("Could not open location database: %s.\n", err)
		}
	}

	// Build prefix tree.
	if pfx2asInPath != "" {
		pfx2asFile, err := os.Open(pfx2asInPath)
		if err != nil {
			log.Fatalf("Could not open pfx2as file: %s\n", err)
		}
		defer pfx2asFile.Close()
		g, err := gzip.NewReader(pfx2asFile)
		var reader io.Reader
		if err != nil {
			// reset file pointer to 0 as gzip.NewReader advances
			// it to the end of an expected gzip header
			pfx2asFile.Seek(0, io.SeekStart)
			reader = pfx2asFile
		} else {
			defer g.Close()
			reader = g
		}
		r := csv.NewReader(reader)
		r.Comma = '\t' // Use tab-delimited instead of comma
		var prefix string
		a.prefixes = iptree.New()
		for {
			record, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			prefix = strings.Join([]string{record[0], record[1]}, "/")
			a.prefixes.AddByString(prefix, prefix)
		}
	}

	// Set up DNS servers and queriers.
	if len(dnsServers) != 0 {
		for i := range dnsServers {
			a.dnsServers = append(a.dnsServers, dnsServers[i]+":53")
		}
		a.dnsClient.Timeout = 15 * time.Second
	}
	a.dnsChannel = make(chan ipOutput)
	for i := 0; i < 1000; i++ {
		a.dnsWG.Add(1)
		go a.dnsQuerier()
	}

	a.minUniques = minUniques
	a.minScanRate = minScanRate

	a.EventChannel = make(chan *analysis.Event)

	a.wg.Add(1)
	go a.Reader()

	// Make temporary stats maps.
	a.packetStats = make(map[int]uint64)
	a.eventStats = make(map[int]uint32)

	return a
}

// Close closes down an annotator, waiting for all readers first.
func (a *Annotator) Close() {
	a.wg.Wait()

	if a.asns != nil {
		a.asns.Close()
	}

	if a.locations != nil {
		a.locations.Close()
	}

	a.dnsWriter.Close()

	log.Printf("Reader annotated %d events, ignored %d.\n",
		a.eventsAnnotated, a.eventsIgnored)
	log.Printf("Reader annotated %d packets, ignored %d.\n",
		a.packetsAnnotated, a.packetsIgnored)
	totalPackets := a.packetsAnnotated + a.packetsIgnored
	totalEvents := a.eventsAnnotated + a.eventsIgnored
	log.Printf("Processed %d events and %d packets.\n",
		totalEvents, totalPackets)

	// Temporary statistics calculations.
	currPacketCoverage := 100 * float64(a.packetsAnnotated) /
		float64(totalPackets)
	currEventCoverage := 100 * float64(a.eventsAnnotated) /
		float64(totalEvents)

	log.Printf("Ignored packets made up %f%% of all packets. Ignored events "+
		"made up %f%% of all events.\n",
		float64(a.packetsIgnored)/float64(totalPackets),
		float64(a.eventsIgnored)/float64(totalEvents))
	log.Printf("At threshold %d, packet coverage was %f%%, "+
		"event coverage was %f%%.\n", a.minUniques, currPacketCoverage,
		currEventCoverage)

	// TODO: Perhaps make this a flag for output?
	/*
		for i := a.minUniques - 1; i > 0; i-- {
			iPacketCoverage := 100 * float64(a.packetStats[i]+a.packetsAnnotated) /
				float64(totalPackets)
			iEventCoverage := 100 * float64(a.eventStats[i]+a.eventsAnnotated) /
				float64(totalEvents)
			log.Printf("At threshold %d, packet coverage would have been %f%%, "+
				"event coverage would have been %f%%.\n", i, iPacketCoverage,
				iEventCoverage)
		}
	*/
}

// Reader sits in a loop taking in events and annotates them with useful
// information such as the event type, AS data, etc.
//
// NOTE: Reader will hang unless the annotator's EventChannel is closed.
func (a *Annotator) Reader() {
	// Enter main loop over events.
	for e := range a.EventChannel {
		es := e.Signature
		ep := e.Packets

		// Create sets to count the number of unique dests and /24 dests.
		unique24s := set.NewUint32Set()
		for k := range *ep.Dests.Map() {
			unique24s.Add(k & 0xffffff00)
		}

		// Ignore if the number of unique destinations is too low.
		if ep.Dests.Size() < a.minUniques {
			a.packetsIgnored += ep.Packets
			a.eventsIgnored++

			// Update temporary stats.
			for i := ep.Dests.Size(); i > 0; i-- {
				a.packetStats[i] += ep.Packets
				a.eventStats[i]++
			}

			continue
		}

		// Ignore if the packet rate is too low.
		scanDuration := ep.Latest.Sub(ep.First).Seconds()
		scanRate := float64(ep.Packets) * DarknetFactor / scanDuration
		if scanRate < a.minScanRate {
			a.packetsIgnored += ep.Packets
			a.eventsIgnored++

			// Update temporary stats.
			for i := ep.Dests.Size(); i > 0; i-- {
				a.packetStats[i] += ep.Packets
				a.eventStats[i]++
			}

			continue
		}

		// Convert the source IP to a net.IP object.
		sourceIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(sourceIP, es.SourceIP)

		// If this is a TCP packet, check if its from zmap, masscan, or mirai.
		var zmap bool
		var masscan bool
		var mirai bool
		if es.Traffic == analysis.TCPSYN {
			zmap = true
			masscan = true
			mirai = true
			for i := 0; i < len(ep.Samples); i++ {
				packet := gopacket.NewPacket(ep.Samples[i],
					layers.LayerTypeEthernet, gopacket.NoCopy)
				if packet == nil {
					log.Fatal("Could not parse packet to fingerprint.")
				}

				nl := packet.NetworkLayer()
				if nl == nil || nl.LayerType() != layers.LayerTypeIPv4 {
					log.Fatal("Contradiction in traffic type and IPv4 parse.")
				}
				ip := nl.(*layers.IPv4)

				tl := packet.TransportLayer()
				if tl == nil || tl.LayerType() != layers.LayerTypeTCP {
					log.Fatal("Contradiction in traffic type and TCP parse.")
				}
				tcp := tl.(*layers.TCP)

				dstIP := binary.BigEndian.Uint32(ip.DstIP.To4())
				dstPort := tcp.DstPort
				seq := tcp.Seq
				id := ip.Id

				if zmap && id != 54321 {
					zmap = false
				}
				if masscan && id != uint16(dstIP^uint32(dstPort)^seq) {
					masscan = false
				}
				if mirai && dstIP != seq {
					mirai = false
				}
			}
		}

		// Get geographic data for the source IP.
		var latitude float64
		var longitude float64
		var country string
		var city string
		if a.locations != nil {
			location, err := a.locations.City(sourceIP)
			if err != nil {
				log.Fatalf("Couldn't check location for IP: %s.\n", err)
			}
			latitude = location.Location.Latitude
			longitude = location.Location.Longitude
			country = location.Country.IsoCode
			city = location.City.Names["en"]
		}

		var asnNumber uint
		var organisation string
		if a.asns != nil {
			asn, err := a.asns.ASN(sourceIP)
			if err != nil {
				log.Fatalf("Couldn't check ASN data for IP: %s\n", err)
			}
			asnNumber = asn.AutonomousSystemNumber
			organisation = asn.AutonomousSystemOrganization
		}

		// Get prefix data.
		var routedPrefix string
		if a.prefixes != nil {
			val, ok, err := a.prefixes.Get(sourceIP)
			if err != nil {
				log.Fatalf("Couldn't look up IP prefix: %s.\n", err)
			}
			if err == nil && ok {
				routedPrefix = val.(string)
			}
		}

		// Convert the saved samples to a string.
		samples := make([]string, len(ep.Samples))
		for i := 0; i < len(ep.Samples); i++ {
			samples[i] = base64.StdEncoding.EncodeToString(ep.Samples[i])
		}

		output := Output{
			SourceIP:      sourceIP.String(),
			Port:          es.Port,
			Traffic:       uint16(es.Traffic),
			First:         ep.First,
			Last:          ep.Latest,
			Packets:       ep.Packets,
			Bytes:         ep.Bytes,
			UniqueDests:   ep.Dests.Size(),
			UniqueDest24s: unique24s.Size(),
			Lat:           latitude,
			Long:          longitude,
			Country:       country,
			City:          city,
			ASN:           int(asnNumber),
			Org:           organisation,
			Prefix:        routedPrefix,
			Zmap:          zmap,
			Masscan:       masscan,
			Mirai:         mirai,
			Samples:       samples,
			// RDNS is populated asynchronously.
		}

		if es.Traffic.IsTCP() == true {
			output.TCP = es.Traffic.ToString()
		} else if es.Traffic.IsICMP() == true {
			output.ICMP = es.Traffic.ToString()
		}

		// Spawn a goroutine to query DNS asynchronously.
		pair := ipOutput{ip: sourceIP, output: &output}
		a.dnsChannel <- pair

		a.packetsAnnotated += ep.Packets
		a.eventsAnnotated++
	}

	// Wait for all pending DNS queries to finish then end.
	close(a.dnsChannel)
	a.dnsWG.Wait()
	a.wg.Done()
}

// dnsQuerier gets DNS information and populates the given output object with
// it. Once the query is complete, the output is written to the dnsWriter.
func (a *Annotator) dnsQuerier() {
	for pair := range a.dnsChannel {
		sourceIP := pair.ip
		output := pair.output

		// If we aren't using DNS, just write what we have.
		if len(a.dnsServers) == 0 {
			// Marshal and write.
			j, err := json.Marshal(*output)
			if err != nil {
				log.Fatalf("Could not marshal DNS data for %s.\n",
					sourceIP.String())
			}

			a.dnsWriter.Write(j)

			continue
		}

		// Get rDNS data.
		revAddr, err := dns.ReverseAddr(sourceIP.String())
		if err != nil {
			log.Fatalf("Could not create reversed DNS address: %s.\n", err)
		}
		dnsMessage := dns.Msg{}

		dnsMessage.SetQuestion(revAddr, dns.TypePTR)
		dnsMessage.RecursionDesired = true
		serverIndex := rand.Intn(len(a.dnsServers))

		// Retry if necessary.
		var record *dns.Msg
		for i := 0; i < 2; i++ {
			record, _, err = a.dnsClient.Exchange(&dnsMessage,
				a.dnsServers[serverIndex])
			if err == nil {
				break
			}
		}
		rdnsNames := make([]string, 0)
		if err != nil {
			log.Printf("Could not get reverse DNS lookup: %s\n", err)
			rdnsNames = append(rdnsNames, "FAILED (ERR)")
		} else {
			for _, ans := range record.Answer {
				if ans.Header().Rrtype != dns.TypePTR {
					log.Printf("Encountered a non-PTR DNS response looking "+
						"up %s.\n", sourceIP.String())
					rdnsNames = append(rdnsNames, "FAILED (NON-PTR)")
					continue
				}
				rdnsNames = append(rdnsNames, ans.(*dns.PTR).Ptr)
			}
		}
		output.RDNS = rdnsNames

		// Marshal and write.
		j, err := json.Marshal(*output)
		if err != nil {
			log.Fatalf("Could not marshal DNS data for %s.\n",
				sourceIP.String())
		}

		a.dnsWriter.Write(j)
	}

	a.dnsWG.Done()
}
