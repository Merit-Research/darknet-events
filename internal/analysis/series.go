package analysis

import (
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"time"
)

// TODO: Move to unify with count.go.
type NoIPSig struct {
	Port    uint16
	Traffic TrafficType
}

func NewNoIPSig(port uint16, traffic uint16) NoIPSig {
	no := NoIPSig{Port: port, Traffic: TrafficType(traffic)}
	return no
}

// PacketEventCount stores a packet count and an event count.
type PacketEventCount struct {
	Packets uint64
	Events  uint32
}

// PacketEventCount stores a packet count and an event count as floats.
type PacketEventCountFloat struct {
	Packets float64
	Events  float64
}

// Series holds data in a time series.
type Series struct {
	S          []map[NoIPSig]*PacketEventCount      // Time series data
	A          []map[NoIPSig]*PacketEventCountFloat // Moving averages
	D          []map[NoIPSig]*PacketEventCountFloat // Deviation
	Signatures map[NoIPSig]struct{}
	Interval   int
	Length     int
	Window     int
}

// NewSeries initialises a new Series object.
func NewSeries(length int, interval int, window int) *Series {
	s := new(Series)
	s.S = make([]map[NoIPSig]*PacketEventCount, length, length)
	s.A = make([]map[NoIPSig]*PacketEventCountFloat, length, length)
	s.D = make([]map[NoIPSig]*PacketEventCountFloat, length, length)
	s.Signatures = make(map[NoIPSig]struct{})
	for i := 0; i < length; i++ {
		s.S[i] = make(map[NoIPSig]*PacketEventCount)
		s.A[i] = make(map[NoIPSig]*PacketEventCountFloat)
		s.D[i] = make(map[NoIPSig]*PacketEventCountFloat)
	}
	s.Interval = interval
	s.Length = length
	s.Window = window

	return s
}

// LoadSeries loads a Series object from the given path. If there are more
// intervals to add, it will initialise space for them. This function makes
// no accomodations for a difference in interval between the loaded Series
// object and files that will be added.
func LoadSeries(path string) *Series {
	// Capture and log the time it took to load the state file.
	log.Println("Loading time-series state from input file.")
	dumpStart := time.Now()
	defer func() {
		dumpEnd := time.Now()
		log.Printf("Loaded time-series state from input file in %s.\n",
			dumpEnd.Sub(dumpStart).String())
	}()

	s := new(Series)

	in, err := os.Open(path)
	if err != nil {
		log.Fatal("Failed to open time-series state: ", err)
	}
	defer in.Close()

	enc := gob.NewDecoder(in)
	err = enc.Decode(s)
	if err != nil {
		log.Fatal("Failed to decode time-series state: ", err)
	}

	// TODO: Expand for new items.

	return s
}

// DumpSeries dumps a Series object to the given path.
func (s *Series) DumpSeries(path string) {
	// Capture and log the time it took to save the state file.
	log.Println("Saving time-series state to output file.")
	dumpStart := time.Now()
	defer func() {
		dumpEnd := time.Now()
		log.Printf("Saved time-series state to output file in %s.\n",
			dumpEnd.Sub(dumpStart).String())
	}()

	out, err := os.Create(path)
	if err != nil {
		log.Fatal("Could not create file to dump time series: ", err)
	}
	defer out.Close()

	enc := gob.NewEncoder(out)
	err = enc.Encode(s)
	if err != nil {
		log.Fatal("Failed to encode time-series: ", err)
	}
}

func (s *Series) Add(i int, k NoIPSig, v uint64) {
	// Add to signature set.
	if _, found := s.Signatures[k]; found == false {
		var noMem struct{}
		s.Signatures[k] = noMem
	}

	if s.S[i][k] == nil {
		s.S[i][k] = new(PacketEventCount)
	}
	s.S[i][k].Packets += v
	s.S[i][k].Events++
}

func (s *Series) Calc() {
	for i := 0; i < s.Length; i++ {
		for sig := range s.Signatures {
			// If the signature wasn't encountered on the day, backfill with 0.
			if s.S[i][sig] == nil {
				s.S[i][sig] = new(PacketEventCount)
				s.S[i][sig].Packets = 0
				s.S[i][sig].Events = 0
			}

			// Create the average and deviation entries.
			if s.A[i][sig] == nil {
				s.A[i][sig] = new(PacketEventCountFloat)
			}
			if s.D[i][sig] == nil {
				s.D[i][sig] = new(PacketEventCountFloat)
			}

			// If we don't have enough data to calculate an average, move on.
			if i < s.Window-1 {
				s.A[i][sig].Packets = 0
				s.A[i][sig].Events = 0
				s.D[i][sig].Packets = 0
				s.D[i][sig].Events = 0
				continue
			}

			// Calculate the rolling sum.
			var packetSum uint64
			var eventSum uint32
			for j := i - s.Window + 1; j <= i; j++ {
				if s.S[j][sig] != nil {
					packetSum += s.S[j][sig].Packets
					eventSum += s.S[j][sig].Events
				}
			}

			// Calculate the moving average.
			s.A[i][sig].Packets = float64(packetSum) / float64(s.Window)
			s.A[i][sig].Events = float64(eventSum) / float64(s.Window)

			// If we don't have enough data to calculate the deviation, move
			// on.
			if i < s.Window {
				s.D[i][sig].Packets = 0
				s.D[i][sig].Events = 0
				continue
			}

			// Calculate the deviation squared.
			packetDev := float64(s.S[i][sig].Packets) - s.A[i-1][sig].Packets
			eventDev := float64(s.S[i][sig].Events) - s.A[i-1][sig].Events
			packetDevPerc := packetDev / s.A[i-1][sig].Packets
			eventDevPerc := eventDev / s.A[i-1][sig].Events
			s.D[i][sig].Packets = packetDevPerc
			s.D[i][sig].Events = eventDevPerc
		}
	}
}

func (s *Series) WriteAvCount(out *os.File, sig NoIPSig) {
	for day := range s.S {
		fmt.Fprintf(out, "%d, %d, %d, %f, %f\n", day,
			s.S[day][sig].Packets, s.S[day][sig].Events,
			s.A[day][sig].Packets, s.A[day][sig].Events)
	}
}

func (s *Series) WriteAvVolCount(out *os.File, sig NoIPSig) {
	fmt.Fprintf(out, "Day, Packets, Events, Moving Average Packets, "+
		"Moving Average Events, Daily Packet Deviation, "+
		"Daily Event Deviation\n")
	for day := range s.S {
		fmt.Fprintf(out, "%d, %d, %d, %f, %f, %f, %f\n", day,
			s.S[day][sig].Packets, s.S[day][sig].Events,
			s.A[day][sig].Packets, s.A[day][sig].Events,
			s.D[day][sig].Packets, s.D[day][sig].Events)
	}
}

func (s *Series) WriteAvTotalCounts(out *os.File) {
	for day, counts := range s.S {
		var sumPackets uint64
		var sumEvents uint32
		var sumAvPackets float64
		var sumAvEvents float64
		for sig, pair := range counts {
			sumPackets += pair.Packets
			sumEvents += pair.Events
			sumAvPackets += s.A[day][sig].Packets
			sumAvEvents += s.A[day][sig].Events
		}

		fmt.Fprintf(out, "%d, %d, %d, %f, %f\n", day,
			sumPackets, sumEvents, sumAvPackets, sumAvEvents)
	}
}

func (s *Series) FindDelta() {
	for day, counts := range s.S {
		if day == 0 {
			continue
		}

		for sig, pair := range counts {
			if s.S[day-1][sig] == nil {
				continue
			}

			if float64(pair.Events) > 1.25*float64(s.S[day-1][sig].Events) &&
				s.S[day-1][sig].Events > 500 {

				fmt.Printf("%02d, %f, %d, %d, %d, %d\n", day,
					float64(pair.Events)/
						float64(s.S[day-1][sig].Events)-1,
					sig.Port, sig.Traffic, pair.Packets, pair.Events)
			}
			/*
				if float64(pair.Packets) > 1.5*float64(s.S[day-1][sig].Packets) &&
					s.S[day-1][sig].Packets > 100000 {

					fmt.Printf("%02d, %f, %d, %d, %d, %d\n", day,
						float64(pair.Packets)/
							float64(s.S[day-1][sig].Packets)-1,
						sig.Port, sig.Traffic, pair.Events, pair.Packets)
				}
			*/
		}
	}
}
