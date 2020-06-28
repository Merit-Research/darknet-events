package main

import (
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"darknet-events/internal/analysis"
	"darknet-events/internal/annotate"
)

// DarknetSize is the number of IP addresses in the darknet.
var DarknetSize uint32 = 475136

// SmallScanMargin is the number of unique destinations below which a scan is
// considered "small".
var SmallScanMargin int = int(DarknetSize) / 10

// DarknetFactor is the multiplier to extrapolate darknet event values to
// global values.
var DarknetFactor float64 = float64(4294967296) / float64(DarknetSize)

// CountryBreakoutMargin is the minimum number of events from a country per
// NoIPSig to be counted - this reduces the file size of country breakouts.
var CountryBreakoutMargin uint32 = 2500

// Events contains relevant information for an event.
type Events struct {
	Packets uint32 // Total number of packets across all events.
	Dests   uint32
	Times   []time.Time // Sequences of first, last times (two per event).
}

type NoIPSig struct {
	Port    uint16
	Traffic analysis.TrafficType
}

// load loads state from an infile.
func load(inPath string, m map[analysis.EventSignature]*Events) {
	log.Println("Loading state from input file.")
	loadStart := time.Now()
	defer func() {
		loadEnd := time.Now()
		log.Printf("Loaded state from input file in %s.\n",
			loadEnd.Sub(loadStart).String())
	}()
	in, err := os.Open(inPath)
	if err != nil {
		log.Fatal("Failed to open input state file: ", err)
	}
	decoder := gob.NewDecoder(in)
	err = decoder.Decode(&m)
	if err != nil {
		log.Fatalf("Failed to load state from input file: %s.\n", err)
	}
}

// dump saves state to an outfile.
func dump(outPath string, m map[analysis.EventSignature]*Events) {
	log.Println("Saving state to output file.")
	dumpStart := time.Now()
	defer func() {
		dumpEnd := time.Now()
		log.Printf("Saved state to output file in %s.\n",
			dumpEnd.Sub(dumpStart).String())
	}()
	out, err := os.Create(outPath)
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	encoder := gob.NewEncoder(out)
	err = encoder.Encode(m)
	if err != nil {
		log.Fatalf("Failed to save state to output file: %s.\n", err)
	}
}

// Round rounds a value to the nearest given value.
func round(x float64, nearest float64) float64 {
	return math.Round(x/nearest) * nearest
}

func main() {
	// Parse flags
	/*
		inStatePathString := flag.String("instate", "",
			"Path to the input state file")
		outStatePathString := flag.String("outstate", "",
			"Path to the output state file")
	*/
	resultsInPathsString := flag.String("infiles", "",
		"Path to the input results files.")
	flag.Parse()

	// Check that given input results files exist.
	var resultsInPaths []string
	if *resultsInPathsString == "" {
		resultsInPaths = make([]string, 0, 0)
	} else {
		resultsInPaths = strings.Split(*resultsInPathsString, " ")
		for i := 0; i < len(resultsInPaths); i++ {
			file, err := os.Open(resultsInPaths[i])
			if err != nil {
				log.Fatal("Failed to find results file: ", err)
			}
			file.Close()
		}
	}

	// Load input state if necessary.
	/*
		if *inStatePathString != "" {
			load(*inStatePathString, m)
		}
	*/

	// Create counters for IPv4 coverage.
	packetCoverage := make(map[float64]uint64)
	eventCoverage := make(map[float64]uint32)

	// Create counters for scan rate coverage.
	packetScanRates := make(map[float64]uint64)
	eventScanRates := make(map[float64]uint32)

	// Counters for number of packets and events.
	packetCounts := make(map[NoIPSig]uint64)
	eventCounts := make(map[NoIPSig]uint32)
	var packets uint64
	var events uint32

	// Small and large scan breakouts.
	packetSmallScanCounts := make(map[NoIPSig]uint64)
	eventSmallScanCounts := make(map[NoIPSig]uint32)
	packetLargeScanCounts := make(map[NoIPSig]uint64)
	eventLargeScanCounts := make(map[NoIPSig]uint32)

	// Country-by-country breakout counts.
	packetCountryCounts := make(map[string]map[NoIPSig]uint64)
	eventCountryCounts := make(map[string]map[NoIPSig]uint32)
	packetCountryTotalCounts := make(map[string]uint64)
	eventCountryTotalCounts := make(map[string]uint32)

	// Small/large and country breakout counts.
	packetSmallScanCountryCounts := make(map[string]map[NoIPSig]uint64)
	eventSmallScanCountryCounts := make(map[string]map[NoIPSig]uint32)
	packetLargeScanCountryCounts := make(map[string]map[NoIPSig]uint64)
	eventLargeScanCountryCounts := make(map[string]map[NoIPSig]uint32)
	packetSmallScanCountryTotalCounts := make(map[string]uint64)
	eventSmallScanCountryTotalCounts := make(map[string]uint32)
	packetLargeScanCountryTotalCounts := make(map[string]uint64)
	eventLargeScanCountryTotalCounts := make(map[string]uint32)

	// Mirai breakout.
	packetMiraiCounts := make(map[NoIPSig]uint64)
	eventMiraiCounts := make(map[NoIPSig]uint32)
	packetMiraiCountryCounts := make(map[string]map[NoIPSig]uint64)
	eventMiraiCountryCounts := make(map[string]map[NoIPSig]uint32)
	packetMiraiCoverage := make(map[float64]uint64)
	eventMiraiCoverage := make(map[float64]uint32)
	packetMiraiScanRates := make(map[float64]uint64)
	eventMiraiScanRates := make(map[float64]uint32)

	// Zmap and Masscan usage counters.
	var zmapPackets uint64
	var zmapSmallScanPackets uint64
	var zmapLargeScanPackets uint64
	var masscanPackets uint64
	var masscanSmallScanPackets uint64
	var masscanLargeScanPackets uint64
	var zmapEvents uint32
	var zmapSmallScanEvents uint32
	var zmapLargeScanEvents uint32
	var masscanEvents uint32
	var masscanSmallScanEvents uint32
	var masscanLargeScanEvents uint32

	// Mirai large scan counter
	var miraiSmallEvents uint32
	var miraiLargeEvents uint32

	// Read input files.
	for i := 0; i < len(resultsInPaths); i++ {
		fileBytes, err := ioutil.ReadFile(resultsInPaths[i])
		if err != nil {
			log.Fatal("Could not read results file: ", err)
		}
		log.Printf("Read in results file %s\n", resultsInPaths[i])

		// Unmarshal objects into memory.
		var results []annotate.Output
		err = json.Unmarshal(fileBytes, &results)
		if err != nil {
			log.Fatal("Could not unmarshal results: ", err)
		}
		log.Println("Unmarshaled", len(results), "results.")

		// Iterate through events.
		for i := 0; i < len(results); i++ {
			event := results[i]

			// Create Port/Proto signature.
			key := new(NoIPSig)
			key.Port = event.Port
			key.Traffic = analysis.TrafficType(event.Traffic)

			// Add to a coverage bucket.
			var bucket float64
			percentOfIPv4 := float64(event.UniqueDests) / float64(DarknetSize)
			if percentOfIPv4 < 0.00001 {
				bucket = round(percentOfIPv4, 0.000001)
			} else if percentOfIPv4 < 0.0001 {
				bucket = round(percentOfIPv4, 0.00001)
			} else if percentOfIPv4 < 0.001 {
				bucket = round(percentOfIPv4, 0.0001)
			} else if percentOfIPv4 < 0.01 {
				bucket = round(percentOfIPv4, 0.001)
			} else if percentOfIPv4 < 0.1 {
				bucket = round(percentOfIPv4, 0.01)
			} else {
				bucket = round(percentOfIPv4, 0.1)
			}
			packetCoverage[bucket] += uint64(event.Packets)
			eventCoverage[bucket]++

			// If Mirai, add to Mirai coverage breakout.
			if event.Mirai == true {
				packetMiraiCoverage[bucket] += uint64(event.Packets)
				eventMiraiCoverage[bucket]++
			}

			// Add to scan rate bucket.
			scanDuration := event.Last.Sub(event.First).Seconds()
			scanRate := float64(event.Packets) * DarknetFactor / scanDuration
			if scanRate < 100 {
				bucket = round(scanRate, 10)
			} else if scanRate < 1000 {
				bucket = round(scanRate, 100)
			} else if scanRate < 10000 {
				bucket = round(scanRate, 1000)
			} else if scanRate < 100000 {
				bucket = round(scanRate, 10000)
			} else if scanRate < 1000000 {
				bucket = round(scanRate, 100000)
			} else {
				bucket = round(scanRate, 1000000)
			}
			packetScanRates[bucket] += uint64(event.Packets)
			eventScanRates[bucket]++

			// If Mirai, add to Mirai scan rate breakout.
			if event.Mirai == true {
				packetMiraiScanRates[bucket] += uint64(event.Packets)
				eventMiraiScanRates[bucket]++
			}

			// Add to general packet counts.
			packetCounts[*key] += uint64(event.Packets)
			eventCounts[*key]++
			packets += uint64(event.Packets)
			events++

			// Add to small/large scan breakouts.
			if event.UniqueDests < SmallScanMargin {
				packetSmallScanCounts[*key] += uint64(event.Packets)
				eventSmallScanCounts[*key]++

				// Add to small/large scan country breakout.
				if packetSmallScanCountryCounts[event.Country] == nil {
					packetSmallScanCountryCounts[event.Country] =
						make(map[NoIPSig]uint64)
					eventSmallScanCountryCounts[event.Country] =
						make(map[NoIPSig]uint32)
				}
				packetSmallScanCountryCounts[event.Country][*key] +=
					uint64(event.Packets)
				eventSmallScanCountryCounts[event.Country][*key]++
				packetSmallScanCountryTotalCounts[event.Country] +=
					uint64(event.Packets)
				eventSmallScanCountryTotalCounts[event.Country]++

				// Add to Zmap/Masscan counters.
				if event.Zmap == true {
					zmapSmallScanPackets += uint64(event.Packets)
					zmapSmallScanEvents++
				} else if event.Masscan == true {
					masscanSmallScanPackets += uint64(event.Packets)
					masscanSmallScanEvents++
				}

				// Count if the event was Mirai.
				if event.Mirai == true {
					miraiSmallEvents++
				}
			} else {
				packetLargeScanCounts[*key] += uint64(event.Packets)
				eventLargeScanCounts[*key]++

				// Add to small/large scan country breakout.
				if packetLargeScanCountryCounts[event.Country] == nil {
					packetLargeScanCountryCounts[event.Country] =
						make(map[NoIPSig]uint64)
					eventLargeScanCountryCounts[event.Country] =
						make(map[NoIPSig]uint32)
				}
				packetLargeScanCountryCounts[event.Country][*key] +=
					uint64(event.Packets)
				eventLargeScanCountryCounts[event.Country][*key]++
				packetLargeScanCountryTotalCounts[event.Country] +=
					uint64(event.Packets)
				eventLargeScanCountryTotalCounts[event.Country]++

				// Add to Zmap/Masscan counters.
				if event.Zmap == true {
					zmapLargeScanPackets += uint64(event.Packets)
					zmapLargeScanEvents++
				} else if event.Masscan == true {
					masscanLargeScanPackets += uint64(event.Packets)
					masscanLargeScanEvents++
				}

				// Count if the event was Mirai.
				if event.Mirai == true {
					miraiLargeEvents++
				}
			}

			// Add to country-by-country breakouts.
			if packetCountryCounts[event.Country] == nil {
				packetCountryCounts[event.Country] = make(map[NoIPSig]uint64)
				eventCountryCounts[event.Country] = make(map[NoIPSig]uint32)
			}
			packetCountryCounts[event.Country][*key] += uint64(event.Packets)
			eventCountryCounts[event.Country][*key]++
			packetCountryTotalCounts[event.Country] += uint64(event.Packets)
			eventCountryTotalCounts[event.Country]++

			// If applicable, add to Mirai breakouts.
			if event.Mirai == true {
				packetMiraiCounts[*key] += uint64(event.Packets)
				eventMiraiCounts[*key]++
				if packetMiraiCountryCounts[event.Country] == nil {
					packetMiraiCountryCounts[event.Country] =
						make(map[NoIPSig]uint64)
					eventMiraiCountryCounts[event.Country] =
						make(map[NoIPSig]uint32)
				}

				// Add to country breakout.
				packetMiraiCountryCounts[event.Country][*key] +=
					uint64(event.Packets)
				eventMiraiCountryCounts[event.Country][*key]++
			}

			// Add to total Zmap/Masscan tallies.
			if event.Zmap == true {
				zmapPackets += uint64(event.Packets)
				zmapEvents++
			} else if event.Masscan == true {
				masscanPackets += uint64(event.Packets)
				masscanEvents++
			}
		}
	}

	var out *os.File
	var err error

	// Write out coverage buckets to CSV.
	out, err = os.Create("./out/coverage.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	packetCoverageCDF := make(map[float64]uint64)
	eventCoverageCDF := make(map[float64]uint32)
	for k := range eventCoverage {
		eventCoverageCDF[k] = 0
	}
	for bracket := range eventCoverageCDF {
		for bucket, count := range eventCoverage {
			if bucket <= bracket {
				packetCoverageCDF[bracket] += packetCoverage[bucket]
				eventCoverageCDF[bracket] += count
			}
		}
	}
	for k, v := range eventCoverageCDF {
		fmt.Fprintf(out, "%f, %d, %d\n", k, packetCoverageCDF[k], v)
	}
	log.Println("Wrote coverage.")

	// Write out scan rate buckets to CSV.
	out, err = os.Create("./out/rates.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	packetScanRatesCDF := make(map[float64]uint64)
	eventScanRatesCDF := make(map[float64]uint32)
	for k := range eventScanRates {
		eventScanRatesCDF[k] = 0
	}
	for bracket := range eventScanRatesCDF {
		for bucket, count := range eventScanRates {
			if bucket <= bracket {
				packetScanRatesCDF[bracket] += packetScanRates[bucket]
				eventScanRatesCDF[bracket] += count
			}
		}
	}
	for k, v := range eventScanRatesCDF {
		fmt.Fprintf(out, "%f, %d, %d\n", k, packetScanRatesCDF[k], v)
	}
	log.Println("Wrote rates.")

	// Write out each count to CSV.
	out, err = os.Create("./out/counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetCounts {
		fmt.Fprintf(out, "%d, %d, %d, %d\n", k.Port, k.Traffic,
			v, eventCounts[k])
	}
	log.Println("Wrote counts.")

	// Write out small/large scan counts.
	out, err = os.Create("./out/small_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetSmallScanCounts {
		fmt.Fprintf(out, "%d, %d, %d, %d\n", k.Port, k.Traffic,
			v, eventSmallScanCounts[k])
	}
	out, err = os.Create("./out/large_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetLargeScanCounts {
		fmt.Fprintf(out, "%d, %d, %d, %d\n", k.Port, k.Traffic,
			v, eventLargeScanCounts[k])
	}
	log.Println("Wrote small/large counts.")

	// Write out each country's counts.
	out, err = os.Create("./out/country_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k1, v1 := range packetCountryCounts {
		for k2, v2 := range v1 {
			if eventCountryCounts[k1][k2] > CountryBreakoutMargin {
				fmt.Fprintf(out, "%s, %d, %d, %d, %d\n", k1, k2.Port,
					k2.Traffic, v2, eventCountryCounts[k1][k2])
			}
		}
	}
	log.Println("Wrote country counts.")

	// Write out each country's total counts.
	out, err = os.Create("./out/country_total_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetCountryTotalCounts {
		fmt.Fprintf(out, "%s, %d, %d\n", k, v, eventCountryTotalCounts[k])
	}
	log.Println("Wrote country total counts.")

	// Write out small/large country breakouts.
	out, err = os.Create("./out/small_country_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k1, v1 := range packetSmallScanCountryCounts {
		for k2, v2 := range v1 {
			if eventCountryCounts[k1][k2] > CountryBreakoutMargin {
				fmt.Fprintf(out, "%s, %d, %d, %d, %d\n", k1, k2.Port,
					k2.Traffic, v2, eventSmallScanCountryCounts[k1][k2])
			}
		}
	}
	out, err = os.Create("./out/large_country_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k1, v1 := range packetLargeScanCountryCounts {
		for k2, v2 := range v1 {
			if eventCountryCounts[k1][k2] > CountryBreakoutMargin {
				fmt.Fprintf(out, "%s, %d, %d, %d, %d\n", k1, k2.Port,
					k2.Traffic, v2, eventLargeScanCountryCounts[k1][k2])
			}
		}
	}
	log.Println("Wrote small/large country counts.")

	// Write out country/size total breakouts.
	out, err = os.Create("./out/small_country_total_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetSmallScanCountryTotalCounts {
		fmt.Fprintf(out, "%s, %d, %d\n", k, v, eventSmallScanCountryTotalCounts[k])
	}
	out, err = os.Create("./out/large_country_total_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetLargeScanCountryTotalCounts {
		fmt.Fprintf(out, "%s, %d, %d\n", k, v, eventLargeScanCountryTotalCounts[k])
	}

	// Write out Mirai breakouts.
	out, err = os.Create("./out/mirai_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k, v := range packetMiraiCounts {
		fmt.Fprintf(out, "%d, %d, %d, %d\n", k.Port, k.Traffic,
			v, eventMiraiCounts[k])
	}
	out, err = os.Create("./out/mirai_country_counts.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	for k1, v1 := range packetMiraiCountryCounts {
		for k2, v2 := range v1 {
			fmt.Fprintf(out, "%s, %d, %d, %d, %d\n", k1, k2.Port, k2.Traffic,
				v2, eventMiraiCountryCounts[k1][k2])
		}
	}
	out, err = os.Create("./out/mirai_coverage.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	packetMiraiCoverageCDF := make(map[float64]uint64)
	eventMiraiCoverageCDF := make(map[float64]uint32)
	for k := range eventMiraiCoverage {
		eventMiraiCoverageCDF[k] = 0
	}
	for bracket := range eventMiraiCoverageCDF {
		for bucket, count := range eventMiraiCoverage {
			if bucket <= bracket {
				packetMiraiCoverageCDF[bracket] += packetMiraiCoverage[bucket]
				eventMiraiCoverageCDF[bracket] += count
			}
		}
	}
	for k, v := range eventMiraiCoverageCDF {
		fmt.Fprintf(out, "%f, %d, %d\n", k, packetMiraiCoverageCDF[k], v)
	}
	out, err = os.Create("./out/mirai_scan_rates.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	packetMiraiScanRatesCDF := make(map[float64]uint64)
	eventMiraiScanRatesCDF := make(map[float64]uint32)
	for k := range eventMiraiScanRates {
		eventMiraiScanRatesCDF[k] = 0
	}
	for bracket := range eventMiraiScanRatesCDF {
		for bucket, count := range eventMiraiScanRates {
			if bucket <= bracket {
				packetMiraiScanRatesCDF[bracket] +=
					packetMiraiScanRates[bucket]
				eventMiraiScanRatesCDF[bracket] += count
			}
		}
	}
	for k, v := range eventMiraiScanRatesCDF {
		fmt.Fprintf(out, "%f, %d, %d\n", k, packetMiraiScanRatesCDF[k], v)
	}
	log.Println("Wrote Mirai breakouts.")

	log.Println("Processed", packets, "packets in", events, "events.")
	log.Printf("%d packets were sent with Zmap across %d events.\n",
		zmapPackets, zmapEvents)
	log.Printf("%d packets were sent with Zmap across %d small scan events.",
		zmapSmallScanPackets, zmapSmallScanEvents)
	log.Printf("%d packets were sent with Zmap across %d large scan events.",
		zmapLargeScanPackets, zmapLargeScanEvents)
	log.Printf("%d packets were sent with Massscan across %d events.\n",
		masscanPackets, masscanEvents)
	log.Printf("%d packets were sent with Massscan across %d small scan events.",
		masscanSmallScanPackets, masscanSmallScanEvents)
	log.Printf("%d packets were sent with Massscan across %d large scan events.",
		masscanLargeScanPackets, masscanLargeScanEvents)
	log.Printf("%d small scans and %d large scans were from Mirai.\n",
		miraiSmallEvents, miraiLargeEvents)
}
