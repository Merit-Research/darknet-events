package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"darknet-events/internal/analysis"
	"darknet-events/internal/annotate"
	"darknet-events/internal/set"
)

func main() {
	window := flag.Int("window", 3,
		"Number of days to consider in moving average")
	inStatePathString := flag.String("instate", "",
		"Path to the input state file")
	outStatePathString := flag.String("outstate", "",
		"Path to the output state file")
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

	// Create a time series, loading state if necessary.
	var s *analysis.Series
	if *inStatePathString != "" {
		s = analysis.LoadSeries(*inStatePathString)
	} else {
		// TODO: Make these flags
		s = analysis.NewSeries(len(resultsInPaths), 24, *window)
	}

	// Create a Mirai-specific time series.
	// var mirai *analysis.Series
	// s = analysis.NewSeries(len(resultsInPaths), 24, *window)

	var yesterdayPort82 *set.StringSet
	var yesterdayPort85 *set.StringSet

	// Iterate through files.
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

		port82 := set.NewStringSet()
		port85 := set.NewStringSet()

		// Iterate through events.
		for j := 0; j < len(results); j++ {
			event := results[j]

			// Create port/proto signature.
			key := analysis.NewNoIPSig(event.Port, event.Traffic)

			// Add event to time series.
			if event.Mirai == true {
				s.Add(i, key, uint64(event.Packets))
			}

			// Add to Mirai series if necessary.
			if event.Mirai == true {
				// mirai.Add(i, key, uint64(event.Packets))
			}

			// TEMP
			// Add IP to 82 set.
			if event.Mirai == true && event.Port == 82 {
				port82.Add(event.SourceIP)
			}
			if event.Mirai == true && event.Port == 85 {
				port85.Add(event.SourceIP)
			}
		}

		yes82 := 0
		yes85 := 0
		if i != 0 {
			for ip := range *port82.Map() {
				if yesterdayPort82.Contains(ip) {
					yes82++
				}
			}
			for ip := range *port85.Map() {
				if yesterdayPort85.Contains(ip) {
					yes85++
				}
			}
		}

		overlap := 0
		for ip := range *port82.Map() {
			if port85.Contains(ip) {
				overlap++
			}
		}

		fmt.Printf("%d, %d, %d, %d, %d\n",
			yes82, port82.Size(), yes85, port85.Size(), overlap)

		yesterdayPort82 = port82
		yesterdayPort85 = port85
	}

	// Save state. No need if we didn't parse any new files.
	if *outStatePathString != "" && len(resultsInPaths) != 0 {
		s.DumpSeries(*outStatePathString)
	}

	// Calculate moving averages.
	s.Calc()

	// Output data.
	var out *os.File
	var err error

	// Write total counts.
	out, err = os.Create("./out/timeseries_total_volume.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	s.WriteAvTotalCounts(out)

	sig := analysis.NewNoIPSig(82, 11)
	out, err = os.Create("./out/timeseries_total_82.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	s.WriteAvCount(out, sig)

	sig = analysis.NewNoIPSig(85, 11)
	out, err = os.Create("./out/timeseries_total_85.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	s.WriteAvVolCount(out, sig)

	sig = analysis.NewNoIPSig(8181, 11)
	out, err = os.Create("./out/timeseries_total_8181.csv")
	if err != nil {
		log.Fatal("Failed to create output state file: ", err)
	}
	defer out.Close()
	s.WriteAvVolCount(out, sig)

	// Write total Mirai counts.
	/*
		out, err = os.Create("./out/timeseries_mirai_total_volume.csv")
		if err != nil {
			log.Fatal("Failed to create output state file: ", err)
		}
		defer out.Close()
		s.WriteAvTotalCounts(out)
	*/

	log.Println("All files written.")
}
