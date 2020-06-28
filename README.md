# Darknet Processing

Processing traffic from a darknet to classify internet background radiation events.

# Run

## Helpers:

Helper scripts have been written to automate usage:

* `run_parse.py` runs the parser element of this program
  * Set the initialisation variables at the top of the script, then run:
  `./run_parse.py START_TIME END_TIME [CACHE_IN_PATH] [NEWDL]`, where the start and end times are in the format `YYYY-MM-DD:HH`
* `run_count.py` runs the general statistics element of this program
* `run_timeseries.py` runs the time-series analysis element of this program

## Parse Usage:

```./bin/parse --threshold <packet_threshold> [--uniques <min_unique_dests>] [--rate <min_scan_rate>] --samples <num_samples> [--cpu <cpu_pprof_out_path>] [--mem <mem_pprof_out_path>] --eventout <event_results_out_path> [--ongoingout <ongoing_results_out_path>] [--newdl] [--cachein <cache_in_state_path>] [--cacheout <cache_out_state_path>] [--asnin <maxmind_asn_path>] [--geoin <maxmind_geo_path>] [--pfx2asin <pfx2as_path>] [--dns <dns_server>] --pcap <pcap_paths_space_separated>```

### Flags

Mandatory:

* `threshold` - Minimum number of packets for an event to be annotated and saved.
* `samples` - Number of samples to take for events.
* `eventout` - Path to write JSON results to.
* `pcap` - Path to input pcap file(s), separated by spaces.

Optional:

* `newdl` - Set this flag to have output be in newline-delimited JSON format.
* `cpu` - Output path for CPU pprof file. No CPU profiling will be done if omitted.
* `mem` - Output path for memory pprof file. No memory profiling will be done if omitted.
* `cachein` - Path to input cache state. Used to continue analysis from previous run.
* `cacheout` - Path to output cache state. State will be discarded if omitted.
* `ongoingout` - Path to the ongoing event output file. No file will be created if omitted.
* `asnin` - Path to MaxMind ASN DB. No ASN annotations will be added if omitted.
* `geoin` - Path to MaxMind Cities DB. No Geographic annotations will be added if omitted.
* `pfx2asin` - Path to prefix2as DB. No IP/Prefix annotations will be added if omitted.
* `dns` - List of paths to DNS servers. No reverse pointer lookups will be made if omitted. If several are included, one will be picked at random for each query.
* `uniques` - Minimum number of unique IP destinations required for an event to be annotated and saved. If not given, defaults to 0.
* `rate` - Minimum global scan rate (in PPS) for an event to be annotated and saved. If not given, defaults to 0.

### Example Usage:

Minimum usable command: 

```./bin/parse --threshold 624 --samples 3 --eventout "./out/results_2020-10-21:16_2020-10-21:17.json" --pcap "./samples/2020-10-21.16.pcap.gz"```

Running with all options: 

```./bin/parse --threshold 624 --uniques 10 --rate 10 --samples 3 --cpu "./out/cpu_2020-10-21:16_2020-10-21:17.prof" --mem "./out/mem_2020-10-21:16_2020-10-21:17.prof" --eventout "./out/results_2020-10-21:16_2020-10-21:17.json" --ongoingout "./out/ongoing_2020-10-21:16_2020-10-21:17.json" --cachein "./out/cache_2020-10-21:15_2020-10-21:16.state" --cacheout "./out/cache_2020-10-21:16_2020-10-21:17.state" --newdl --asnin "./resources/asn/GeoLite2-ASN_20201021/GeoLite2-ASN.mmdb" --geoin "./resources/city/GeoLite2-City_20201021/GeoLite2-City.mmdb" --pfx2asin "./resources/caida-pfx2as/routeviews-rv2-20201021-0800.pfx2as.gz" --dns "1.1.1.1" --pcap "./samples/2020-10-21.16.pcap.gz"```

### Results

~~The results of each run are saved in JSON format with the following members:~~

```source IP, traffic type, dest port, first packet time, last packet time, # of packets, # of bytes total, # unique destinations, # unique /24 destinations, latitude, longitude, ISO country code, city, ASN number, organisation, prefix, RDNS pointer(s), zmap, masscan, mirai, sample(s)```

// To be updated soon.

## To-do

* ~~Move config to flag-based system~~
* ~~Import and export cache~~
* ~~Granular traffic decoding~~
* ~~GeoMind and pfx2as~~
* ~~DNS data~~
* ~~Reservoir sampling~~
* ~~Fingerprinting zmap, Masscan, etc.~~
* ~~Move packet threshold to packets per second~~

## Additional Notes

To run `parse` by reading directly off an interface, compile `parse_live` instead, and pass it the `--interface` flag followed by the name of the interface instead of the `--pcap` flag.
