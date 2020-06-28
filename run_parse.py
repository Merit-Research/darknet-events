#!/usr/bin/env python3

'''
SET THE FOLLOWING VARIABLES TO CONFIGURE PROGRAM:

BLOCKSIZE:      Number of pcaps to process before saving state and output.
DATETIMEPCAP:   Datetime format string for input pcap files.
DATETIMEMMASN:  Datetime format string for MaxMind ASN DB.
DATETIMEMMGEO:  Datetime format string for MaxMind Geo DB.
DATETIMEPFX2AS: Datetime format string for Prefix2AS DB.
DNS:            IP address(es) of desired DNS server(s) for reverse pointer lookups.
OUTPATH:        Path for output files.
ONGOINGOUTPATH: Path for ongoing event output file.
THRESHOLD:      Time (in seconds) without a packet for an event to be considered over.
MINUNIQUES:     Amount of unique destinations an event must hit to be annotated.
MINRATE:        Minimum PPS for an event to be annotated.
NUMSAMPLES:     Amount of packet samples to save for each event.
PROFILECPU:     Profile CPU with pprof.
PROFILEMEM:     Profile memory with pprof.

'''

BLOCKSIZE       = 24
OUTPATH         = "./out/" # "/data1/conrad_scratch/" 
ONGOINGOUTPATH  = "./out/" # "/data1/conrad_scratch/" 
DATETIMEPCAP    = "./samples/%Y-%m-%d.%H.pcap.gz" #  "/data1/darknet/archive/%Y/%m/%d/%Y-%m-%d.%H.pcap.gz"
DATETIMEMMASN   = "" # "/data/maxmind-asn/archive/GeoLite2-ASN_%Y%m%d/GeoLite2-ASN.mmdb"
DATETIMEMMGEO   = "" # "/data/maxmind-city/archive/GeoLite2-City_%Y%m%d/GeoLite2-City.mmdb"
DATETIMEPFX2AS  = "" # "/data/caida-pfx2as/routeviews-rv2-%Y%m%d-%H00.pfx2as.gz"
DNS             = [] # ["1.1.1.1", "198.108.1.42", "198.108.130.5", "198.109.36.3"]
THRESHOLD       = "624"
MINUNIQUES      = "10"
MINRATE         = "10.0"
NUMSAMPLES      = "3"
PROFILECPU      = False
PROFILEMEM      = False

'''
The following code will generate the shell script required to run ./bin/parse.

'''

from datetime import datetime, timedelta
import os
import sys

def main():
    if len(sys.argv) != 3 and len(sys.argv) != 4 and len(sys.argv) != 5:
        print("Requires two arguments of form YYYY-MM-DD:HH, an optional cache input path, and an option newdl bool.")
        exit(0)
    
    # Parse start and end times.
    start = datetime.strptime(sys.argv[1], "%Y-%m-%d:%H")
    end = datetime.strptime(sys.argv[2], "%Y-%m-%d:%H")

    # Calculate number of subcommands (one subcommand per hour).
    delta = end - start
    delta_hours = int(delta.days * 24 + delta.seconds / 60 / 60)
    print("Number of hours to parse is", delta_hours)
    print()

    # Clean up and make.
    command = "rm -f " + OUTPATH + "parse_job.log;"
    command += " make;"

    # Get cache input path (if there)
    if len(sys.argv) == 4 and (sys.argv[3].lower() != "true" and sys.argv[3].lower() != "false"):
        cache_in_path = sys.argv[3]
        newdl = False
    elif len(sys.argv) == 4:
        cache_in_path = ""
        if sys.argv[3].lower() == "true":
            newdl = True
        else:
            newdl = False
    elif len(sys.argv) == 5:
        cache_in_path = sys.argv[3]
        if sys.argv[4].lower() == "true":
            newdl = True
        else:
            newdl = False
    else:
        cache_in_path = ""
        newdl = False    

    # Build parse commands.
    command += " ("
    command += "echo \"$(date):   STARTING\" >> " + OUTPATH + "parse_job.log;"
    # Build commands in blocks of BLOCKSIZE pcaps.
    for i in range(0, delta_hours - BLOCKSIZE + 1, BLOCKSIZE):
        subcommand, cache_out_path = build_parse_command(start, i, i + BLOCKSIZE, cache_in_path, newdl)
        command += subcommand
        cache_in_path = cache_out_path
        # Chain further subcommands if necessary.
        if i != delta_hours - BLOCKSIZE:
            command += "; "
    # Build command for remainder of pcaps.
    if delta_hours % BLOCKSIZE != 0:
        subcommand, cache_out_path = build_parse_command(start, delta_hours - (delta_hours % BLOCKSIZE), delta_hours, cache_in_path, newdl)
        command += subcommand

    # Add final portion of parse command.
    command += "; echo \"$(date):   COMPLETE\" >> " + OUTPATH + "parse_job.log) &"

    print(command)
    print()
    
    # Run command.
    os.system(command)

    print("Command executed.")

def build_parse_command(start, low, high, cache_in_path, newdl):
    command = ""

    subcommand_start = datetime.strftime(start + timedelta(hours=low), "%Y-%m-%d:%H")
    subcommand_end = datetime.strftime(start + timedelta(hours=high), "%Y-%m-%d:%H")
    subcommand_window = subcommand_start + "_" + subcommand_end

    command += " nohup"
    command += " sh -c './bin/parse"

    command += " --threshold " + THRESHOLD
    command += " --uniques " + MINUNIQUES
    command += " --rate " + MINRATE
    command += " --samples " + NUMSAMPLES

    if PROFILECPU:
        command += " --cpu \"" + OUTPATH + "cpu_" + subcommand_window + ".prof\""
    if PROFILEMEM:
        command += " --mem \"" + OUTPATH + "mem_" + subcommand_window + ".prof\""

    # Set up result output path.
    command += " --eventout \"" + OUTPATH + "results_" + subcommand_window + ".json\""

    # If given, set up ongoing events output path.
    if ONGOINGOUTPATH != "":
        command += " --ongoingout \"" + ONGOINGOUTPATH + "ongoing_" + subcommand_window + ".json\""

    # Set newline option.
    if newdl == True:
        command += " --newdl"

    # Set up cache state input and output paths.
    command += " --cachein \"" + cache_in_path + "\""
    cache_out_path = OUTPATH + "cache_" + subcommand_window + ".state"
    command += " --cacheout \"" + cache_out_path + "\""
    cache_in_path = cache_out_path

    # Set up ASN, geo, pfx2as, and DNS annotation.
    if DATETIMEMMASN != "":
        filename = find_most_recent(start, DATETIMEMMASN)
        command += " --asnin \"" + filename + "\""

    if DATETIMEMMGEO != "":
        filename = find_most_recent(start, DATETIMEMMGEO)
        command += " --geoin \"" + filename + "\""

    if DATETIMEPFX2AS != "":
        filename = find_most_recent(start, DATETIMEPFX2AS)
        command += " --pfx2asin \"" + filename + "\""

    if DNS != []:
        command += " --dns \""
        for i, server in enumerate(DNS):
            command += server
            if i != len(DNS) - 1:
                command += " "
        command += "\""

    # Get pcap file name.
    command += " --pcap \""
    for i in range(low, high):
        filename = datetime.strftime(start + timedelta(hours=i), DATETIMEPCAP)
        command += filename
        if i != high - 1:
            command += " "
    command += "\""

    # Set up subcommand logging.
    curr_time = datetime.now()
    command += "; echo \"$(date):   " + subcommand_window + " DONE\" >> " + OUTPATH + "parse_job.log"
    command += "' > " + OUTPATH + "parse_" + subcommand_window + ".log 2>&1"

    print(command)
    print()

    return command, cache_out_path

def find_most_recent(start, template):
    filename = ""
    for i in range(0, 32 * 12):
        filename = datetime.strftime(start - timedelta(hours=i * 2), template)
        if os.path.isfile(filename):
            return filename
    print("Could not find a file of form", template)
    return ""

if __name__ == "__main__":
    main()
