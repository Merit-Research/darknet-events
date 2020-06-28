#!/usr/bin/env python3

from datetime import datetime, timedelta
import os
import sys

BLOCKSIZE = 24

def main():
    if len(sys.argv) != 4:
        print("Requires two arguments of form YYYY-MM-DD:HH and path to folder containing results. Exiting.")
        exit(0)

    # Parse start and end times.
    start = datetime.strptime(sys.argv[1], "%Y-%m-%d:%H")
    end = datetime.strptime(sys.argv[2], "%Y-%m-%d:%H")

    # Calculate number of results files (one file per hour).
    delta = end - start
    delta_hours = int(delta.days * 24 + delta.seconds / 60 / 60)

    command = "make;"
    command += " ./bin/count"

    # Build input and output state flag strings.
    instate_path = sys.argv[3] + "countstate_" + sys.argv[1] + "_" + sys.argv[2] + ".state"
    if os.path.isfile(instate_path):
        command += " --instate " + instate_path
        use_instate = True
    else:
        # command += " --outstate " + instate_path
        use_instate = False

    if not use_instate:
        command += " --infiles \""
        for i in range(0, delta_hours - BLOCKSIZE + 1, BLOCKSIZE):
            if i != 0:
                command += " "
            command += build_count_command(start, i, i + BLOCKSIZE)
        if delta_hours % BLOCKSIZE != 0:
            if delta_hours > BLOCKSIZE:
                command += " "
            command += build_count_command(start, delta_hours - (delta_hours % BLOCKSIZE), delta_hours)
        command += "\""

    print(command)
    print()

    # Run the command.
    os.system(command)

def build_count_command(start, low, high):
    subcommand_start = datetime.strftime(start + timedelta(hours=low), "%Y-%m-%d:%H")
    subcommand_end = datetime.strftime(start + timedelta(hours=high), "%Y-%m-%d:%H")
    subcommand_window = subcommand_start + "_" + subcommand_end

    command = sys.argv[3] + "results_" + subcommand_window + ".json"

    return command

if __name__ == "__main__":
    main()
