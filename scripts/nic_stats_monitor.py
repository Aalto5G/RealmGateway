#!/usr/bin/env python3

import argparse
from itertools import chain
import time
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(description='Network interface monitor v0.1')
    parser.add_argument('--nic', type=str, required=True,
                        help='Network interface')
    parser.add_argument('--interval', type=int, default=1,
                        help='Refresh interval')
    parser.add_argument('--counter-interval', dest='counter_interval', action='store_true',
                        help='Calculate stats for each time interval')
    parser.add_argument('--counter-zero', dest='counter_zero', action='store_true',
                        help='Calculate stats from startup',
                        # This does not reset the interface counters, but shows relative numbers when the program started
                        )
    return parser.parse_args()

def _read_net_dev():
    results = {}
    with open('/proc/net/dev', 'r') as f:
        lines = f.readlines()
        columnLine = lines[1]
        _, receiveCols , transmitCols = columnLine.split('|')
        receiveCols = map(lambda a:'rx_{}'.format(a), receiveCols.split())
        transmitCols = map(lambda a:'tx_{}'.format(a), transmitCols.split())
        cols = list(chain(receiveCols, transmitCols))
        for line in lines[2:]:
            if line.find(':') < 0:
                continue
            iface, data = line.split(':')
            iface = iface.strip()
            results[iface] = dict(zip(cols, data.split()))
    return results

if __name__ == "__main__":
    args = parse_arguments()
    print('## Starting Network interface monitor v0.1 @{} every {:.2f} sec'.format(args.nic, args.interval))
    # Obtain initial startup values
    start_time = time.time()
    start_data = _read_net_dev()[args.nic]
    data_tmp = start_data

    while True:
        time.sleep(args.interval)
        data_d1 = _read_net_dev()[args.nic]

        if args.counter_interval:
            # Calculate stats for each time interval
            time_display = time.time() - start_time
            results = {}
            for k in data_d1:
                results[k] = int(data_d1[k]) - int(data_tmp[k])
            # Save current counters for next iteration
            data_tmp = data_d1
        elif args.counter_zero:
            # Calculate stats from startup
            time_display = time.time()
            results = {}
            for k in data_d1:
                results[k] = int(data_d1[k]) - int(data_tmp[k])
        else:
            # Use read values directly
            time_display = time.time()
            results = data_d1

        print('{:.2f}\t{}\t{}'.format(time_display, args.nic, results))

