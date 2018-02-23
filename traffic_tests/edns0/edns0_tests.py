#!/usr/bin/env python3

# Run as:
# ./edns0_tests.py --nic ens2f1 --test-iteration 3 --test-duration 10 --test-backoff 2 --start 0 --stop 301 --step 10
# ./edns0_tests.py --nic ens2f1 --test-iteration 3 --test-duration 10 --test-backoff 2 --datapoints 0 10 20 30 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180 190 200 210 220 230 240 250 260 270 280 290 300
# ./edns0_tests.py --nic ens2f1 --test-iteration 3 --test-duration 10 --test-backoff 2 --datapoints 0 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100 105 110 115 120 125 130 135 140 145 150
# ./edns0_tests.py --nic ens2f1 --test-iteration 3 --test-duration 10 --test-backoff 2 --datapoints 0 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100 105 110 115 120 125 130 135 140 145 150 160 170 180 190 200 210 220 230 240 250 260 270 280 290 300

import sys
import argparse
from itertools import chain
import time
import pprint
import subprocess
import random

TEST_INTERFACE = 'ens2f1'
TEST_ITERATION = 3
TEST_DURATION = 10
TEST_BACKOFF = 3

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

def _filter_data_net_dev(data_d, keys):
    keys_delete = []
    for k in data_d:
        if k not in keys:
            keys_delete.append(k)
        # Make int of data
        data_d[k] = int(data_d[k])
    for k in keys_delete:
        del data_d[k]
    return data_d


def _do_test(name, notes):
    ''' Run basic test functionality '''
    t0 = time.time()
    data_d0 = _read_net_dev()
    data_f0 = _filter_data_net_dev(data_d0[TEST_INTERFACE], ('tx_packets', 'rx_packets', 'rx_drop', 'rx_fifo'))

    time.sleep(TEST_DURATION)

    t1 = time.time()
    tt = t1 - t0
    data_d1 = _read_net_dev()
    data_f1 = _filter_data_net_dev(data_d1[TEST_INTERFACE], ('tx_packets', 'rx_packets', 'rx_drop', 'rx_fifo'))

    tx_packets = data_f1['tx_packets'] - data_f0['tx_packets']
    rx_packets = data_f1['rx_packets'] - data_f0['rx_packets']
    rx_drop    = data_f1['rx_drop']    - data_f0['rx_drop']
    if 'rx_fifo' in data_f1:
        rx_fifo = data_f1['rx_fifo'] - data_f0['rx_fifo']
        rx_drop += rx_fifo

    pct_drop   = rx_drop / (rx_drop + rx_packets) * 100.0
    log_result('{},{:.2f},{},{},{},{:.2f},{}'.format(name, tt, tx_packets, rx_packets, rx_drop, pct_drop, notes))

    #log_error('>>>  {}/{}/{}/{:.2f}% tx_packets/rx_packets/rx_drop/%rx_drop in {:.2f} sec '.format(tx_packets, rx_packets, rx_drop, pct_drop, tt))
    log_error('>>>  {:.2f}K/{:.2f}K/{:.2f}K/{:.2f}% tx_packets/rx_packets/rx_drop/%rx_drop (pps) in {:.2f} sec'.format(tx_packets/tt/1000, rx_packets/tt/1000, rx_drop/tt/1000, pct_drop,tt))

def _do_exec(to_exec):
    for line in to_exec:
        subprocess.run(line, shell=True, check=True)

def test(name, pre_exec=[], notes=''):
    ''' Obtain baseline performance '''
    # Prepare environment
    _do_exec(pre_exec)
    # Wait backoff time for environment to be ready
    time.sleep(TEST_BACKOFF)
    # Run test
    _do_test(name, notes)

def log_error(s):
    ''' Use stderr to log results in comma separated values'''
    print(s, file=sys.stderr, flush=True)

def log_result(s):
    ''' Use stderr to log results in comma separated values'''
    print(s, file=sys.stdout, flush=True)

def cleanup_iptables():
    rules = ['iptables -t filter -F', 'iptables -t filter -X',
             'iptables -t mangle -F', 'iptables -t mangle -X',
             'iptables -t nat -F',    'iptables -t nat -X',
             'iptables -t raw -F',    'iptables -t raw -X'
            ]
    _do_exec(rules)

def generate_ipt_basic1(n):
    ''' Generate basic iptables rule for simplest matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_basic2(n):
    ''' Generate basic iptables rule for simplest matching with packet mark'''
    rules = ['iptables -t filter -A FORWARD -p udp --dport 53 -m mark --mark {}'.format(i) for i in range(n)]
    return rules

def generate_ipt_dns1(n):
    ''' Generate type 1 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53 -m string --algo bm --hex-string "|07|example|03|com|00|" --from 40 --to 295 -m comment --comment "Match both domain and subdomains"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns2(n):
    ''' Generate type 2 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53 -m string --algo bm --hex-string "|04|leaf|04|nsfw|07|example|03|com|00|" --from 40 --to 41 -m comment --comment "Match both domain and subdomains"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns3(n):
    ''' Generate type 3 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53  -m string --algo bm --hex-string "|04|nsfw|07|example|03|com|00|" --from 41 --to 295 -m comment --comment "Match subdomain only *.nsfw.example.com"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns4(n):
    ''' Generate type 4 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53  -m string --algo bm --hex-string "|04|nsfw" --from 40 --to 295 -m comment --comment "Match nsfw unsafe label"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns5(n):
    ''' Generate type 5 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53  -m string --algo bm --hex-string "nsfw" --from 40 --to 295 -m comment --comment "Match nsfw unsafe word"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns6(n):
    ''' Generate type 6 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53  -m string --algo bm --hex-string "|ff020004deadbeef|" --from 40 -m comment --comment "EDNS0_EClientID - deadbeef"'
    rules = [rule for i in range(n)]
    return rules

def generate_ipt_dns7(n):
    ''' Generate type 7 DNS iptables rule for matching '''
    rule = 'iptables -t filter -A FORWARD -p udp --dport 53  -m string --algo bm --hex-string "|ff01000a0001c61200640011|" --from 40 -m comment --comment "EDNS0_EClientInfoOption - 198.18.0.100 / UDP"'
    rules = [rule for i in range(n)]
    return rules


def parse_arguments():
    parser = argparse.ArgumentParser(description='EDNS0 firewall rule test v0.1')
    parser.add_argument('--nic', type=str, required=True,
                        help='Network interface')
    parser.add_argument('--start', type=int, default=0,
                        help='Start range')
    parser.add_argument('--stop', type=int, default=100,
                        help='Stop range')
    parser.add_argument('--step', type=int, default=5,
                        help='Step range')
    parser.add_argument('--datapoints', nargs='+', type=int, default=[],
                        help='Datapoint values for iptables nof rules, <1, 5, 10>')
    parser.add_argument('--test-iteration', type=int, default=3,
                        help='Number of iterations for each test')
    parser.add_argument('--test-duration', type=float, default=10,
                        help='Duration of each test')
    parser.add_argument('--test-backoff', type=float, default=2,
                        help='Backoff duration before each test')

    return parser.parse_args()

if __name__ == "__main__":
    log_error('## Starting tests ##')
    # Parse arguments
    args = parse_arguments()
    # Re set global variables
    TEST_INTERFACE = args.nic
    TEST_ITERATION = args.test_iteration
    TEST_DURATION = args.test_duration
    TEST_BACKOFF = args.test_backoff
    # Evaluate given list of datapoints
    if len(args.datapoints) > 0:
        datapoints = args.datapoints
    else:
        # Build own list of datapoints based on range parameters
        datapoints = list(range(args.start, args.stop, args.step))

    # Write CSV header
    log_result('test_id,test_duration,tx_packets,rx_packets,rx_drop,%rx_drop,ipt_rules,notes')
    # Store a counter for test_sequence
    seq = 0
    # Run tests
    for i in range(TEST_ITERATION):
        i+=1
        seq+=1
        log_error('\nStarting iteration {}/{} ({})...\n'.format(i, TEST_ITERATION, seq))

        ## Test 1: No ipt rules
        #cleanup_iptables()
        #test('pps_baseline', notes='0,pps_baseline')

        for j in datapoints:
            if j == 0:
                j = 1
            pre_exec = generate_ipt_basic1(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},basic1'.format(j))
            seq+=1

            pre_exec = generate_ipt_basic2(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},basic2'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns1(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns1'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns2(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns2'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns3(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns3'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns4(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns4'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns5(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns5'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns6(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns6'.format(j))
            seq+=1

            pre_exec = generate_ipt_dns7(j)
            cleanup_iptables()
            test(seq, pre_exec=pre_exec, notes='{0},dns7'.format(j))
