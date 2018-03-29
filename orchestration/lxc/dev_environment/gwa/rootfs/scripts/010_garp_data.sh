#!/bin/bash

# Send Gratuituous ARP to update ARP cache tables in neighbors

IPADDRS="100.64.1.130 100.64.1.131 100.64.1.132 100.64.1.133 100.64.1.134 100.64.1.135 100.64.1.136 100.64.1.137 100.64.1.138 100.64.1.139 100.64.1.140 100.64.1.141 100.64.1.142"
NIC="wan0"

for ip in $IPADDRS; do
    arping -c 1 -U -I $NIC $ip
done
