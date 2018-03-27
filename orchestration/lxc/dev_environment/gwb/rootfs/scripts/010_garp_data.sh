#!/bin/bash

# Send Gratuituous ARP to update ARP cache tables in neighbors

IPADDRS="100.64.2.130 100.64.2.131 100.64.2.132 100.64.2.133 100.64.2.134 100.64.2.135 100.64.2.136 100.64.2.137 100.64.2.138 100.64.2.139 100.64.2.140 100.64.2.141 100.64.2.142"
NIC="wan0"

for ip in $IPADDRS; do
    arping -c 1 -U -I $NIC $ip
done
