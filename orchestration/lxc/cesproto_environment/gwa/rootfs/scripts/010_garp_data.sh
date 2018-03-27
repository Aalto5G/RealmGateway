#!/bin/bash

# Send Gratuituous ARP to update ARP cache tables in neighbors

IPADDRS="195.148.125.201 195.148.125.202 195.148.125.203 195.148.125.204"
NIC="wan0"

for ip in $IPADDRS; do
    arping -c 1 -U -I $NIC $ip
done
