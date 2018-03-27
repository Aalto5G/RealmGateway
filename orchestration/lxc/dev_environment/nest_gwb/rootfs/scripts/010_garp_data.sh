#!/bin/bash

# Send Gratuituous ARP to update ARP cache tables in neighbors

IPADDRS="192.168.0.10 192.168.0.11 192.168.0.12 192.168.0.13 192.168.0.14"
NIC="wan0"

for ip in $IPADDRS; do
    arping -c 1 -U -I $NIC $ip
done
