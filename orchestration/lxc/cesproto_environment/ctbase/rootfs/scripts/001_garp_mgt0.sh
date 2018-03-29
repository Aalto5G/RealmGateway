#!/bin/bash

# Send Gratuituous ARP to update ARP cache tables in neighbors

NIC="mgt0"
ip=$(ip -f inet addr show dev $NIC | sed -n 's/^ *inet *\([.0-9]*\).*/\1/p')
arping -c 1 -U -I $NIC $ip
