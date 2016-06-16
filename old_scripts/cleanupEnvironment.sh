#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Remove supporting infrastructure for CES-A & CES-B
###############################################################################

# [CES-A]
## LAN side
ip link set dev qbi-lana     down
ip link set dev qve-phy-lana down
ip link set dev qvi-phy-lana down
ip link del qve-phy-lana
brctl delbr qbi-lana

## WAN side
ip link set dev qbi-wan      down
ip link set dev qve-phy-wana down
ip link set dev qvi-phy-wana down
ip link del qve-phy-wana
brctl delbr qbi-wan

## TUN side
ip link set dev qve-phy-tuna down
ip link set dev qvi-phy-tuna down
ip link del qve-phy-tuna
ovs-vsctl --if-exists del-br qbi-tuna

# [CES-B]
## LAN side
ip link set dev qbi-lanb     down
ip link set dev qve-phy-lanb down
ip link set dev qvi-phy-lanb down
ip link del qve-phy-lanb
brctl delbr qbi-lanb

## WAN side
ip link set dev qbi-wan      down
ip link set dev qve-phy-wanb down
ip link set dev qvi-phy-wanb down
ip link del qve-phy-wanb
brctl delbr qbi-wan

## TUN side
ip link set dev qve-phy-tunb down
ip link set dev qvi-phy-tunb down
ip link del qve-phy-tunb
ovs-vsctl --if-exists del-br qbi-tunb


###############################################################################
# Remove CES-A configuration
###############################################################################

## LAN side
ip link set dev qbf-lana    down
ip link set dev qve-l3-lana down
ip link set dev l3-lana     down
ip link del qve-l3-lana
brctl delbr qbf-lana

## WAN side
ip link set dev qbf-wana     down
ip link set dev qve-l3-wana  down
ip link set dev l3-wana      down
ip link del qve-l3-wana 
brctl delbr qbf-wana

## TUN side
ip link set dev qbf-tuna     down
ip link set dev qve-l3-tuna  down
ip link set dev l3-tuna      down
ip link del qve-l3-tuna
brctl delbr qbf-tuna

###############################################################################
# Remove CES-B configuration
###############################################################################

## LAN side
ip link set dev qbf-lanb     down
ip link set dev qve-l3-lanb  down
ip link set dev l3-lanb      down
ip link del qve-l3-lanb
brctl delbr qbf-lanb

## WAN side
ip link set dev qbf-wanb     down
ip link set dev qve-l3-wanb  down
ip link set dev l3-wanb      down
ip link del qve-l3-wanb 
brctl delbr qbf-wanb

## TUN side
ip link set dev qbf-tunb     down
ip link set dev qve-l3-tunb  down
ip link set dev l3-tunb      down
ip link del qve-l3-tunb
brctl delbr qbf-tunb


###############################################################################
# Remove network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
done
