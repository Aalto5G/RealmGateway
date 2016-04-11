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
ip link set dev qbr-int-lana    down
ip link set dev qve-phy-lana    down
ip link set dev qve-l2-lana     down
ip link del qve-phy-lana
brctl delbr qbr-int-lana

## WAN side
ip link set dev qbr-int-wan     down
ip link set dev qve-phy-wana    down
ip link set dev qve-l2-wana     down
ip link del qve-phy-wana
brctl delbr qbr-int-wan

## TUN side
ip link set dev qve-phy-tuna    down
ip link set dev qve-l2-tuna     down
ip link del qve-phy-tuna
ovs-vsctl --if-exists del-br qbr-int-tuna

# [CES-B]
## LAN side
ip link set dev qbr-int-lanb    down
ip link set dev qve-phy-lanb    down
ip link set dev qve-l2-lanb     down
ip link del qve-phy-lanb
brctl delbr qbr-int-lanb

## WAN side
ip link set dev qbr-int-wan     down
ip link set dev qve-phy-wanb    down
ip link set dev qve-l2-wanb     down
ip link del qve-phy-wanb
brctl delbr qbr-int-wan

## TUN side
ip link set dev qve-phy-tunb    down
ip link set dev qve-l2-tunb     down
ip link del qve-phy-tunb
ovs-vsctl --if-exists del-br qbr-int-tunb


###############################################################################
# Remove CES-A configuration
###############################################################################

## LAN side
ip link set dev qbr-filter-lana down
ip link set dev qve-l3-lana     down
ip link set dev l3-lana         down
ip link del qve-l3-lana
brctl delbr qbr-filter-lana

## WAN side
ip link set dev qbr-filter-wana down
ip link set dev qve-l3-wana     down
ip link set dev l3-wana         down
ip link del qve-l3-wana 
brctl delbr qbr-filter-wana

## TUN side
ip link set dev qbr-filter-tuna down
ip link set dev qve-l3-tuna     down
ip link set dev l3-tuna         down
ip link del qve-l3-tuna
brctl delbr qbr-filter-tuna

###############################################################################
# Remove CES-B configuration
###############################################################################

## LAN side
ip link set dev qbr-filter-lanb down
ip link set dev qve-l3-lanb     down
ip link set dev l3-lanb         down
ip link del qve-l3-lanb
brctl delbr qbr-filter-lanb

## WAN side
ip link set dev qbr-filter-wanb down
ip link set dev qve-l3-wanb     down
ip link set dev l3-wanb         down
ip link del qve-l3-wanb 
brctl delbr qbr-filter-wanb

## TUN side
ip link set dev qbr-filter-tunb down
ip link set dev qve-l3-tunb     down
ip link set dev l3-tunb         down
ip link del qve-l3-tunb
brctl delbr qbr-filter-tunb


###############################################################################
# Remove network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
done
