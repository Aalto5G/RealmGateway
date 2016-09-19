#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Remove CES-A configuration
###############################################################################

## LAN side
ip link set dev l3-lana down
ip link del l3-lana

## WAN side
ip link set dev l3-wana down
ip link del l3-wana

## TUN side
ip link set dev l3-tuna down
ip link del l3-tuna
ovs-vsctl --if-exists del-br qbi-tuna


###############################################################################
# Remove CES-B configuration
###############################################################################

## LAN side
ip link set dev l3-lanb down
ip link del l3-lanb

## WAN side
ip link set dev l3-wanb down
ip link del l3-wanb

## TUN side
ip link set dev l3-tunb down
ip link del l3-tunb
ovs-vsctl --if-exists del-br qbi-tunb


###############################################################################
# Remove supporting infrastructure for CES-A & CES-B
###############################################################################

# [COMMON]
## WAN side
ip link set dev qbi-wan down
ip link del qbi-wan
ip link set dev qbi-wan2 down
ip link del qbi-wan2
ip link del wan0_phy

# [CES-A]
## LAN side
ip link set dev qbi-lana down
ip link del qbi-lana

# [CES-B]
## LAN side
ip link set dev qbi-lanb down
ip link del qbi-lanb



###############################################################################
# Remove network namespace configuration
###############################################################################

for i in nslana nsproxy nswan nswan2; do
    #Remove namespaces
    ip netns del $i > /dev/null 2> /dev/null
    #Remove /etc mount point
    rm -rf /etc/netns/$i
done
