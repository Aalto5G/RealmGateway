#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Create supporting infrastructure for single instance of Realm Gateway
###############################################################################

echo "Enable IP forwarding"
sysctl -w "net.ipv4.ip_forward=1"                 > /dev/null 2> /dev/null
echo "Disable IPv6 for all interfaces"
sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null
echo "Unloading iptables bridge kernel modules"
rmmod xt_physdev
rmmod br_netfilter

# [COMMON]
## WAN side
ip link set dev br-wan0 down
ip link del dev br-wan0
ip link set dev br-wan1 down
ip link del dev br-wan1
# [RealmGateway-A]
## WAN side
ip link set dev br-wan0a down
ip link del dev br-wan0a
## LAN side
ip link set dev br-lan0a down
ip link del dev br-lan0a


###############################################################################
# Create host configuration
###############################################################################

## Create a macvlan interface to provide NAT and communicate with the other virtual hosts
NAT_NIC="eth1"
iptables -t nat -D POSTROUTING -o $NAT_NIC -j MASQUERADE

###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in lan0a rgw0a proxy0a router0 public0; do
    #Remove namespaces
    ip netns del $i > /dev/null 2> /dev/null
done
