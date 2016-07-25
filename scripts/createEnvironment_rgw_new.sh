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
ip link add dev br-wan0 type bridge
ip link set dev br-wan0 up
ip link add dev br-wan1 type bridge
ip link set dev br-wan1 up
# [RealmGateway-A]
## WAN side
ip link add dev br-wan0a type bridge
ip link set dev br-wan0a up
## LAN side
ip link add dev br-lan0a type bridge
ip link set dev br-lan0a up


###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in lan0a rgw0a proxy0a router0 public0; do
    #Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
    ip netns add $i
    #Configure sysctl options
    ip netns exec $i sysctl -w "net.ipv4.ip_forward=1"                 > /dev/null 2> /dev/null
    ip netns exec $i sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
    ip netns exec $i sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
    ip netns exec $i sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null
    #Configure the loopback interface in namespace
    ip netns exec $i ip address add 127.0.0.1/8 dev lo
    ip netns exec $i ip link set dev lo up
    #Create new /etc mount point
    mkdir -p  /etc/netns/$i
    echo $i > /etc/netns/$i/hostname
    touch     /etc/netns/$i/resolv.conf
done

###############################################################################
# Create host configuration
###############################################################################

## Create a macvlan interface to provide NAT and communicate with the other virtual hosts
NAT_NIC="eth1"
ip link add link br-wan0 dev tap-wan0 type macvlan mode bridge
ip link set dev tap-wan0 up
ip address add 198.18.0.254/24 dev tap-wan0
iptables -t nat -A POSTROUTING -o $NAT_NIC -j MASQUERADE


###############################################################################
# Create router0 configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan0 dev wan0 type macvlan mode bridge
ip link add link br-wan1 dev wan1 type macvlan mode bridge
ip link set wan0 netns router0
ip link set wan1 netns router0
ip netns exec router0 ip link set dev wan0 up
ip netns exec router0 ip link set dev wan1 up
ip netns exec router0 ip address add 198.18.0.1/24 dev wan0
ip netns exec router0 ip address add 198.18.1.1/24 dev wan1


###############################################################################
# Create proxy0a configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan0  dev wan0  type macvlan mode bridge
ip link add link br-wan0a dev wan0a type macvlan mode bridge
ip link set wan0  netns proxy0a
ip link set wan0a netns proxy0a
ip netns exec proxy0a ip link set dev wan0  up
ip netns exec proxy0a ip link set dev wan0a up
ip netns exec proxy0a ip address add 198.18.0.8/24 dev wan0
ip netns exec proxy0a ip address add 198.18.0.9/29 dev wan0a #Longest match prefix for routing
ip netns exec proxy0a ip route add default via 198.18.0.1 dev wan0

# Setting up TCP SYNPROXY in NS-PROXY - ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
ip netns exec proxy0a sysctl -w net.ipv4.tcp_syncookies=1 # This is not available in the network namespace
ip netns exec proxy0a sysctl -w net.ipv4.tcp_timestamps=1 # This is not available in the network namespace
ip netns exec proxy0a sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
# Disable sending ICMP redirects
ip netns exec proxy0a sysctl -w net.ipv4.conf.all.send_redirects=0
ip netns exec proxy0a sysctl -w net.ipv4.conf.default.send_redirects=0
ip netns exec proxy0a sysctl -w net.ipv4.conf.lo.send_redirects=0
ip netns exec proxy0a sysctl -w net.ipv4.conf.wan0.send_redirects=0
# Configure iptables for SYNPROXY
ip netns exec proxy0a iptables -t raw    -F
ip netns exec proxy0a iptables -t raw    -A PREROUTING -i wan0 -p tcp -m tcp --syn -j CT --notrack
ip netns exec proxy0a iptables -t filter -F
ip netns exec proxy0a iptables -t filter -A FORWARD -i wan0 -o wan0a -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
ip netns exec proxy0a iptables -t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP
## Inline TCP SYNProxy: Enable arp_proxy to answer ARP for known routes (RealmGateway)
ip netns exec proxy0a sysctl -w net.ipv4.conf.wan0.proxy_arp=1
ip netns exec proxy0a sysctl -w net.ipv4.conf.wan0a.proxy_arp=1


###############################################################################
# Create rgw0a configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan0a dev wan0 type macvlan mode bridge
ip link add link br-lan0a dev lan0 type macvlan mode bridge
ip link set wan0 netns rgw0a
ip link set lan0 netns rgw0a
ip netns exec rgw0a ip link set dev wan0 up
ip netns exec rgw0a ip link set dev lan0 up
ip netns exec rgw0a ip address add 198.18.0.10/24 dev wan0
ip netns exec rgw0a ip address add 192.168.0.1/24 dev lan0
ip netns exec rgw0a ip route add default via 198.18.0.1 dev wan0

# Add Circular Pool address for ARP responses
ip netns exec rgw0a ip address add 198.18.0.11/32 dev wan0
ip netns exec rgw0a ip address add 198.18.0.12/32 dev wan0
ip netns exec rgw0a ip address add 198.18.0.13/32 dev wan0
ip netns exec rgw0a ip address add 198.18.0.14/32 dev wan0
# Configure SNAT in Realm Gateway
ip netns exec rgw0a iptables -t nat -F POSTROUTING
ip netns exec rgw0a iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o wan0 -j SNAT --to-source 198.18.0.11-198.18.0.14 --persistent


###############################################################################
# Create lan0a configuration
###############################################################################

ip link add link br-lan0a dev lan0 type macvlan mode bridge
ip link set lan0 netns lan0a
ip netns exec lan0a ip link set dev lan0 up
ip netns exec lan0a ip address add 192.168.0.100/24 dev lan0
ip netns exec lan0a ip route add default via 192.168.0.1 dev lan0
ip netns exec lan0a echo "nameserver 192.168.0.1" > /etc/resolv.conf


###############################################################################
# Create public0 configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan1 dev wan0 type macvlan mode bridge
ip link set wan0 netns public0
ip netns exec public0 ip link set dev wan0 up
ip netns exec public0 ip address add 198.18.1.100/24 dev wan0
ip netns exec public0 ip route add default via 198.18.1.1 dev wan0
ip netns exec public0 echo "nameserver 198.18.1.1" > /etc/resolv.conf
