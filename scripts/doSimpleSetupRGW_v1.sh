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
## LAN side
ip link add dev br-lan0a type bridge
ip link set dev br-lan0a up


###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in hosta gwa router public; do
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
ip link add link br-wan0 dev tap-wan0 type macvlan mode bridge
ip link set dev tap-wan0 up
ip address add 198.18.0.254/24 dev tap-wan0
ip route add 198.18.0.0/22 via 198.18.0.1


###############################################################################
# Create router configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan0 dev wan0 type macvlan mode bridge
ip link add link br-wan1 dev wan1 type macvlan mode bridge
ip link set wan0 netns router
ip link set wan1 netns router
ip netns exec router ip link set dev wan0 name eth0
ip netns exec router ip link set dev wan1 name eth1
ip netns exec router ip link set dev eth0 up
ip netns exec router ip link set dev eth1 up
ip netns exec router ip address add 198.18.0.1/24 dev eth0
ip netns exec router ip address add 198.18.1.1/24 dev eth1
ip netns exec router ip route add default via 198.18.0.254 dev eth0
ip netns exec router bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'

# Setting up TCP SYNPROXY in router - ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
ip netns exec router sysctl -w net.ipv4.tcp_syncookies=1 # This is not available in the network namespace
ip netns exec router sysctl -w net.ipv4.tcp_timestamps=1 # This is not available in the network namespace
ip netns exec router sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
# Configure iptables for SYNPROXY - Protect wan1 from incoming SYNs from wan0
ip netns exec router iptables -t raw    -F
ip netns exec router iptables -t raw    -A PREROUTING -i eth0 -p tcp -m tcp --syn -j CT --notrack
ip netns exec router iptables -t filter -F
ip netns exec router iptables -t filter -A FORWARD -i eth0 -o eth1 -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
ip netns exec router iptables -t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP


###############################################################################
# Create gwa configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan1  dev wan0 type macvlan mode bridge
ip link add link br-lan0a dev lan0 type macvlan mode bridge
ip link set wan0 netns gwa
ip link set lan0 netns gwa
ip netns exec gwa ip link set dev lan0 name eth0
ip netns exec gwa ip link set dev wan0 name eth1
ip netns exec gwa ip link set dev eth0 up
ip netns exec gwa ip link set dev eth1 up
ip netns exec gwa ip address add 192.168.0.1/24  dev eth0
ip netns exec gwa ip address add 198.18.1.130/24 dev eth1
ip netns exec gwa ip route add default via 198.18.1.1 dev eth1
ip netns exec gwa bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'

# Add Circular Pool address for ARP responses
ip netns exec gwa ip address add 198.18.1.131/32 dev eth1 # Reserved for CES
ip netns exec gwa ip address add 198.18.1.132/32 dev eth1 # Reserved for CES
ip netns exec gwa ip address add 198.18.1.133/32 dev eth1
ip netns exec gwa ip address add 198.18.1.134/32 dev eth1
ip netns exec gwa ip address add 198.18.1.135/32 dev eth1
ip netns exec gwa ip address add 198.18.1.136/32 dev eth1
ip netns exec gwa ip address add 198.18.1.137/32 dev eth1
ip netns exec gwa ip address add 198.18.1.138/32 dev eth1
ip netns exec gwa ip address add 198.18.1.139/32 dev eth1
ip netns exec gwa ip address add 198.18.1.140/32 dev eth1
ip netns exec gwa ip address add 198.18.1.141/32 dev eth1
ip netns exec gwa ip address add 198.18.1.142/32 dev eth1
# Configure SNAT in Realm Gateway - Done in the init script
#ip netns exec gwa iptables -t nat -F POSTROUTING
#ip netns exec gwa iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o wan0 -j SNAT --to-source 198.18.0.133-198.18.0.135 --persistent


###############################################################################
# Create hosta configuration
###############################################################################

ip link add link br-lan0a dev lan0 type macvlan mode bridge
ip link set lan0 netns hosta
ip netns exec hosta ip link set dev lan0 name eth0
ip netns exec hosta ip link set dev eth0 up
ip netns exec hosta ip address add 192.168.0.100/24 dev eth0
ip netns exec hosta ip route add default via 192.168.0.1 dev eth0
ip netns exec hosta bash -c 'echo "nameserver 192.168.0.1" > /etc/resolv.conf'


###############################################################################
# Create public configuration
###############################################################################

## Assign and configure namespace interface
ip link add link br-wan1 dev wan0 type macvlan mode bridge
ip link set wan0 netns public
ip netns exec public ip link set dev wan0 name eth0
ip netns exec public ip link set dev eth0 up
ip netns exec public ip address add 198.18.0.100/24 dev eth0
ip netns exec public ip route add default via 198.18.0.1 dev eth0
ip netns exec public bash -c 'echo "nameserver 198.18.0.1" > /etc/resolv.conf'
