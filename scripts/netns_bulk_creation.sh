#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

NAME="hosta"
FIRST="101"
LAST="250"
NIC="lan0"
IPADDR_PREFIX="192.168.0."
IPADDR_NETPREFIX="/24"
IPADDR_GATEWAY="192.168.0.1"
IPADDR_DNS="192.168.0.1"

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

echo "Creating network namespace from $NAME$FIRST to $NAME$LAST"

for i in `seq $FIRST $LAST`; do
    nsname="$NAME$i"
    echo "Creating network namespace $nsname @ $IPADDR_PREFIX$i$IPADDR_NETPREFIX"
    #Remove and create new namespaces
    ip netns del $nsname > /dev/null 2> /dev/null
    ip netns add $nsname
    #Create new /etc mount point
    mkdir -p        /etc/netns/$nsname
    echo  $nsname > /etc/netns/$nsname/hostname
    touch           /etc/netns/$nsname/resolv.conf
    echo "nameserver $IPADDR_DNS" > /etc/netns/$nsname/resolv.conf
    #Configure sysctl options
    ip netns exec $nsname sysctl -w "net.ipv4.ip_forward=0"                 > /dev/null 2> /dev/null
    ip netns exec $nsname sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
    ip netns exec $nsname sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
    ip netns exec $nsname sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null
    #Configure the loopback interface in namespace
    ip netns exec $nsname ip address add 127.0.0.1/8 dev lo
    ip netns exec $nsname ip link set dev lo up
    #Configure the bridged interface in namespace
    ip link add link $NIC dev $nsname-tap type macvlan mode bridge
    ip link set $nsname-tap netns $nsname
    #Change name to make it look as a container node
    ip netns exec $nsname ip link set dev $nsname-tap name $NIC
    ip netns exec $nsname ip link set dev $NIC up
    ip netns exec $nsname ip address add $IPADDR_PREFIX$i$IPADDR_NETPREFIX dev $NIC
    ip netns exec $nsname ip route add default via $IPADDR_GATEWAY
done

echo "Done!"
# This configuration allows connectivity between network namespaces but not to the host itself
# if needed, we could create a local bridge where to attach everything or enable hairpining in the main host:
# brctl hairpin br-lan0a gwa_test_lan0 on turn hairpin on/off
