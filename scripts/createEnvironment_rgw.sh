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
sysctl -w "net.ipv4.ip_forward=1" > /dev/null 2> /dev/null

echo "Disable IPv6 for all interfaces"
sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null

echo "Unloading iptables bridge kernel modules"
rmmod xt_physdev
rmmod br_netfilter


# [COMMON]
## WAN side
ip link add dev qbi-wan type bridge
ip link set dev qbi-wan up
## WAN2 side
ip link add dev qbi-wan2 type bridge
ip link set dev qbi-wan2 up

# [CES-A]
## LAN side
ip link add dev qbi-lana type bridge
ip link set dev qbi-lana up



###############################################################################
# Create CES-A configuration
###############################################################################

## LAN side
ip link add link qbi-lana dev l3-lana type macvlan mode bridge
ip link set dev l3-lana address 00:00:00:00:01:AA
ip link set dev l3-lana up

## WAN side
#ip link add link qbi-wan dev l3-wana type macvlan mode bridge
## Use veth instead for ebtables
ip link add l3-wana type veth peer name wan1
#ip link set l3-wana_br master qbi-wan #ip link set $dev nomaster
ip link set dev l3-wana address 00:00:00:00:01:BB
ip link set dev l3-wana multicast off
ip link set dev l3-wana arp off
ip link set dev l3-wana up
ip link set dev wan1    address 00:00:00:00:01:BB
ip link set dev wan1    multicast off
ip link set dev wan1    arp off

# Set IP configuration
ip address add 192.168.0.1/24 dev l3-lana
ip address add 198.18.0.11/32 dev l3-wana
ip address add 198.18.0.12/32 dev l3-wana
ip address add 198.18.0.13/32 dev l3-wana
ip address add 198.18.0.14/32 dev l3-wana
# Add route in CES-A to reach NS-WAN2
ip route add 198.18.0.0/16 dev l3-wana

# Configure SNAT in Realm Gateway
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o l3-wana -j SNAT --to-source 198.18.0.12-198.18.0.14 -m comment --comment "SNAT to 198.18.0.[12,13,14]"


###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nsproxy nswan nswan2; do
    #Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
    ip netns add $i
    #Configure the loopback interface in namespace
    ip netns exec $i ip address add 127.0.0.1/8 dev lo
    ip netns exec $i ip link set dev lo up
    #Create new /etc mount point
    mkdir -p  /etc/netns/$i
    echo $i > /etc/netns/$i/hostname
    touch     /etc/netns/$i/resolv.conf
done

## Assign and configure namespace interface
### [NS-LAN-A]
ip link add link qbi-lana dev lan0 type macvlan mode bridge
ip link set lan0 netns nslana
ip netns exec nslana ip link set dev lan0 mtu 1500
ip netns exec nslana ip link set dev lan0 address 00:00:C0:A8:00:65
ip netns exec nslana ip link set dev lan0 up
ip netns exec nslana ip address add 192.168.0.101/24 dev lan0
ip netns exec nslana ip route add default via 192.168.0.1

### [NS-PROXY]
ip link add link qbi-wan dev wan0 type macvlan mode bridge
#ip link add wan0 type veth peer name wan0_nsproxy_br
#ip link set wan0_nsproxy_br master qbi-wan #ip link set $dev nomaster
#ip link set dev wan0_nsproxy_br up
ip link set wan0 netns nsproxy
ip link set wan1 netns nsproxy
ip netns exec nsproxy ip link set dev wan0 mtu 1500
ip netns exec nsproxy ip link set dev wan0 address 00:00:C6:12:00:0A
ip netns exec nsproxy ip link set dev wan0 up
ip netns exec nsproxy ip link set dev wan1 up
ip netns exec nsproxy ip address add 198.18.0.10/24 dev wan0
ip netns exec nsproxy ip route add default via 198.18.0.1
ip netns exec nsproxy ip route add 198.18.0.11/32 dev wan1
ip netns exec nsproxy ip route add 198.18.0.12/32 dev wan1
ip netns exec nsproxy ip route add 198.18.0.13/32 dev wan1
ip netns exec nsproxy ip route add 198.18.0.14/32 dev wan1


### [NS-WAN]
#ip link add link qbi-wan dev wan0 type macvlan mode bridge
ip link add wan0 type veth peer name wan0_phy
ip link set wan0_phy master qbi-wan #ip link set $dev nomaster
ip link set dev wan0_phy up
ip link set wan0 netns nswan
ip netns exec nswan ip link set dev wan0 mtu 1500
ip netns exec nswan ip link set dev wan0 address 00:00:C6:12:00:01
ip netns exec nswan ip link set dev wan0 up
ip netns exec nswan ip address add 198.18.0.1/24 dev wan0
# Add new interface for inter-routing
ip link add link qbi-wan2 dev wan1 type macvlan mode bridge
ip link set wan1 netns nswan
ip netns exec nswan ip link set dev wan1 mtu 1500
ip netns exec nswan ip link set dev wan1 address 00:00:C6:12:01:01
ip netns exec nswan ip link set dev wan1 up
ip netns exec nswan ip address add 198.18.1.1/24 dev wan1

### [NS-WAN2]
ip link add link qbi-wan2 dev wan1 type macvlan mode bridge
ip link set wan1 netns nswan2
ip netns exec nswan2 ip link set dev wan1 mtu 1500
ip netns exec nswan2 ip link set dev wan1 address 00:00:C6:12:01:65
ip netns exec nswan2 ip link set dev wan1 up
ip netns exec nswan2 ip address add 198.18.1.101/24 dev wan1
ip netns exec nswan2 ip route add default via 198.18.1.1


##################################### EBTABLES #################################
## Build ARP Responder to force traffic via NSPROXY
### 'The kernel macvtap packet processing bypasses both iptables and ebtables, so libvirt's filters are ineffective for guest interfaces using a macvtap connection'
#
#NIC_BRIDGE="qbi-wan"
#NIC_GATEWAY="wan0_nswan_br"
#NIC_PROXY="wan0_nsproxy_br"
#NIC_RGW="l3-wana_br"
#MAC_SYNPROXY="00:00:c6:12:00:0a"
#MAC_RGW="00:00:00:00:01:BB"
#
#ebtables -t nat -F
## Create different ARP responder based on incoming interface for Realm Gateway IP addresses
#for ip in "198.18.0.11" "198.18.0.12" "198.18.0.13" "198.18.0.14"
#do
#    ebtables -t nat -A PREROUTING --logical-in $NIC_BRIDGE -i $NIC_GATEWAY -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $MAC_SYNPROXY
#    ebtables -t nat -A PREROUTING --logical-in $NIC_BRIDGE -i $NIC_PROXY   -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $MAC_RGW
#    ebtables -t nat -A PREROUTING --logical-in $NIC_BRIDGE -i $NIC_RGW     -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $MAC_RGW
#done
## Create specific ARP responder based on incoming interface from Realm Gateway
#ebtables -t nat -A PREROUTING  --logical-in $NIC_BRIDGE -i $NIC_RGW -p arp --arp-opcode 1 -j arpreply --arpreply-mac $MAC_SYNPROXY


# Setting up TCP SYNPROXY in NS-PROXY - ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
ip netns exec nsproxy sysctl -w net.ipv4.tcp_syncookies=1 # This is not available in the network namespace
ip netns exec nsproxy sysctl -w net.ipv4.tcp_timestamps=1 # This is not available in the network namespace
ip netns exec nsproxy sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
# Disable sending ICMP redirects
ip netns exec nsproxy sysctl -w net.ipv4.conf.all.send_redirects=0
ip netns exec nsproxy sysctl -w net.ipv4.conf.default.send_redirects=0
ip netns exec nsproxy sysctl -w net.ipv4.conf.lo.send_redirects=0
ip netns exec nsproxy sysctl -w net.ipv4.conf.wan0.send_redirects=0
# Enable arp_proxy on wan0 interface to answer ARP for known routes (RealmGateway)
sysctl -w net.ipv4.conf.wan0.proxy_arp=1

ip netns exec nsproxy iptables -t raw    -F
ip netns exec nsproxy iptables -t raw    -A PREROUTING -i wan0 -p tcp -m tcp --syn -j CT --notrack                                                    
ip netns exec nsproxy iptables -t filter -F
ip netns exec nsproxy iptables -t filter -A FORWARD -i wan0 -p tcp -m tcp -d 198.18.0.0/24 -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
ip netns exec nsproxy iptables -t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP

# Create different ARP responder based on incoming interface for Realm Gateway IP addresses
#for ip in "198.18.0.11" "198.18.0.12" "198.18.0.13" "198.18.0.14"
#do
#    ebtables -t nat -A PREROUTING  --logical-in qbi-wan -i wan0_phy -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac 00:00:c6:12:00:0a
#done
# TOCHECK: farpd - ARP reply daemon - http://manpages.ubuntu.com/manpages/xenial/man8/farpd.8.html
