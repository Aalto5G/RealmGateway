#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Create supporting infrastructure for CES-A & CES-B
###############################################################################

echo "Enable IP forwarding"
sysctl -w "net.ipv4.ip_forward=1" > /dev/null 2> /dev/null

echo "Disable IPv6 for all interfaces"
sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null

echo "Unloading bridge kernel modules"
rmmod xt_physdev
rmmod br_netfilter


# [COMMON]
## WAN side
ip link add dev qbi-wan type bridge
ip link set dev qbi-wan up

# [CES-A]
## LAN side
ip link add dev qbi-lana type bridge
ip link set dev qbi-lana up

# [CES-B]
## LAN side
ip link add dev qbi-lanb type bridge
ip link set dev qbi-lanb up



###############################################################################
# Create CES-A configuration
###############################################################################

## LAN side
ip link add link qbi-lana dev l3-lana type macvlan mode bridge
ip link set dev l3-lana address 00:00:00:00:01:AA
ip link set dev l3-lana up

## WAN side
ip link add link qbi-wan dev l3-wana type macvlan mode bridge
ip link set dev l3-wana address 00:00:00:00:01:BB
ip link set dev l3-wana up

## TUN side
ip link add ovs-l3-tuna type veth peer name l3-tuna
ip link set dev l3-tuna address 00:00:00:00:01:CC
ip link set dev l3-tuna mtu 1400
ip link set dev l3-tuna arp off
ip link set dev l3-tuna up
ip link set dev ovs-l3-tuna up
# Create bridge in OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbi-tuna
ovs-vsctl add-br qbi-tuna
ovs-vsctl set bridge qbi-tuna other-config:datapath-id=0000000000000001
ovs-vsctl set bridge qbi-tuna protocols=OpenFlow13
ovs-vsctl set-controller qbi-tuna tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbi-tuna ovs-l3-tuna

# Set IP configuration
ip address add 192.168.0.1/24 dev l3-lana
ip address add 198.18.0.11/24 dev l3-wana
ip address add 1.1.1.1/32     dev l3-tuna
ip route add 172.16.0.0/24    dev l3-tuna

ovs-vsctl --may-exist add-port qbi-tuna tuna-gre0 -- set interface tuna-gre0 type=gre options:local_ip=198.18.0.11 options:remote_ip=198.18.0.12 options:in_key=flow options:out_key=flow \
                                                  -- set interface tuna-gre0 ofport_request=10


###############################################################################
# Create CES-B configuration
###############################################################################

## LAN side
ip link add link qbi-lanb dev l3-lanb type macvlan mode bridge
ip link set dev l3-lanb address 00:00:00:00:02:AA
ip link set dev l3-lanb up

## WAN side
ip link add link qbi-wan dev l3-wanb type macvlan mode bridge
ip link set dev l3-wanb address 00:00:00:00:02:BB
ip link set dev l3-wanb up

## TUN side
ip link add ovs-l3-tunb type veth peer name l3-tunb
ip link set dev l3-tunb address 00:00:00:00:02:CC
ip link set dev l3-tunb mtu 1400
ip link set dev l3-tunb arp off
ip link set dev l3-tunb up
ip link set dev ovs-l3-tunb up
# Create bridge in OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbi-tunb
ovs-vsctl add-br qbi-tunb
ovs-vsctl set bridge qbi-tunb other-config:datapath-id=0000000000000002
ovs-vsctl set bridge qbi-tunb protocols=OpenFlow13
ovs-vsctl set-controller qbi-tunb tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbi-tunb ovs-l3-tunb

# Set IP configuration
ip address add 192.168.1.1/24 dev l3-lanb
ip address add 198.18.0.12/24 dev l3-wanb
ip address add 1.1.1.2/32     dev l3-tunb
ip route add 172.16.1.0/24    dev l3-tunb

ovs-vsctl --may-exist add-port qbi-tunb tunb-gre0 -- set interface tunb-gre0 type=gre options:local_ip=198.18.0.12 options:remote_ip=198.18.0.11 options:in_key=flow options:out_key=flow \
                                                  -- set interface tunb-gre0 ofport_request=10


###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan nswan2; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
    ip netns add $i
    #Configure the loopback interface in namespace
    ip netns exec $i ip address add 127.0.0.1/8 dev lo
    ip netns exec $i ip link set dev lo up
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

### [NS-LAN-B]
ip link add link qbi-lanb dev lan0 type macvlan mode bridge
ip link set lan0 netns nslanb
ip netns exec nslanb ip link set dev lan0 mtu 1500
ip netns exec nslanb ip link set dev lan0 address 00:00:C0:A8:01:65
ip netns exec nslanb ip link set dev lan0 up
ip netns exec nslanb ip address add 192.168.1.101/24 dev lan0
ip netns exec nslanb ip route add default via 192.168.1.1

### [NS-WAN]
ip link add link qbi-wan dev wan0 type macvlan mode bridge
ip link set wan0 netns nswan
ip netns exec nswan ip link set dev wan0 mtu 1500
ip netns exec nswan ip link set dev wan0 address 00:00:C6:12:00:01
ip netns exec nswan ip link set dev wan0 up
ip netns exec nswan ip address add 198.18.0.1/24 dev wan0
# Add new interface for inter-routing
ip link add link qbi-wan dev wan1 type macvlan mode bridge
ip link set wan1 netns nswan
ip netns exec nswan ip link set dev wan1 mtu 1500
ip netns exec nswan ip link set dev wan1 address 00:00:C6:12:01:01
ip netns exec nswan ip link set dev wan1 up
ip netns exec nswan ip address flush dev wan1
ip netns exec nswan ip address add 198.18.1.1/24 dev wan1

### [NS-WAN2]
ip link add link qbi-wan dev wan1 type macvlan mode bridge
ip link set wan1 netns nswan2
ip netns exec nswan2 ip link set dev wan1 mtu 1500
ip netns exec nswan2 ip link set dev wan1 address 00:00:C6:12:01:65
ip netns exec nswan2 ip link set dev wan1 up
ip netns exec nswan2 ip address flush dev wan1
ip netns exec nswan2 ip address add 198.18.1.101/24 dev wan1
ip netns exec nswan2 ip route add default via 198.18.1.1

# Add route in CES-A to reach NS-WAN2
ip route add 198.18.1.0/24 via 198.18.0.1


# Setting up TCP SYNPROXY in NS-WAN2 - ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
ip netns exec nswan2 sysctl -w net/ipv4/tcp_syncookies=1 # This is not available in the network namespace
ip netns exec nswan2 sysctl -w net/ipv4/tcp_timestamps=1 # This is not available in the network namespace
ip netns exec nswan2 sysctl -w net/netfilter/nf_conntrack_tcp_loose=0

ip netns exec nswan2 iptables -t raw    -I PREROUTING -p tcp -m tcp --syn -j CT --notrack                                                    
ip netns exec nswan2 iptables -t filter -I FORWARD -p tcp -m tcp -d 198.18.0.0/24 -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
ip netns exec nswan2 iptables -t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP
