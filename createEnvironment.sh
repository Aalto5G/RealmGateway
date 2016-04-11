#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Create supporting infrastructure for CES-A & CES-B
###############################################################################

echo "Enable IP forwarding..."
sysctl -w "net.ipv4.ip_forward=1" > /dev/null 2> /dev/null

echo "Disable IPv6 for all interfaces"
sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null

echo "Loading bridge kernel modules"
modprobe br_netfilter
modprobe xt_physdev
## Modifying sysctl configuration for bridges
sysctl -w "net.bridge.bridge-nf-call-arptables=1"
sysctl -w "net.bridge.bridge-nf-call-ip6tables=1"
sysctl -w "net.bridge.bridge-nf-call-iptables=1"
sysctl -w "net.bridge.bridge-nf-filter-pppoe-tagged=0"
sysctl -w "net.bridge.bridge-nf-filter-vlan-tagged=0"
sysctl -w "net.bridge.bridge-nf-pass-vlan-input-dev=0"


# [CES-A]
## LAN side
ip link add qve-phy-lana type veth peer name qve-l2-lana
brctl addbr qbr-int-lana
brctl addif qbr-int-lana qve-l2-lana
ip link set dev qbr-int-lana    up
ip link set dev qve-phy-lana    up promisc on
ip link set dev qve-l2-lana     up promisc on

## WAN side
ip link add qve-phy-wana type veth peer name qve-l2-wana
brctl addbr qbr-int-wan
brctl addif qbr-int-wan qve-l2-wana
ip link set dev qbr-int-wan     up
ip link set dev qve-phy-wana    up promisc on
ip link set dev qve-l2-wana     up promisc on

## TUN side
ip link add qve-phy-tuna type veth peer name qve-l2-tuna
ip link set dev qve-phy-tuna    up promisc on
ip link set dev qve-l2-tuna     up promisc on
# Create and add interfaces to OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbr-int-tuna
ovs-vsctl add-br qbr-int-tuna
ovs-vsctl set bridge qbr-int-tuna other-config:datapath-id=0000000000000001
ovs-vsctl set bridge qbr-int-tuna protocols=OpenFlow13
ovs-vsctl set-controller qbr-int-tuna tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbr-int-tuna qve-l2-tuna

# [CES-B]
## LAN side
ip link add qve-phy-lanb type veth peer name qve-l2-lanb
brctl addbr qbr-int-lanb
brctl addif qbr-int-lanb qve-l2-lanb
ip link set dev qbr-int-lanb    up
ip link set dev qve-phy-lanb    up promisc on
ip link set dev qve-l2-lanb     up promisc on

## WAN side
ip link add qve-phy-wanb type veth peer name qve-l2-wanb
brctl addbr qbr-int-wan
brctl addif qbr-int-wan qve-l2-wanb
ip link set dev qbr-int-wan     up
ip link set dev qve-phy-wanb    up promisc on
ip link set dev qve-l2-wanb     up promisc on

## TUN side
ip link add qve-phy-tunb type veth peer name qve-l2-tunb
ip link set dev qve-phy-tunb    up promisc on
ip link set dev qve-l2-tunb     up promisc on
# Create and add interfaces to OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbr-int-tunb
ovs-vsctl add-br qbr-int-tunb
ovs-vsctl set bridge qbr-int-tunb other-config:datapath-id=0000000000000002
ovs-vsctl set bridge qbr-int-tunb protocols=OpenFlow13
ovs-vsctl set-controller qbr-int-tunb tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbr-int-tunb qve-l2-tunb


###############################################################################
# Create CES-A configuration
###############################################################################

## LAN side
ip link add qve-l3-lana type veth peer name l3-lana
brctl addbr qbr-filter-lana
brctl addif qbr-filter-lana qve-l3-lana
brctl addif qbr-filter-lana qve-phy-lana
ip link set dev qbr-filter-lana up
ip link set dev qve-phy-lana    up promisc on
ip link set dev qve-l3-lana     up promisc on
ip link set dev l3-lana         up promisc off
ip link set dev l3-lana address 00:00:00:00:01:AA

## WAN side
ip link add qve-l3-wana type veth peer name l3-wana
brctl addbr qbr-filter-wana
brctl addif qbr-filter-wana qve-l3-wana
brctl addif qbr-filter-wana qve-phy-wana
ip link set dev qbr-filter-wana up
ip link set dev qve-phy-wana    up promisc on
ip link set dev qve-l3-wana     up promisc on
ip link set dev l3-wana         up promisc off
ip link set dev l3-wana address 00:00:00:00:01:BB

## TUN side
ip link add qve-l3-tuna type veth peer name l3-tuna
brctl addbr qbr-filter-tuna
brctl addif qbr-filter-tuna qve-l3-tuna
brctl addif qbr-filter-tuna qve-phy-tuna
ip link set dev qbr-filter-tuna up
ip link set dev qve-phy-tuna    up promisc on
ip link set dev qve-l3-tuna     up promisc on
ip link set dev l3-tuna         up promisc off
ip link set dev l3-tuna address 00:00:00:00:01:CC

### Disable MAC learning in filtering bridges
brctl setageing qbr-filter-lana 0
brctl setageing qbr-filter-wana 0
brctl setageing qbr-filter-tuna 0

# Set IP configuration
ip address add 192.168.0.1/24 dev l3-lana
ip address add 198.18.0.11/24 dev l3-wana
ip address add 1.1.1.1/32     dev l3-tuna
ip link set dev l3-tuna arp off
ip route add 172.16.0.0/24 dev l3-tuna

ovs-vsctl --may-exist add-port qbr-int-tuna tuna-gre0 -- set interface tuna-gre0 type=gre options:local_ip=198.18.0.11 options:remote_ip=198.18.0.12 options:in_key=flow options:out_key=flow \
                                                      -- set interface tuna-gre0 ofport_request=10
                                                      

###############################################################################
# Create CES-B configuration
###############################################################################

## LAN side
ip link add qve-l3-lanb type veth peer name l3-lanb
brctl addbr qbr-filter-lanb
brctl addif qbr-filter-lanb qve-l3-lanb
brctl addif qbr-filter-lanb qve-phy-lanb
ip link set dev qbr-filter-lanb up
ip link set dev qve-phy-lanb    up promisc on
ip link set dev qve-l3-lanb     up promisc on
ip link set dev l3-lanb         up promisc off
ip link set dev l3-lanb address 00:00:00:00:02:AA

## WAN side
ip link add qve-l3-wanb type veth peer name l3-wanb
brctl addbr qbr-filter-wanb
brctl addif qbr-filter-wanb qve-l3-wanb
brctl addif qbr-filter-wanb qve-phy-wanb
ip link set dev qbr-filter-wanb up
ip link set dev qve-phy-wanb    up promisc on
ip link set dev qve-l3-wanb     up promisc on
ip link set dev l3-wanb         up promisc off
ip link set dev l3-wanb address 00:00:00:00:02:BB

## TUN side
ip link add qve-l3-tunb type veth peer name l3-tunb
brctl addbr qbr-filter-tunb
brctl addif qbr-filter-tunb qve-l3-tunb
brctl addif qbr-filter-tunb qve-phy-tunb
ip link set dev qbr-filter-tunb up
ip link set dev qve-phy-tunb    up promisc on
ip link set dev qve-l3-tunb     up promisc on
ip link set dev l3-tunb         up promisc off
ip link set dev l3-tunb address 00:00:00:00:02:CC

### Disable MAC learning in filtering bridges
brctl setageing qbr-filter-lanb 0
brctl setageing qbr-filter-wanb 0
brctl setageing qbr-filter-tunb 0

# Set IP configuration
ip address add 192.168.1.1/24 dev l3-lanb
ip address add 198.18.0.12/24 dev l3-wanb
ip address add 1.1.1.2/32     dev l3-tunb
ip link set dev l3-tunb arp off
ip route add 172.16.1.0/24 dev l3-tunb

ovs-vsctl --may-exist add-port qbr-int-tunb tunb-gre0 -- set interface tunb-gre0 type=gre options:local_ip=198.18.0.12 options:remote_ip=198.18.0.11 options:in_key=flow options:out_key=flow \
                                                      -- set interface tunb-gre0 ofport_request=10

                                                           
###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
    ip netns add $i
    #Configure the loopback interface in namespace
    ip netns exec $i ip address add 127.0.0.1/8 dev lo
    ip netns exec $i ip link set dev lo up
done

## Assign and configure namespace interface
### [NS-LAN-A]
ip link add link qbr-int-lana dev lan0 type macvlan
ip link set lan0 netns nslana
ip netns exec nslana ip link set dev lan0 mtu 1400
ip netns exec nslana ip link set dev lan0 address 00:00:C0:A8:00:65
ip netns exec nslana ip link set dev lan0 up
ip netns exec nslana ip address add 192.168.0.101/24 dev lan0
ip netns exec nslana ip route add default via 192.168.0.1

### [NS-LAN-B]
ip link add link qbr-int-lanb dev lan0 type macvlan
ip link set lan0 netns nslanb
ip netns exec nslanb ip link set dev lan0 mtu 1400
ip netns exec nslanb ip link set dev lan0 address 00:00:C0:A8:01:65
ip netns exec nslanb ip link set dev lan0 up
ip netns exec nslanb ip address add 192.168.1.101/24 dev lan0
ip netns exec nslanb ip route add default via 192.168.1.1

### [NS-WAN]
ip link add link qbr-int-wan dev wan0 type macvlan
ip link set wan0 netns nswan
ip netns exec nswan ip link set dev wan0 mtu 1500
ip netns exec nswan ip link set dev wan0 address 00:00:C6:12:00:65
ip netns exec nswan ip link set dev wan0 up
ip netns exec nswan ip address add 198.18.0.101/24 dev wan0
ip netns exec nswan ip route add default via 198.18.0.1
