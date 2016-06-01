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
ip link add qve-phy-lana type veth peer name qvi-phy-lana
brctl addbr qbi-lana
brctl addif qbi-lana qvi-phy-lana
ip link set dev qbi-lana    up
ip link set dev qve-phy-lana    up promisc on
ip link set dev qvi-phy-lana     up promisc on

## WAN side
ip link add qve-phy-wana type veth peer name qvi-phy-wana
brctl addbr qbi-wan
brctl addif qbi-wan qvi-phy-wana
ip link set dev qbi-wan     up
ip link set dev qve-phy-wana    up promisc on
ip link set dev qvi-phy-wana     up promisc on

## TUN side
ip link add qve-phy-tuna type veth peer name qvi-phy-tuna
ip link set dev qve-phy-tuna    up promisc on
ip link set dev qvi-phy-tuna     up promisc on
# Create and add interfaces to OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbi-tuna
ovs-vsctl add-br qbi-tuna
ovs-vsctl set bridge qbi-tuna other-config:datapath-id=0000000000000001
ovs-vsctl set bridge qbi-tuna protocols=OpenFlow13
ovs-vsctl set-controller qbi-tuna tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbi-tuna qvi-phy-tuna

# [CES-B]
## LAN side
ip link add qve-phy-lanb type veth peer name qvi-phy-lanb
brctl addbr qbi-lanb
brctl addif qbi-lanb qvi-phy-lanb
ip link set dev qbi-lanb    up
ip link set dev qve-phy-lanb    up promisc on
ip link set dev qvi-phy-lanb     up promisc on

## WAN side
ip link add qve-phy-wanb type veth peer name qvi-phy-wanb
brctl addbr qbi-wan
brctl addif qbi-wan qvi-phy-wanb
ip link set dev qbi-wan     up
ip link set dev qve-phy-wanb    up promisc on
ip link set dev qvi-phy-wanb     up promisc on

## TUN side
ip link add qve-phy-tunb type veth peer name qvi-phy-tunb
ip link set dev qve-phy-tunb    up promisc on
ip link set dev qvi-phy-tunb     up promisc on
# Create and add interfaces to OpenvSwitch
service openvswitch-switch restart
ovs-vsctl --if-exists del-br qbi-tunb
ovs-vsctl add-br qbi-tunb
ovs-vsctl set bridge qbi-tunb other-config:datapath-id=0000000000000002
ovs-vsctl set bridge qbi-tunb protocols=OpenFlow13
ovs-vsctl set-controller qbi-tunb tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port qbi-tunb qvi-phy-tunb


###############################################################################
# Create CES-A configuration
###############################################################################

## LAN side
ip link add qve-l3-lana type veth peer name l3-lana
brctl addbr qbf-lana
brctl addif qbf-lana qve-l3-lana
brctl addif qbf-lana qve-phy-lana
ip link set dev qbf-lana up
ip link set dev qve-phy-lana    up promisc on
ip link set dev qve-l3-lana     up promisc on
ip link set dev l3-lana         up promisc off
ip link set dev l3-lana address 00:00:00:00:01:AA

## WAN side
ip link add qve-l3-wana type veth peer name l3-wana
brctl addbr qbf-wana
brctl addif qbf-wana qve-l3-wana
brctl addif qbf-wana qve-phy-wana
ip link set dev qbf-wana up
ip link set dev qve-phy-wana    up promisc on
ip link set dev qve-l3-wana     up promisc on
ip link set dev l3-wana         up promisc off
ip link set dev l3-wana address 00:00:00:00:01:BB

## TUN side
ip link add qve-l3-tuna type veth peer name l3-tuna
brctl addbr qbf-tuna
brctl addif qbf-tuna qve-l3-tuna
brctl addif qbf-tuna qve-phy-tuna
ip link set dev qbf-tuna up
ip link set dev qve-phy-tuna    up promisc on
ip link set dev qve-l3-tuna     up promisc on
ip link set dev l3-tuna         up promisc off
ip link set dev l3-tuna address 00:00:00:00:01:CC

### Disable MAC learning in filtering bridges
brctl setageing qbf-lana 0
brctl setageing qbf-wana 0
brctl setageing qbf-tuna 0

# Set IP configuration
ip address add 192.168.0.1/24 dev l3-lana
ip address add 198.18.0.11/24 dev l3-wana
ip address add 1.1.1.1/32     dev l3-tuna
ip link set dev l3-tuna arp off
ip route add 172.16.0.0/24 dev l3-tuna

ovs-vsctl --may-exist add-port qbi-tuna tuna-gre0 -- set interface tuna-gre0 type=gre options:local_ip=198.18.0.11 options:remote_ip=198.18.0.12 options:in_key=flow options:out_key=flow \
                                                  -- set interface tuna-gre0 ofport_request=10
                                                      

###############################################################################
# Create CES-B configuration
###############################################################################

## LAN side
ip link add qve-l3-lanb type veth peer name l3-lanb
brctl addbr qbf-lanb
brctl addif qbf-lanb qve-l3-lanb
brctl addif qbf-lanb qve-phy-lanb
ip link set dev qbf-lanb up
ip link set dev qve-phy-lanb    up promisc on
ip link set dev qve-l3-lanb     up promisc on
ip link set dev l3-lanb         up promisc off
ip link set dev l3-lanb address 00:00:00:00:02:AA

## WAN side
ip link add qve-l3-wanb type veth peer name l3-wanb
brctl addbr qbf-wanb
brctl addif qbf-wanb qve-l3-wanb
brctl addif qbf-wanb qve-phy-wanb
ip link set dev qbf-wanb up
ip link set dev qve-phy-wanb    up promisc on
ip link set dev qve-l3-wanb     up promisc on
ip link set dev l3-wanb         up promisc off
ip link set dev l3-wanb address 00:00:00:00:02:BB

## TUN side
ip link add qve-l3-tunb type veth peer name l3-tunb
brctl addbr qbf-tunb
brctl addif qbf-tunb qve-l3-tunb
brctl addif qbf-tunb qve-phy-tunb
ip link set dev qbf-tunb up
ip link set dev qve-phy-tunb    up promisc on
ip link set dev qve-l3-tunb     up promisc on
ip link set dev l3-tunb         up promisc off
ip link set dev l3-tunb address 00:00:00:00:02:CC

### Disable MAC learning in filtering bridges
brctl setageing qbf-lanb 0
brctl setageing qbf-wanb 0
brctl setageing qbf-tunb 0

# Set IP configuration
ip address add 192.168.1.1/24 dev l3-lanb
ip address add 198.18.0.12/24 dev l3-wanb
ip address add 1.1.1.2/32     dev l3-tunb
ip link set dev l3-tunb arp off
ip route add 172.16.1.0/24 dev l3-tunb

ovs-vsctl --may-exist add-port qbi-tunb tunb-gre0 -- set interface tunb-gre0 type=gre options:local_ip=198.18.0.12 options:remote_ip=198.18.0.11 options:in_key=flow options:out_key=flow \
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
ip link add link qbi-lana dev lan0 type macvlan
ip link set lan0 netns nslana
ip netns exec nslana ip link set dev lan0 mtu 1400
ip netns exec nslana ip link set dev lan0 address 00:00:C0:A8:00:65
ip netns exec nslana ip link set dev lan0 up
ip netns exec nslana ip address add 192.168.0.101/24 dev lan0
ip netns exec nslana ip route add default via 192.168.0.1

### [NS-LAN-B]
ip link add link qbi-lanb dev lan0 type macvlan
ip link set lan0 netns nslanb
ip netns exec nslanb ip link set dev lan0 mtu 1400
ip netns exec nslanb ip link set dev lan0 address 00:00:C0:A8:01:65
ip netns exec nslanb ip link set dev lan0 up
ip netns exec nslanb ip address add 192.168.1.101/24 dev lan0
ip netns exec nslanb ip route add default via 192.168.1.1

### [NS-WAN]
ip link add link qbi-wan dev wan0 type macvlan
ip link set wan0 netns nswan
ip netns exec nswan ip link set dev wan0 mtu 1500
ip netns exec nswan ip link set dev wan0 address 00:00:C6:12:00:65
ip netns exec nswan ip link set dev wan0 up
ip netns exec nswan ip address add 198.18.0.101/24 dev wan0
ip netns exec nswan ip route add default via 198.18.0.1
