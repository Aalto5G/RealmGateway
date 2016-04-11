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
sudo modprobe br_netfilter
sudo modprobe xt_physdev
## Modifying sysctl configuration for bridges
sysctl -w "net.bridge.bridge-nf-call-arptables=1"
sysctl -w "net.bridge.bridge-nf-call-ip6tables=1"
sysctl -w "net.bridge.bridge-nf-call-iptables=1"
sysctl -w "net.bridge.bridge-nf-filter-pppoe-tagged=0"
sysctl -w "net.bridge.bridge-nf-filter-vlan-tagged=0"
sysctl -w "net.bridge.bridge-nf-pass-vlan-input-dev=0"


# [CES-A]
## LAN side
sudo ip link add qve-phy-lana type veth peer name qve-l2-lana
sudo brctl addbr qbr-int-lana
sudo brctl addif qbr-int-lana qve-l2-lana
sudo ip link set dev qbr-int-lana    up
sudo ip link set dev qve-phy-lana    up promisc on
sudo ip link set dev qve-l2-lana     up promisc on

## WAN side
sudo ip link add qve-phy-wana type veth peer name qve-l2-wana
sudo brctl addbr qbr-int-wan
sudo brctl addif qbr-int-wan qve-l2-wana
sudo ip link set dev qbr-int-wan     up
sudo ip link set dev qve-phy-wana    up promisc on
sudo ip link set dev qve-l2-wana     up promisc on

## TUN side
sudo ip link add qve-phy-tuna type veth peer name qve-l2-tuna
sudo ip link set dev qve-phy-tuna    up promisc on
sudo ip link set dev qve-l2-tuna     up promisc on
# Create and add interfaces to OpenvSwitch
sudo service openvswitch-switch restart
sudo ovs-vsctl --if-exists del-br qbr-int-tuna
sudo ovs-vsctl add-br qbr-int-tuna
sudo ovs-vsctl set bridge qbr-int-tuna other-config:datapath-id=0000000000000001
sudo ovs-vsctl set bridge qbr-int-tuna protocols=OpenFlow13
sudo ovs-vsctl set-controller qbr-int-tuna tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
sudo ovs-vsctl --may-exist add-port qbr-int-tuna qve-l2-tuna

# [CES-B]
## LAN side
sudo ip link add qve-phy-lanb type veth peer name qve-l2-lanb
sudo brctl addbr qbr-int-lanb
sudo brctl addif qbr-int-lanb qve-l2-lanb
sudo ip link set dev qbr-int-lanb    up
sudo ip link set dev qve-phy-lanb    up promisc on
sudo ip link set dev qve-l2-lanb     up promisc on

## WAN side
sudo ip link add qve-phy-wanb type veth peer name qve-l2-wanb
sudo brctl addbr qbr-int-wan
sudo brctl addif qbr-int-wan qve-l2-wanb
sudo ip link set dev qbr-int-wan     up
sudo ip link set dev qve-phy-wanb    up promisc on
sudo ip link set dev qve-l2-wanb     up promisc on

## TUN side
sudo ip link add qve-phy-tunb type veth peer name qve-l2-tunb
sudo ip link set dev qve-phy-tunb    up promisc on
sudo ip link set dev qve-l2-tunb     up promisc on
# Create and add interfaces to OpenvSwitch
sudo service openvswitch-switch restart
sudo ovs-vsctl --if-exists del-br qbr-int-tunb
sudo ovs-vsctl add-br qbr-int-tunb
sudo ovs-vsctl set bridge qbr-int-tunb other-config:datapath-id=0000000000000002
sudo ovs-vsctl set bridge qbr-int-tunb protocols=OpenFlow13
sudo ovs-vsctl set-controller qbr-int-tunb tcp:127.0.0.1:6633
#Add the tunnel interface to the Openvswitch bridge
sudo ovs-vsctl --may-exist add-port qbr-int-tunb qve-l2-tunb


###############################################################################
# Create CES-A configuration
###############################################################################

## LAN side
sudo ip link add qve-l3-lana type veth peer name l3-lana
sudo brctl addbr qbr-filter-lana
sudo brctl addif qbr-filter-lana qve-l3-lana
sudo brctl addif qbr-filter-lana qve-phy-lana
sudo ip link set dev qbr-filter-lana up
sudo ip link set dev qve-phy-lana    up promisc on
sudo ip link set dev qve-l3-lana     up promisc on
sudo ip link set dev l3-lana         up promisc off

## WAN side
sudo ip link add qve-l3-wana type veth peer name l3-wana
sudo brctl addbr qbr-filter-wana
sudo brctl addif qbr-filter-wana qve-l3-wana
sudo brctl addif qbr-filter-wana qve-phy-wana
sudo ip link set dev qbr-filter-wana up
sudo ip link set dev qve-phy-wana    up promisc on
sudo ip link set dev qve-l3-wana     up promisc on
sudo ip link set dev l3-wana         up promisc off

## TUN side
sudo ip link add qve-l3-tuna type veth peer name l3-tuna
sudo brctl addbr qbr-filter-tuna
sudo brctl addif qbr-filter-tuna qve-l3-tuna
sudo brctl addif qbr-filter-tuna qve-phy-tuna
sudo ip link set dev qbr-filter-tuna up
sudo ip link set dev qve-phy-tuna    up promisc on
sudo ip link set dev qve-l3-tuna     up promisc on
sudo ip link set dev l3-tuna         up promisc off

### Disable MAC learning in filtering bridges
sudo brctl setageing qbr-filter-lana 0
sudo brctl setageing qbr-filter-wana 0
sudo brctl setageing qbr-filter-tuna 0

# Set IP configuration
sudo ip address add 192.168.0.1/24 dev l3-lana
sudo ip address add 198.18.0.11/24 dev l3-wana
sudo ip address add 1.1.1.1/32     dev l3-tuna
sudo ip link set dev l3-tuna arp off
sudo ip route add 172.16.0.0/24 dev l3-tuna

sudo ovs-vsctl --may-exist add-port qbr-int-tuna tuna-gre0 -- set interface tuna-gre0 type=gre options:local_ip=198.18.0.11 options:remote_ip=198.18.0.12 options:in_key=flow options:out_key=flow \
                                                           -- set interface tuna-gre0 ofport_request=10
                                                      

###############################################################################
# Create CES-B configuration
###############################################################################

## LAN side
sudo ip link add qve-l3-lanb type veth peer name l3-lanb
sudo brctl addbr qbr-filter-lanb
sudo brctl addif qbr-filter-lanb qve-l3-lanb
sudo brctl addif qbr-filter-lanb qve-phy-lanb
sudo ip link set dev qbr-filter-lanb up
sudo ip link set dev qve-phy-lanb    up promisc on
sudo ip link set dev qve-l3-lanb     up promisc on
sudo ip link set dev l3-lanb         up promisc off

## WAN side
sudo ip link add qve-l3-wanb type veth peer name l3-wanb
sudo brctl addbr qbr-filter-wanb
sudo brctl addif qbr-filter-wanb qve-l3-wanb
sudo brctl addif qbr-filter-wanb qve-phy-wanb
sudo ip link set dev qbr-filter-wanb up
sudo ip link set dev qve-phy-wanb    up promisc on
sudo ip link set dev qve-l3-wanb     up promisc on
sudo ip link set dev l3-wanb         up promisc off

## TUN side
sudo ip link add qve-l3-tunb type veth peer name l3-tunb
sudo brctl addbr qbr-filter-tunb
sudo brctl addif qbr-filter-tunb qve-l3-tunb
sudo brctl addif qbr-filter-tunb qve-phy-tunb
sudo ip link set dev qbr-filter-tunb up
sudo ip link set dev qve-phy-tunb    up promisc on
sudo ip link set dev qve-l3-tunb     up promisc on
sudo ip link set dev l3-tunb         up promisc off

### Disable MAC learning in filtering bridges
sudo brctl setageing qbr-filter-lanb 0
sudo brctl setageing qbr-filter-wanb 0
sudo brctl setageing qbr-filter-tunb 0

# Set IP configuration
sudo ip address add 192.168.1.1/24 dev l3-lanb
sudo ip address add 198.18.0.12/24 dev l3-wanb
sudo ip address add 1.1.1.2/32     dev l3-tunb
sudo ip link set dev l3-tunb arp off
sudo ip route add 172.16.1.0/24 dev l3-tunb

sudo ovs-vsctl --may-exist add-port qbr-int-tunb tunb-gre0 -- set interface tunb-gre0 type=gre options:local_ip=198.18.0.12 options:remote_ip=198.18.0.11 options:in_key=flow options:out_key=flow \
                                                           -- set interface tunb-gre0 ofport_request=10

                                                           
###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
sudo ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan; do
    ##Remove and create new namespaces
    sudo ip netns del $i > /dev/null 2> /dev/null
    sudo ip netns add $i
    #Configure the loopback interface in namespace
    sudo ip netns exec $i ip address add 127.0.0.1/8 dev lo
    sudo ip netns exec $i ip link set dev lo up
done

## Assign and configure namespace interface
### [NS-LAN-A]
sudo ip link add link qbr-int-lana dev lan0 type macvlan
sudo ip link set lan0 netns nslana
sudo ip netns exec nslana ip link set dev lan0 mtu 1400
sudo ip netns exec nslana ip link set dev lan0 address 00:00:C0:A8:00:65
sudo ip netns exec nslana ip link set dev lan0 up
sudo ip netns exec nslana ip address add 192.168.0.101/24 dev lan0
sudo ip netns exec nslana ip route add default via 192.168.0.1

### [NS-LAN-B]
sudo ip link add link qbr-int-lanb dev lan0 type macvlan
sudo ip link set lan0 netns nslanb
sudo ip netns exec nslanb ip link set dev lan0 mtu 1400
sudo ip netns exec nslanb ip link set dev lan0 address 00:00:C0:A8:01:65
sudo ip netns exec nslanb ip link set dev lan0 up
sudo ip netns exec nslanb ip address add 192.168.1.101/24 dev lan0
sudo ip netns exec nslanb ip route add default via 192.168.1.1

### [NS-WAN]
sudo ip link add link qbr-int-wan dev wan0 type macvlan
sudo ip link set wan0 netns nswan
sudo ip netns exec nswan ip link set dev wan0 mtu 1500
sudo ip netns exec nswan ip link set dev wan0 address 00:00:C6:12:00:65
sudo ip netns exec nswan ip link set dev wan0 up
sudo ip netns exec nswan ip address add 198.18.0.101/24 dev wan0
sudo ip netns exec nswan ip route add default via 198.18.0.1
