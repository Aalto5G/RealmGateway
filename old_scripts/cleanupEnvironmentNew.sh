#!/bin/bash
#Create virtual networking scenario for 2 CES nodes
OLDIFS=$IFS

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

# Naming convention
# * qvr: veth pair for routing
# + qvo: veth pair openvswitch side
# + qvb: veth pair bridge side
# + qbr: bridge
# + qr: l3 agent managed port, router side
# + qg: l3 agent managed port, gateway side
# + ovs-something: OpenvSwitch something instance

# Name of the instance
CESNAME="cesa"  #CHANGEME#

# Name of the OVS bridge
OVS_NAME="ovs-$CESNAME"
OVS_DPID="0000000000000001"
# SDN Controller for the OVS instance
OVS_CTRL=( 127.0.0.1 6633 ) #(IpAddr, TcpPort)  #CHANGEME#

# Integration with Linux bridges
QBR_LAN="qbr-$CESNAME-lan"
QBR_WAN="qbr-$CESNAME-wan"
QBR_TUN="qbr-$CESNAME-tun"

# Special case for the Tunnel endpoint interface - veth pair connected to OVS
QVO_TUN="qvo-$CESNAME-tun"

# Virtual Ethernet pairs plugged to Linux bridges
QVB_LAN="qvb-$CESNAME-lan"
QVB_WAN="qvb-$CESNAME-wan"
QVB_TUN="qvb-$CESNAME-tun"

## Other end of the veth pair used for routing
QVR_LAN="l3-$CESNAME-lan"
QVR_WAN="l3-$CESNAME-wan"
QVR_TUN="l3-$CESNAME-tun"

# "Physical" interfaces connected to Linux bridges
PHY_LAN="phy-$CESNAME-lan"
PHY_WAN="phy-$CESNAME-wan"
PHY_TUN="phy-$CESNAME-tun"

# IP address allocation for interfaces 
QVB_LAN_ADDR=( 00:00:00:00:01:AA 192.168.0.1 24 192.168.0.0 )           #(IpAddr, netmask, NetAddr, GwAddr)  #CHANGEME#
QVB_WAN_ADDR=( 00:00:00:00:01:BB 198.18.0.11 24 198.18.0.0 198.18.0.1 ) #(IpAddr, netmask, NetAddr, GwAddr)  #CHANGEME#
QVB_TUN_ADDR=( 00:00:00:00:01:CC 1.1.1.1 32 1.1.1.1 )                   #(IpAddr, netmask, NetAddr, GwAddr)  #CHANGEME#
# IP network allocated for proxy addresses
PROXYNETWORK="172.16.0.0/24"  #CHANGEME#

# Linux bridges to attach macvlan interfaces
LXB_CES1="brlan-cesa"
LXB_CES2="brlan-cesb"
LXB_WAN="brwan-ces"

# Network namespaces
NS_LAN_CES1="cesa"
NS_LAN_CES2="cesb"
NS_WAN_CES="wan"

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Removing the network namespaces..."

for i in $NS_LAN_CES1 $NS_LAN_CES2 $NS_WAN_CES; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
done
    
echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Removing the Linux bridges..."

for i in $QBR_LAN $QBR_WAN $QBR_TUN $LXB_CES1 $LXB_CES2 $LXB_WAN; do
    ##Remove and create new Linux bridges
    ip link set dev $i down > /dev/null 2> /dev/null
    brctl delbr $i > /dev/null 2> /dev/null
done


echo "Removing veth pair interfaces attached to Linux bridges ..."

#Define array for iterations
array=( $QVB_LAN,$QVR_LAN $QVB_WAN,$QVR_WAN $QVB_TUN,$QVR_TUN $PHY_TUN,$QVO_TUN 
        $LXB_CES1 $LXB_CES2 $LXB_WAN
        )
for i in "${array[@]}"; do IFS=","; set $i
    ### Delete veth pairs
    ip link del $1 > /dev/null 2> /dev/null
done
IFS=$OLDIFS

#Delete OVS bridge
ovs-vsctl --if-exists del-br $OVS_NAME
