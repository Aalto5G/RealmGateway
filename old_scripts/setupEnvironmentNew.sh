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


## Disable IPv6 for all interfaces
sysctl -w "net.ipv6.conf.all.disable_ipv6=1"      > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.default.disable_ipv6=1"  > /dev/null 2> /dev/null
sysctl -w "net.ipv6.conf.lo.disable_ipv6=1"       > /dev/null 2> /dev/null

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Creating the Linux bridges..."

for i in $QBR_LAN $QBR_WAN $QBR_TUN; do
    ##Remove and create new Linux bridges
    ip link set dev $i down > /dev/null 2> /dev/null
    brctl delbr $i > /dev/null 2> /dev/null
    brctl addbr $i
    ip link set dev $i up
done

echo ""
echo "Creating veth pair interfaces for attaching to Linux bridges ..."

#Define array for iterations
array=( $QVB_LAN,$QVR_LAN $QVB_WAN,$QVR_WAN $QVB_TUN,$QVR_TUN $PHY_TUN,$QVO_TUN )
for i in "${array[@]}"; do IFS=","; set $i
    ### Recreate veth pairs
    ip link del $1 > /dev/null 2> /dev/null
    ip link add $1 type veth peer name $2
    #Bring up and set promisc
    ip link set dev $1 up promisc on
    ip link set dev $2 up promisc on
    #Disable IPv6
    #sysctl -w "net.ipv6.conf.$1.disable_ipv6=1" > /dev/null 2> /dev/null
    #sysctl -w "net.ipv6.conf.$2.disable_ipv6=1" > /dev/null 2> /dev/null
    #Disable offload
    /sbin/disableOffload $1 > /dev/null 2> /dev/null
    /sbin/disableOffload $2 > /dev/null 2> /dev/null
done
IFS=$OLDIFS


echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Adding patch interfaces to the Linux bridges..."

#Define array for iterations
array=( $QBR_LAN,$PHY_LAN $QBR_WAN,$PHY_WAN $QBR_TUN,$PHY_TUN
        $QBR_LAN,$QVB_LAN $QBR_WAN,$QVB_WAN $QBR_TUN,$QVB_TUN )
for i in "${array[@]}"; do IFS=","; set $i
    #Add veth to Linux bridges
    brctl addif $1 $2
done
IFS=$OLDIFS

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Configuring network for $CESNAME ..."

#Define array for iterations
array=( $QVR_LAN,${QVB_LAN_ADDR[0]},${QVB_LAN_ADDR[1]},${QVB_LAN_ADDR[2]}
        $QVR_WAN,${QVB_WAN_ADDR[0]},${QVB_WAN_ADDR[1]},${QVB_WAN_ADDR[2]}
        $QVR_TUN,${QVB_TUN_ADDR[0]},${QVB_TUN_ADDR[1]},${QVB_TUN_ADDR[2]}
        )

for i in "${array[@]}"; do IFS=","; set $i
    #Configure the routing interfaces
    ip address add $3/$4 dev $1
    ip link set dev $1 address $2
    ip link set dev $1 up
done
IFS=$OLDIFS

echo ""
echo "Enable IP forwarding..."
sysctl -w "net.ipv4.ip_forward=1" > /dev/null 2> /dev/null

echo ""
echo "Enabling NAT via iptables..."
/sbin/iptables -t nat -A POSTROUTING -s ${QVB_LAN_ADDR[1]}/${QVB_LAN_ADDR[2]} -o $QVR_WAN -j SNAT --to ${QVB_WAN_ADDR[1]}
/sbin/iptables -A FORWARD -i $QVR_WAN -o $QVR_LAN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Add static route for proxy addresses
ip link set dev $QVR_TUN arp off
ip route add $PROXYNETWORK dev $QVR_TUN
ip route add default via ${QVB_WAN_ADDR[4]}

################################################################################
##########################  Configuring OpenvSwitch ############################
echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Configuring OpenvSwitch $OVS_NAME instance ..."

#Restart Openvswitch Service
service openvswitch-switch restart

#Delete Openvswitch bridge
ovs-vsctl --if-exists del-br $OVS_NAME
#Create OVS bridge in kernel
ovs-vsctl add-br $OVS_NAME
#Create OVS bridge in userspace
#ovs-vsctl add-br $1 -- set bridge $1 datapath_type=netdev
# Assign a 16 Hex ID to the switch
ovs-vsctl set bridge $OVS_NAME other-config:datapath-id=$OVS_DPID
# Set the OpenFlow version
ovs-vsctl set bridge $OVS_NAME protocols=OpenFlow13
# Configure the switch to enforce the flows and do not learn MAC addresses
ovs-vsctl set-fail-mode $OVS_NAME secure
# Connect to the controller on the IP and TCP port given as parameters
ovs-vsctl set-controller $OVS_NAME tcp:${OVS_CTRL[0]}:${OVS_CTRL[1]}
# Set this option to forward ARP packets to controller
ovs-vsctl set controller $OVS_NAME connection-mode=out-of-band

echo ""
echo "Adding veth tunnel port to OVS instance ..."
#Add the tunnel interface to the Openvswitch bridge
ovs-vsctl --may-exist add-port $OVS_NAME $QVO_TUN

echo ""
echo "Bye!"
echo ""