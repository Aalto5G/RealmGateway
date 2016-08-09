#!/bin/bash
#Create virtual networking scenario for 2 CES nodes
OLDIFS=$IFS

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

#Name of the OVS bridges
OVS_BR1="br-cesa"
OVS_BR2="br-cesb"

#Name of the OVS interfaces
OVS_BR1_LAN="cesa-lan"
OVS_BR1_WAN="cesa-wan"
OVS_BR1_VTEP="cesa-vtep"

OVS_BR2_LAN="cesb-lan"
OVS_BR2_WAN="cesb-wan"
OVS_BR2_VTEP="cesb-vtep"

OVS_BR1_LAN_IPADDR=( 192.168.0.1 24 192.168.0.0 )           #(IpAddr, netmask, NetAddr, GwAddr)
OVS_BR1_WAN_IPADDR=( 198.18.0.11 24 198.18.0.0 198.18.0.1 ) #(IpAddr, netmask, NetAddr, GwAddr)
OVS_BR1_VTEP_IPADDR=( 1.1.1.1 32 1.1.1.1 )                  #(IpAddr, netmask, NetAddr, GwAddr)

OVS_BR2_LAN_IPADDR=( 192.168.1.1 24 192.168.1.0 )           #(IpAddr, netmask, NetAddr, GwAddr)
OVS_BR2_WAN_IPADDR=( 198.18.0.12 24 198.18.0.0 198.18.0.1)  #(IpAddr, netmask, NetAddr, GwAddr)
OVS_BR2_VTEP_IPADDR=( 1.1.1.1 32 1.1.1.1 )                  #(IpAddr, netmask, NetAddr, GwAddr)

OVS_BR1_PROXYNETWORK="172.16.0.0/24"
OVS_BR2_PROXYNETWORK="172.16.1.0/24"

#SDN Controllers for the OVS bridges
OVS_BR1_CTRL_IPADDR=( 127.0.0.1 6633 ) #(IpAddr, TcpPort)
OVS_BR2_CTRL_IPADDR=( 127.0.0.1 6633 ) #(IpAddr, TcpPort)

#Create Linux bridges for attaching veth interfaces
BR_LANA="br-lana"
BR_LANB="br-lanb"
BR_WAN="br-wan"

#Define veth patch for connecting OVS bridges with Linux bridges
##LAN
PATCH0_BR1_LAN="int-cesa-lan"
PATCH1_BR1_LAN="int-lan-cesa"
PATCH0_BR2_LAN="int-cesb-lan"
PATCH1_BR2_LAN="int-lan-cesb"
##WAN
PATCH0_BR1_WAN="int-cesa-wan"
PATCH1_BR1_WAN="int-wan-cesa"
PATCH0_BR2_WAN="int-cesb-wan"
PATCH1_BR2_WAN="int-wan-cesb"


#Definition of network namespaces
NS_LAN_A="nslana"
NS_LAN_B="nslanb"
NS_WAN="nswan"
#Definition of MTU in namespaces
MTU_NS_LAN_A="1400"
MTU_NS_LAN_B="1400"
MTU_NS_WAN="1500"

#Definition of veth patch for connecting namespaces with Linux bridges
##LAN
PATCH0_HOST1="int-lan-host1"
PATCH1_HOST1="lan0"
PATCH0_HOST2="int-lan-host2"
PATCH1_HOST2="lan0"
##WAN
PATCH0_HOST3="int-wan-host3"
PATCH1_HOST3="wan0"

#Definition of hosts networking in namespaces
IPADDR_HOST1=( 192.168.0.101 24 192.168.0.0 192.168.0.1 ) #(IpAddr, netmask, NetAddr, GwAddr)
IPADDR_HOST2=( 192.168.1.101 24 192.168.1.0 192.168.1.1 ) #(IpAddr, netmask, NetAddr, GwAddr)
IPADDR_HOST3=( 198.18.0.100  24 198.18.0.0  198.18.0.1 )  #(IpAddr, netmask, NetAddr, GwAddr)

#Delete OVS bridges
for i in $OVS_BR1 $OVS_BR2; do
    ovs-vsctl --if-exists del-br $i
done

#Define array for iterations
array=( $PATCH0_BR1_LAN,$PATCH1_BR1_LAN $PATCH0_BR2_LAN,$PATCH1_BR2_LAN
        $PATCH0_BR1_WAN,$PATCH1_BR1_WAN $PATCH0_BR2_WAN,$PATCH1_BR2_WAN
        )

echo ""
echo "Creating patch interfaces for conecting Linux bridges with OVS..."

for i in "${array[@]}"; do IFS=","; set $i
    ### Recreate veth pairs
    ip link del $1 > /dev/null 2> /dev/null
    ip link add $1 type veth peer name $2
    #Bring up and set promisc
    ip link set dev $1 up promisc on
    ip link set dev $2 up promisc on
    #Disable IPv6
    sysctl -w "net.ipv6.conf.$1.disable_ipv6=1" > /dev/null 2> /dev/null
    sysctl -w "net.ipv6.conf.$2.disable_ipv6=1" > /dev/null 2> /dev/null
    #Disable offload
    /sbin/disableOffload.sh $1 > /dev/null 2> /dev/null
    /sbin/disableOffload.sh $2 > /dev/null 2> /dev/null
done
IFS=$OLDIFS

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Creating the Linux bridges..."

for i in $BR_LANA $BR_LANB $BR_WAN; do
    ##Remove and create new Linux bridges
    ip link set dev $i down > /dev/null 2> /dev/null
    brctl delbr $i > /dev/null 2> /dev/null
    brctl addbr $i
    ip link set dev $i up
done

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Creating network namespaces..."

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in $NS_LAN_A $NS_LAN_B $NS_WAN; do
    ##Remove and create new namespaces
    ip netns del $i > /dev/null 2> /dev/null
    ip netns add $i
    #Configure the loopback interface in namespace
    ip netns exec $i ip address add 127.0.0.1/8 dev lo
    ip netns exec $i ip link set dev lo up
done

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Creating patch interfaces for setting up hosts in network namespaces..."

#Define array for iterations
array=( $PATCH0_HOST1,$PATCH1_HOST1,$NS_LAN_A,$MTU_NS_LAN_A,${IPADDR_HOST1[0]},${IPADDR_HOST1[1]},${IPADDR_HOST1[3]}
        $PATCH0_HOST2,$PATCH1_HOST2,$NS_LAN_B,$MTU_NS_LAN_B,${IPADDR_HOST2[0]},${IPADDR_HOST2[1]},${IPADDR_HOST2[3]}
        $PATCH0_HOST3,$PATCH1_HOST3,$NS_WAN,$MTU_NS_WAN,${IPADDR_HOST3[0]},${IPADDR_HOST3[1]},${IPADDR_HOST3[3]}
        )

for i in "${array[@]}"; do IFS=","; set $i
    ### Recreate veth pairs
    ip link del $1 > /dev/null 2> /dev/null
    ip link add $1 type veth peer name $2
    ### Configure host interface
    ip link set dev $1 up promisc on
    sysctl -w "net.ipv6.conf.$1.disable_ipv6=1" > /dev/null 2> /dev/null
    /sbin/disableOffload.sh $1 > /dev/null 2> /dev/null
    ### Assign and configure namespace interface
    ip link set $2 netns $3
    ip netns exec $3 sysctl -w "net.ipv6.conf.$2.disable_ipv6=1" > /dev/null 2> /dev/null
    ip netns exec $3 ip link set dev $2 mtu $4
    ip netns exec $3 ip link set dev $2 up
    ip netns exec $3 ip address add $5/$6 dev $2
    ip netns exec $3 ip route add default via $7
done
IFS=$OLDIFS

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Adding patch interfaces to the Linux bridges..."

#Define array for iterations
array=( $BR_LANA,$PATCH1_BR1_LAN $BR_LANA,$PATCH0_HOST1
        $BR_LANB,$PATCH1_BR2_LAN $BR_LANB,$PATCH0_HOST2
        $BR_WAN,$PATCH1_BR1_WAN  $BR_WAN,$PATCH1_BR2_WAN
        $BR_WAN,$PATCH0_HOST3
        )

for i in "${array[@]}"; do IFS=","; set $i
    #Add veth to Linux bridges
    brctl addif $1 $2
done
IFS=$OLDIFS

################################################################################
##############################  Configuring OVS ################################
echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Configuring OVS instances..."

#Restart Openvswitch Service
service openvswitch-switch restart

#Define array for iterations
array=( $OVS_BR1,"0000000000000001",${OVS_BR1_CTRL_IPADDR[0]},${OVS_BR1_CTRL_IPADDR[1]}
        $OVS_BR2,"0000000000000002",${OVS_BR2_CTRL_IPADDR[0]},${OVS_BR2_CTRL_IPADDR[1]}
       )

for i in "${array[@]}"; do IFS=","; set $i
    #Delete OVS bridge
    ovs-vsctl --if-exists del-br $1
    #Create OVS bridge in kernel
    ovs-vsctl add-br $1
    #Create OVS bridge in userspace
    #ovs-vsctl add-br $1 -- set bridge $1 datapath_type=netdev
    # Assign a 16 Hex ID to the switch
    ovs-vsctl set bridge $1 other-config:datapath-id=$2
    # Set the OpenFlow version
    ovs-vsctl set bridge $1 protocols=OpenFlow13
    # Configure the SW to enforce the flows and do not learn MAC addresses
    ovs-vsctl set-fail-mode $1 secure
    # Connect to the controller on the IP and TCP port given as parameters
    ovs-vsctl set-controller $1 tcp:$3:$4
    # Set this option to forward ARP packets to controller
    ovs-vsctl set controller $1 connection-mode=out-of-band
done
IFS=$OLDIFS

echo ""
echo "Adding ports to OVS instances..."

#Define array for iterations
array=( $OVS_BR1,$OVS_BR1_LAN,type=internal
        $OVS_BR1,$OVS_BR1_LAN,ofport_request=1
        $OVS_BR1,$OVS_BR1_WAN,type=internal
        $OVS_BR1,$OVS_BR1_WAN,ofport_request=2
        $OVS_BR1,$PATCH0_BR1_LAN,ofport_request=3
        $OVS_BR1,$PATCH0_BR1_WAN,ofport_request=4
        $OVS_BR1,$OVS_BR1_VTEP,type=internal
        $OVS_BR1,$OVS_BR1_VTEP,ofport_request=5
        $OVS_BR2,$OVS_BR2_LAN,type=internal
        $OVS_BR2,$OVS_BR2_LAN,ofport_request=1
        $OVS_BR2,$OVS_BR2_WAN,type=internal
        $OVS_BR2,$OVS_BR2_WAN,ofport_request=2
        $OVS_BR2,$PATCH0_BR2_LAN,ofport_request=3
        $OVS_BR2,$PATCH0_BR2_WAN,ofport_request=4
        $OVS_BR2,$OVS_BR2_VTEP,type=internal
        $OVS_BR2,$OVS_BR2_VTEP,ofport_request=5
        )

for i in "${array[@]}"; do IFS=","; set $i
    #Add the interfaces to the bridge
    ovs-vsctl --may-exist add-port $1 $2 -- set Interface $2 $3
done
IFS=$OLDIFS

#Sleep some time
sleep 2

#Show bridge configuration
ovs-vsctl show

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Configuring networking of OVS instances..."

#Define array for iterations
array=( $OVS_BR1_LAN,${OVS_BR1_LAN_IPADDR[0]},${OVS_BR1_LAN_IPADDR[1]},"00:00:00:00:01:AA"
        $OVS_BR1_WAN,${OVS_BR1_WAN_IPADDR[0]},${OVS_BR1_WAN_IPADDR[1]},"00:00:00:00:01:BB"
        $OVS_BR1_VTEP,${OVS_BR1_VTEP_IPADDR[0]},${OVS_BR1_VTEP_IPADDR[1]},"00:00:00:00:01:CC"
        $OVS_BR2_LAN,${OVS_BR2_LAN_IPADDR[0]},${OVS_BR2_LAN_IPADDR[1]},"00:00:00:00:02:AA"
        $OVS_BR2_WAN,${OVS_BR2_WAN_IPADDR[0]},${OVS_BR2_WAN_IPADDR[1]},"00:00:00:00:02:BB"
        $OVS_BR2_VTEP,${OVS_BR2_VTEP_IPADDR[0]},${OVS_BR2_VTEP_IPADDR[1]},"00:00:00:00:02:CC"
        )

for i in "${array[@]}"; do IFS=","; set $i
    #Configure the internal brigde interfaces
    ip address add $2/$3 dev $1
    ip link set dev $1 address $4
    ip link set dev $1 up
done
IFS=$OLDIFS

echo ""
echo "Enable IP forwarding..."

sysctl -w "net.ipv4.ip_forward=1" > /dev/null 2> /dev/null
#Define array for iterations
array=( $OVS_BR1_LAN,${OVS_BR1_LAN_IPADDR[0]},${OVS_BR1_LAN_IPADDR[1]},$OVS_BR1_WAN,${OVS_BR1_WAN_IPADDR[0]}
        $OVS_BR2_LAN,${OVS_BR2_LAN_IPADDR[0]},${OVS_BR2_LAN_IPADDR[1]},$OVS_BR2_WAN,${OVS_BR2_WAN_IPADDR[0]}
        )

echo ""
echo "Enabling NAT via iptables..."

for i in "${array[@]}"; do IFS=","; set $i
    #/sbin/iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o cesa-wan -j SNAT --to 198.18.0.11
    #/sbin/iptables -A FORWARD -i cesb-wan -o cesa-lan -m state --state RELATED,ESTABLISHED -j ACCEPT
    /sbin/iptables -t nat -A POSTROUTING -s $2/$3 -o $4 -j SNAT --to $5
    /sbin/iptables -A FORWARD -i $4 -o $1 -m state --state RELATED,ESTABLISHED -j ACCEPT
done
IFS=$OLDIFS

echo ""
echo "Setting up flows for OVSBR instances..."
for i in $OVS_BR1 $OVS_BR2; do
    ##Flush table and create basic flows
    ovs-ofctl --protocols=OpenFlow13 del-flows $i
    ovs-ofctl --protocols=OpenFlow13 add-flow  $i table=0,in_port=1,actions=output:3
    ovs-ofctl --protocols=OpenFlow13 add-flow  $i table=0,in_port=3,actions=output:1
    ovs-ofctl --protocols=OpenFlow13 add-flow  $i table=0,in_port=2,actions=output:4
    ovs-ofctl --protocols=OpenFlow13 add-flow  $i table=0,in_port=4,actions=output:2
done

# Add route configuration for proxy addresses
ip link set dev $OVS_BR1_VTEP arp off
ip route add $OVS_BR1_PROXYNETWORK dev $OVS_BR1_VTEP
ip link set dev $OVS_BR2_VTEP arp off
ip route add $OVS_BR2_PROXYNETWORK dev $OVS_BR2_VTEP
