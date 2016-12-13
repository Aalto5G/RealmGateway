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
# + br-something: OpenvSwitch something instance

# Name of the instance
CES1="cesa"
CES2="cesb"

# Linux bridges to attach macvlan interfaces
QBR_CES1="brlan-cesa"
QBR_CES2="brlan-cesb"
QBR_WAN="brwan-ces"

# Physical interfaces in $CES1
PHY_LAN_CES1="phy-$CES1-lan"
PHY_WAN_CES1="phy-$CES1-wan"

# Physical interfaces in $CES2
PHY_LAN_CES2="phy-$CES2-lan"
PHY_WAN_CES2="phy-$CES2-wan"

# Physical interfaces in $CES1
patch_PHY_LAN_CES1="patch_phy-$CES1-lan"
patch_PHY_WAN_CES1="patch_phy-$CES1-wan"

# Physical interfaces in $CES2
patch_PHY_LAN_CES2="patch_phy-$CES2-lan"
patch_PHY_WAN_CES2="patch_phy-$CES2-wan"

#Definition of veth patch for connecting namespaces with Linux bridges
##LAN
PATCH0_HOST1="int-lan-host1"
PATCH1_HOST1="lan0"
PATCH0_HOST2="int-lan-host2"
PATCH1_HOST2="lan0"
##WAN
PATCH0_HOST3="int-wan-host3"
PATCH1_HOST3="wan0"

# Network namespaces
NS_LAN_CES1="$CES1"
NS_LAN_CES2="$CES2"
NS_WAN_CES="wan"

#Definition of MTU in namespaces
MTU_NS_LAN_CES1="1400"
MTU_NS_LAN_CES2="1400"
MTU_NS_WAN_CES="1500"

HOST_NS_LAN_CES1=( 00:00:C0:A8:00:65 192.168.0.101 24 192.168.0.0 192.168.0.1 ) #(IpAddr, netmask, NetAddr, GwAddr)
HOST_NS_LAN_CES2=( 00:00:C0:A8:01:65 192.168.1.101 24 192.168.1.0 192.168.1.1 ) #(IpAddr, netmask, NetAddr, GwAddr)
HOST_NS_WAN_CES=( 00:00:C6:12:00:65 100.64.0.101 24 100.64.1.0 100.64.0.1 ) #(IpAddr, netmask, NetAddr, GwAddr)


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

for i in $QBR_CES1 $QBR_CES2 $QBR_WAN; do
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

for i in $NS_LAN_CES1 $NS_LAN_CES2 $NS_WAN_CES; do
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
array=( $PATCH0_HOST1,$PATCH1_HOST1,$NS_LAN_CES1,$MTU_NS_LAN_CES1,${HOST_NS_LAN_CES1[0]},${HOST_NS_LAN_CES1[1]},${HOST_NS_LAN_CES1[2]},${HOST_NS_LAN_CES1[4]}
        $PATCH0_HOST2,$PATCH1_HOST2,$NS_LAN_CES2,$MTU_NS_LAN_CES2,${HOST_NS_LAN_CES2[0]},${HOST_NS_LAN_CES2[1]},${HOST_NS_LAN_CES2[2]},${HOST_NS_LAN_CES2[4]}
        $PATCH0_HOST3,$PATCH1_HOST3,$NS_WAN_CES,$MTU_NS_WAN_CES,${HOST_NS_WAN_CES[0]},${HOST_NS_WAN_CES[1]},${HOST_NS_WAN_CES[2]},${HOST_NS_WAN_CES[4]}
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
    ip netns exec $3 ip link set dev $2 address $5
    ip netns exec $3 ip link set dev $2 up
    ip netns exec $3 ip address add $6/$7 dev $2
    ip netns exec $3 ip route add default via $8
done
IFS=$OLDIFS



