#!/bin/bash
#Cleanup virtual networking scenario for 2 CES nodes
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

OVS_BR1_PROXYNETWORK="172.16.0.0/24"
OVS_BR2_PROXYNETWORK="172.16.1.0/24"

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


#Delete OVS bridges
for i in $OVS_BR1 $OVS_BR2; do
    ovs-vsctl --if-exists del-br $i
done

#Define array for iterations
array=( $PATCH0_BR1_LAN $PATCH0_BR1_WAN $PATCH0_BR2_LAN $PATCH0_BR2_WAN
        $PATCH0_HOST1 $PATCH0_HOST2 $PATCH0_HOST3
        )

echo ""
echo "Deleting patch interfaces..."

for i in "${array[@]}"; do IFS=","; set $i
    ### Deleve veth pairs
    ip link del $1 > /dev/null 2> /dev/null
done
IFS=$OLDIFS

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Deleting the Linux bridges..."

for i in $BR_LANA $BR_LANB $BR_WAN; do
    ##Remove Linux bridges
    ip link set dev $i down > /dev/null 2> /dev/null
    brctl delbr $i > /dev/null 2> /dev/null
done

echo ""
#read -rsp $'Press any key to continue...\n' -n1 key
echo "Deleting network namespaces..."

for i in $NS_LAN_A $NS_LAN_B $NS_WAN; do
    ##Remove namespaces
    ip netns del $i > /dev/null 2> /dev/null
done

exit 1

