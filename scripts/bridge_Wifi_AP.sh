#!/bin/bash

# Define physical NIC that will be bridged to the WiFi AP
NIC="enp0s8"
# Define a maximum MSS_VALUE in case of reduced MTU on the WiFi link
MSS_VALUE="1360"

# Send traffic from the linux bridge to iptables
modprobe br_netfilter
modprobe xt_physdev

sysctl -w net.bridge.bridge-nf-call-arptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-filter-pppoe-tagged=0
sysctl -w net.bridge.bridge-nf-filter-vlan-tagged=1
sysctl -w net.bridge.bridge-nf-pass-vlan-input-dev=1

# Connect external access point to virtualized CES/RealmGateway demo
BR_WAN0="br-wan0"
BR_LANA="br-lan0a"
BR_LANB="br-lan0b"

## Create 3 VLANs for 3 SSID WLANs
ip link add link $NIC name $NIC.10 type vlan id 10
ip link add link $NIC name $NIC.20 type vlan id 20
ip link add link $NIC name $NIC.30 type vlan id 30

## Bring the interfaces up
ip link set dev $NIC    up
ip link set dev $NIC.10 up
ip link set dev $NIC.20 up
ip link set dev $NIC.30 up

## Add interfaces to corresponding Linux bridges
ip link set $NIC.10 master $BR_WAN0
ip link set $NIC.20 master $BR_LANA
ip link set $NIC.30 master $BR_LANB

# Apply MSS clamping on Linux bridges
iptables -t mangle -I FORWARD -m physdev --physdev-in  $NIC.+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE
iptables -t mangle -I FORWARD -m physdev --physdev-out $NIC.+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE

