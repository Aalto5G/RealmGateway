#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

# Definition of IP addresses protected by SYNPROXY
IP_POOL="100.64.1.130 100.64.1.131 100.64.1.132 100.64.1.133 100.64.1.134 100.64.1.135 100.64.1.136 100.64.1.137 100.64.1.138 100.64.1.139 100.64.1.140 100.64.1.141 100.64.1.142"

# Restart OpenvSwitch service
systemctl restart openvswitch-switch

## Create OVS bridges
ovs-vsctl del-br br-synproxy
ovs-vsctl add-br br-synproxy

ovs-vsctl add-port br-synproxy wan0  -- set interface wan0  ofport_request=1
ovs-vsctl add-port br-synproxy mitm0 -- set interface mitm0 ofport_request=2 -- set interface mitm0 type=internal # Connected to *WAN*
ovs-vsctl add-port br-synproxy mitm1 -- set interface mitm1 ofport_request=3 -- set interface mitm1 type=internal # Connected to *WAN_proxied*
ovs-vsctl add-port br-synproxy wan0p -- set interface wan0p ofport_request=4

# Bring up the interfaces
ip link set dev wan0 up
ip link set dev wan0p up
ip link set dev mitm0 up
ip link set dev mitm1 up

# Configure txqueuelen of interfaces / default is 1000
MAX_QLEN=10000
ip link set dev wan0        qlen $MAX_QLEN
ip link set dev wan0p       qlen $MAX_QLEN
ip link set dev mitm0       qlen $MAX_QLEN
ip link set dev mitm1       qlen $MAX_QLEN
ip link set dev br-synproxy qlen $MAX_QLEN

# Configure Man-In-The-Middle interface
ip link set dev mitm0 arp off
ip link set dev mitm1 arp off
ip link set dev mitm0 address 00:00:00:aa:bb:cc
ip link set dev mitm1 address 00:00:00:dd:ee:ff
ip route add default dev mitm0
for ipaddr in $IP_POOL; do
    ip route add $ipaddr/32 dev mitm1
done

# Setup flows & rules
## Create ipset for matching
ipset create circularpool hash:ip -!
ipset flush  circularpool
for ipaddr in $IP_POOL; do
    ipset add circularpool $ipaddr
done

# Setting up TCP SYNPROXY ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0

## Create iptable rules
iptables -t raw    -F
iptables -t raw    -A PREROUTING -i mitm0 -m set --match-set circularpool dst -p tcp -m tcp --syn -j CT --notrack
iptables -t filter -F
iptables -t filter -A FORWARD -i mitm0 -o mitm1 -m set --match-set circularpool dst -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t filter -A FORWARD -p tcp -m conntrack --ctstate INVALID -j DROP


# OpenvSwitch setup
## Create OVS flows
ovs-ofctl del-flows -O OpenFlow13 br-synproxy

### Table 0: Traffic selector
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=100,dl_type=0x0800 actions=resubmit(,2)"
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=1                  actions=resubmit(,1)"


### Table 1: Enable transparent L2-switching
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=1,priority=100,in_port=1      actions=output:4"
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=1,priority=100,in_port=4      actions=output:1"


### Table 2: Controls the packet pipelining
# This is a self-populated learning table. Set default flow to go to TCP Learning table 3
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=2,priority=100                actions=resubmit(,10),resubmit(,11),resubmit(,12)"


### Table 10: Load port values in NXM registry
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=10,priority=100               actions=load:0x0001->NXM_NX_REG0[0..15],load:0x0002->NXM_NX_REG1[0..15],load:0x0003->NXM_NX_REG2[0..15],load:0x0004->NXM_NX_REG3[0..15]"

### Table 11: Contains the learning flows
# Learn new flows coming from WAN
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=11,priority=1,in_port=1,dl_type=0x0800                                                                                                                       \
        actions=learn(table=12,priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[] output:NXM_NX_REG0[0..15]), \
                learn(table=12,priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[] output:NXM_NX_REG3[0..15])"

# Learn new flows coming from WAN_proxied
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=11,priority=1,in_port=4,dl_type=0x0800                                                                                                                       \
        actions=learn(table=12,priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[] output:NXM_NX_REG0[0..15]), \
                learn(table=12,priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[] output:NXM_NX_REG3[0..15])"

### Table 12: Contains the self-populated learned flows and the default flows
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=12,priority=1,in_port=1,      actions=load:0x000000aabbcc->NXM_OF_ETH_DST[], output:2"
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=12,priority=1,in_port=4,      actions=load:0x000000ddeeff->NXM_OF_ETH_DST[], output:3"


# Trace application
#ovs-appctl ofproto/trace br-synproxy in_port=1,tcp,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:04,nw_src=1.1.1.1,nw_dst=195.148.125.201,tcp_dst=81,tcp_src=12345 -




# This is the former configuration.
# There is a problem in table=12 that the learned flow is not found, so the first packet populates the table but is also dropped

#### Table 11: Contains the learning flows
## Learn new flows coming from WAN
#ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=11,priority=1,in_port=1,dl_type=0x0800                                                                                                                                                  \
#        actions=learn(table=12,priority=100,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
#                learn(table=12,priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG0[0..15]), \
#                learn(table=12,priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG3[0..15]), \
#                learn(table=12,priority=100,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15])"
#
## Learn new flows coming from WAN_proxied
#ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=11,priority=1,in_port=4,dl_type=0x0800                                                                                                                                                  \
#        actions=learn(table=12,priority=100,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
#                learn(table=12,priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG0[0..15]), \
#                learn(table=12,priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG3[0..15]), \
#                learn(table=12,priority=100,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15])"
#
