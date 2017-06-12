#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

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

# Configure Man-In-The-Middle interface
ip link set dev mitm0 arp off
ip link set dev mitm1 arp off
ip link set dev mitm0 address 00:00:00:aa:bb:cc
ip link set dev mitm1 address 00:00:00:dd:ee:ff
ip route add default dev mitm0
ip route add 195.148.125.201/32 dev mitm1
ip route add 195.148.125.202/32 dev mitm1
ip route add 195.148.125.203/32 dev mitm1
ip route add 195.148.125.204/32 dev mitm1

# Setup flows & rules
## Create ipset for matching
ipset create circularpool hash:ip -!
ipset flush  circularpool
ipset add circularpool 195.148.125.201
ipset add circularpool 195.148.125.202
ipset add circularpool 195.148.125.203
ipset add circularpool 195.148.125.204

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
### Go to ARP MAC Learning table
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=100,dl_type=0x0806,           actions=goto_table:1"
### Go to TCP Forwading table
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=100,dl_type=0x0800,nw_proto=6 actions=goto_table:2"
### Default flow
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=1                             actions=NORMAL"

### ARP MAC Learning Learning table 1
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=1,priority=1                             actions=NORMAL"

### TCP Forwading table 2
# This is a self-populated learning table. Set default flow to go to TCP Learning table 3
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=2,priority=1                             actions=goto_table:3"

### TCP Learning table 3
# NB: Decide on idle_timeout / hard_timeout of learned flows
# Learn new flows coming from WAN
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=3,priority=1,in_port=1,dl_type=0x0800                                                                                                                                                                  \
        actions=load:0x0001->NXM_NX_REG0[0..15],load:0x0002->NXM_NX_REG1[0..15],load:0x0003->NXM_NX_REG2[0..15],load:0x0004->NXM_NX_REG3[0..15],                                                                                                           \
                learn(table=2,hard_timeout=30,priority=200,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
                learn(table=2,                priority=200,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG0[0..15]), \
                learn(table=2,                priority=200,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG3[0..15]), \
                learn(table=2,hard_timeout=30,priority=200,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15]), \
                resubmit(,2)"

# Learn new flows coming from WAN_proxied
ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=3,priority=1,in_port=4,dl_type=0x0800                                                                                                                                                                  \
        actions=load:0x0001->NXM_NX_REG0[0..15],load:0x0002->NXM_NX_REG1[0..15],load:0x0003->NXM_NX_REG2[0..15],load:0x0004->NXM_NX_REG3[0..15],                                                                                                           \
                learn(table=2,hard_timeout=30,priority=100,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
                learn(table=2,                priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG0[0..15]), \
                learn(table=2,                priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG3[0..15]), \
                learn(table=2,hard_timeout=30,priority=100,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15]), \
                resubmit(,2)"
