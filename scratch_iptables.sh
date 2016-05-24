
#Remove CES-B
sudo ovs-vsctl del-br qbi-tunb
for nic in "qbf-lanb" "qbf-wanb" "qbf-tunb" "l3-lanb" "l3-wanb" "l3-tunb" "qve-phy-lanb" "qve-phy-wanb" "qve-phy-tunb" "qbi-lanb":
do
    sudo ip link set dev $nic down 
    sudo ip link del dev $nic  
done


# How to: Linux Iptables block common attacks
# http://www.cyberciti.biz/tips/linux-iptables-10-how-to-block-common-attack.html
#
# More on hashlimit
# http://www.iptables.info/en/iptables-matches.html#HASHLIMITMATCH
#
# TODO:
# 1. doREJECT traffic up to an upper threshold
# 2. Detect excess of traffic over the upper threshold
# 3. Create specific buckets per user with limit/hour and -j NFQUEUE for evidence collection
# 4. doREJECT the excess of traffic
# 5. Add CT zone for ingress interfaces

# Definition of variables
LAN_NIC="l3-lana"
WAN_NIC="l3-wana"
TUN_NIC="l3-tuna"

PHYSDEV_LAN_NIC="qve-phy-lana"
PHYSDEV_WAN_NIC="qve-phy-wana"
PHYSDEV_TUN_NIC="qve-phy-tuna"

PHYSDEV_LAN_NIC_pair="qvi-phy-lana"
PHYSDEV_WAN_NIC_pair="qvi-phy-wana"
PHYSDEV_TUN_NIC_pair="qvi-phy-tuna"

LAN_NET="192.168.0.0/24"
CPOOL_NET="198.18.0.21/32 198.18.0.22/32 198.18.0.23/32"
PROXY_NET="172.16.0.0/24"


SPOOF_IPS="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"


# Packet marks per interface
hMARK_EGRESS_to_CES="0x4"       #0b00100
hMARK_EGRESS_to_WAN="0x6"       #0b00110
hMARK_EGRESS_to_PROXY="0x7"     #0b00111
hMARK_INGRESS_from_CES="0x18"   #0b11000
hMARK_INGRESS_from_WAN="0x19"   #0b11001
hMARK_INGRESS_from_PROXY="0x1d" #0b11101
hMARK_MASK="0x10"               #0b10000
hMARK_EGRESS_MASK="0x00"        #0b00000
hMARK_INGRESS_MASK="0x10"       #0b10000


# Build ARP Responder with ebtables
CPOOL_MAC="00:00:00:00:01:bb"
ebtables -t nat -F
for ip in $CPOOL_NET
do
    ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $CPOOL_MAC --arpreply-target ACCEPT
done


# Create table
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset #Some people prefer icmp-port-unreachable
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# DEFINITION OF FILTERING POLICIES TO PROTECT FROM ATTACKS
iptables -N QBR_FILTER
iptables -F QBR_FILTER


# Configure raw PREROUTING for specific conntrack zones
## Note: Use conntrack zone 1 for default connection track and zones 2/3/4 for packet filtering via qbf filtering bridges

# Definition of CONNTRACK ZONES
iptables -t raw -N CT_ZONES
iptables -t raw -F CT_ZONES
# Set Zone-1 for L3-routing interfaces
iptables -t raw -A CT_ZONES -i $LAN_NIC -j CT --zone 1
iptables -t raw -A CT_ZONES -i $WAN_NIC -j CT --zone 1
iptables -t raw -A CT_ZONES -i $TUN_NIC -j CT --zone 1
# Set Zone-2 for BridgeFiltering @WAN interface
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-l3-wana  -j CT --zone 2
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-phy-wana -j CT --zone 2
# Set Zone-3 for BridgeFiltering @LAN interface
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-l3-lana  -j CT --zone 3
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-phy-lana -j CT --zone 3
# Set Zone-4 for BridgeFiltering @TUN interface
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-l3-tuna  -j CT --zone 4
iptables -t raw -A CT_ZONES -m physdev --physdev-in qve-phy-tuna -j CT --zone 4
# Set notrack for everything else
iptables -t raw -A CT_ZONES -j CT --notrack

# Definition of PACKET MARK ZONES
iptables -t raw -N PKT_ZONES
iptables -t raw -F PKT_ZONES
# Set Zone-1 for L3-routing interfaces
iptables -t raw -A PKT_ZONES -i $LAN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-lan"
iptables -t raw -A PKT_ZONES -i $WAN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-wan"
iptables -t raw -A PKT_ZONES -i $TUN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-tun"
# Set Zone-2 for BridgeFiltering @WAN interface
## Restore the CONNMARK if the packet was mangled by the TCP Splicer
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-phy-wana -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-l3-wana  -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
# Set MARK if no CONNMARK was set
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-phy-wana -m mark --mark 0x00 -j MARK --set-mark 0x20000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-wan"
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-l3-wana  -m mark --mark 0x00 -j MARK --set-mark 0x21000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-wan"
# Set Zone-3 for BridgeFiltering @LAN interface
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-phy-lana -j MARK --set-mark 0x30000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-lan"
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-l3-lana  -j MARK --set-mark 0x31000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-lan"
# Set Zone-4 for BridgeFiltering @TUN interface
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-phy-tuna -j MARK --set-mark 0x40000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-tun"
iptables -t raw -A PKT_ZONES -m physdev --physdev-in qve-l3-tuna  -j MARK --set-mark 0x41000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-tun"


# Flush PREROUTING chain in RAW table
iptables -t raw -F PREROUTING
#NOTRACK loopback traffic
iptables -t raw -A PREROUTING -i lo -j NOTRACK
iptables -t raw -A OUTPUT -o lo -j NOTRACK

# Jump to CT_ZONES and set appropriate conntrack zone
iptables -t raw -A PREROUTING -j CT_ZONES
# Jump to PKT_ZONES and set packet mark according to zone
iptables -t raw -A PREROUTING -j PKT_ZONES

iptables -t raw -A PREROUTING -m mark ! --mark 0x00000000/0xFF000000 -j TRACE

#
#iptables -t raw -A PREROUTING -i lo -j NOTRACK
#iptables -t raw -A OUTPUT -o lo -j NOTRACK

#iptables -t raw -A PREROUTING -j TRACE
#iptables -t raw -A PREROUTING -j ACCEPT


# Testing TCP Splice function attached to QBF-WAN filtering bridge
iptables -t mangle -F PREROUTING
# LOG netfilter application
#iptables -t mangle -A PREROUTING -m mark --mark 0x22 -j LOG --log-level 7 --log-prefix "1.0.0.NFQUEUE "                   -m comment --comment "Before TEE"
#iptables -t mangle -A PREROUTING -m mark --mark 0x22 -j TEE --gateway 198.18.0.101 --oif qve-phy-wana
#iptables -t mangle -A PREROUTING -m mark --mark 0x22 -j LOG --log-level 7 --log-prefix "1.0.1.NFQUEUE "                   -m comment --comment "After TEE"

#iptables -t mangle -A PREROUTING -m mark --mark 0x02 -j LOG --log-level 7 --log-prefix "1.1.NFQUEUE "                   -m comment --comment "Before NFQUEUE"
#Forward Circular Pool connections to TCP Splice
iptables -t mangle -A PREROUTING -m mark --mark 0x02 -d 198.18.0.21 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 1 -m comment --comment "Do NFQUEUE"
#iptables -t mangle -A PREROUTING -m mark --mark 0x02 -j LOG --log-level 7 --log-prefix "1.2. !NEW "                     -m comment --comment "After NFQUEUE"


# Testing TCP Splice function attached to QBF-WAN filtering bridge
iptables -t nat -F PREROUTING
# LOG netfilter application
#iptables -t nat -A PREROUTING -m mark --mark 0x01 -j LOG --log-level 7 --log-prefix "2.1.DNAT "                         -m comment --comment "Before DNAT"
# Do DNAT towards private host
iptables -t nat -A PREROUTING -m mark --mark 0x01 -d 198.18.0.21 -j DNAT --to-destination 192.168.0.101                 -m comment --comment "Do DNAT"

# Mark 222 means the TCP Splice has received the last ACK of the 3-way handsake. We should create connmark
iptables -t nat -A PREROUTING -m mark --mark 0x222/0xFFF -j LOG --log-level 7 --log-prefix "should match here "
iptables -t nat -A PREROUTING -m mark --mark 0x222/0xFFF -j CONNMARK --save-mark

iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "########### "
iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "### END ### "
iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "########### "


## Packet processing for Circular Pool
### Note: We can rate limit the number of packets that are sent to the Control Plane to prevent DoS
iptables -t mangle -A PREROUTING -m physdev --physdev-is-in -j ACCEPT
iptables -t mangle -A PREROUTING -i $WAN_NIC -j CONNMARK --restore-mark
iptables -t mangle -A PREROUTING -i $LAN_NIC -j CONNMARK --restore-mark

for ip in $CPOOL_NET
do
    iptables -t mangle -A PREROUTING -i $WAN_NIC -d $ip -m mark --mark 0x00 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 10 -m comment --comment "New connection to Circular Pool $ip"
done

### Note: Create new chain in nat table for Circular Pool connections and DNAT target with NEW conntrack state
iptables -t nat -N CIRCULAR_POOL
iptables -t nat -A PREROUTING -m mark ! --mark 0xFFFFFFFE -i $WAN_NIC -j CIRCULAR_POOL -m comment --comment "Continue to Circular Pool DNAT chain"
### Add rule per private host for DNAT operation
iptables -t nat -A CIRCULAR_POOL -m mark --mark 0xC0A80065 -i $WAN_NIC -j DNAT --to-destination 192.168.0.101 -m comment --comment "Forward to 192.168.0.101"


## Packet clasification with mark in MANGLE table only in l3-routed interfaces
iptables -t mangle -A FORWARD -m physdev --physdev-is-in -j ACCEPT -m comment --comment "Traffic from bridged interface"
### LAN & WAN
iptables -t mangle -A FORWARD -i $LAN_NIC -o $WAN_NIC -j MARK --set-mark $hMARK_EGRESS_to_WAN    -m comment --comment "Egress LAN to WAN"
iptables -t mangle -A FORWARD -i $WAN_NIC -o $LAN_NIC -j MARK --set-mark $hMARK_INGRESS_from_WAN -m comment --comment "Ingress WAN to LAN"
### LAN & CES
iptables -t mangle -A FORWARD -i $LAN_NIC -o $TUN_NIC -j MARK --set-mark $hMARK_EGRESS_to_TUN    -m comment --comment "Egress LAN to TUN"
iptables -t mangle -A FORWARD -i $TUN_NIC -o $LAN_NIC -j MARK --set-mark $hMARK_INGRESS_from_TUN -m comment --comment "Ingress TUN to LAN"
### LAN & WAN via CES input
iptables -t mangle -A INPUT   -i $LAN_NIC             -j MARK --set-mark $hMARK_EGRESS_to_CES    -m comment --comment "Egress LAN to CES"
iptables -t mangle -A INPUT   -i $WAN_NIC             -j MARK --set-mark $hMARK_INGRESS_to_CES   -m comment --comment "Ingress WAN to CES"
iptables -t mangle -A INPUT   -i $TUN_NIC             -j DROP                                    -m comment --comment "Drop incoming traffic from TUN"


# Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
# http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged ! -s $LAN_NET   -j DROP -m comment --comment "[E] IP Spoofing"
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged ! -s $PROXY_NET -j DROP -m comment --comment "[I] IP Spoofing"
## Drop other spoofed traffic
for ip in $SPOOF_IPS
do
    iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -s $ip -j DROP -m comment --comment "[I] IP Spoofing"
done

# Forward traffic specific chain
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from LAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from WAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from TUN bridge interface" -j ACCEPT

# Apply filtering only in qbf interfaces
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER

# Set last rule to accept
sudo iptables -A FORWARD -m physdev --physdev-is-in -m comment --comment "Traffic from other bridge interface" -j ACCEPT

iptables -N SOME_POLICY

## CES LOCAL PROCESS (INPUT chain)
iptables -A INPUT -m mark ! --mark 0x00 -j SOME_POLICY  
iptables -A INPUT -j ACCEPT                             

## CES FORWARDING PROCESS (FORWARD chain)
iptables -A FORWARD -m mark ! --mark 0x00 -j SOME_POLICY
iptables -A FORWARD -j ACCEPT   


## Enable NAT
#iptables -t nat -A POSTROUTING -m physdev --physdev-is-bridged  -j ACCEPT -m comment --comment "Traffic from bridged interface"
#iptables -t nat -F
iptables -t nat -I POSTROUTING -o lo -j ACCEPT
iptables -t nat -I POSTROUTING -o eth0 -j ACCEPT
iptables -t nat -I POSTROUTING -o eth1 -j ACCEPT

iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "nat.POSTROUTING:"
#iptables -t nat -A POSTROUTING -m mark   --mark 0x00 -j LOG --log-level 7 --log-prefix "nat.POST: mark==0 "
iptables -t nat -A POSTROUTING -m mark --mark $hMARK_EGRESS_to_WAN -s $LAN_NET -j SNAT --to-source 198.18.0.11 -m comment --comment "Outgoing SNAT to 198.18.0.11"

