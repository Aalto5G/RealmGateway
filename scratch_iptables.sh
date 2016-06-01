
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
LAN_L3="l3-lana"
WAN_L3="l3-wana"
TUN_L3="l3-tuna"

QBF_LAN_L3="qve-l3-lana"
QBF_WAN_L3="qve-l3-wana"
QBF_TUN_L3="qve-l3-tuna"

QBF_LAN_L2="qve-phy-lana"
QBF_WAN_L2="qve-phy-wana"
QBF_TUN_L2="qve-phy-tuna"

QBF_LAN_BR="qbf-lana"
QBF_WAN_BR="qbf-wana"
QBF_TUN_BR="qbf-tuna"

QBF_PREFIX="qbf-+"
L3_PREFIX="l3-+"

#QBF_LAN_L2_pair="qvi-phy-lana"
#QBF_WAN_L2_pair="qvi-phy-wana"
#QBF_TUN_L2_pair="qvi-phy-tuna"

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


#################################### EBTABLES #################################

# Build ARP Responder with ebtables
CPOOL_MAC="00:00:00:00:01:bb"
ebtables -t nat -F
for ip in $CPOOL_NET
do
    ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $CPOOL_MAC --arpreply-target ACCEPT
done


#################################### IPTABLES #################################
# Note: Use conntrack zone 1 for default connection track and zones 2/3/4 for packet filtering via qbf filtering bridges

# Build ipset for the addresses of the Circular Pool
ipset create circularpool_set hash:ip
for ip in $CPOOL_NET
do
    ipset add circularpool_set $ip
done


# --- RAW TABLE ---  #

# Definition of chains for RAW PREROUTING table
iptables -t raw -N RAW_PRE_QBF
iptables -t raw -F RAW_PRE_QBF
iptables -t raw -N RAW_PRE_L3
iptables -t raw -F RAW_PRE_L3

# Populate custom chains of RAW PREROUTING table
# Set Zone-1 and packet mark for Layer-3 routing interfaces
iptables -t raw -A RAW_PRE_L3 -i $WAN_L3 -j CT --zone 1                           -m comment --comment "[l3-wan] CT zone"
iptables -t raw -A RAW_PRE_L3 -i $WAN_L3 -j MARK --set-mark 0x12000000/0xFF000000 -m comment --comment "[l3-wan] inbound MARK"
iptables -t raw -A RAW_PRE_L3 -i $WAN_L3 -j ACCEPT
iptables -t raw -A RAW_PRE_L3 -i $LAN_L3 -j CT --zone 1                           -m comment --comment "[l3-lan] CT zone"
iptables -t raw -A RAW_PRE_L3 -i $LAN_L3 -j MARK --set-mark 0x13000000/0xFF000000 -m comment --comment "[l3-lan] inbound MARK"
iptables -t raw -A RAW_PRE_L3 -i $LAN_L3 -j ACCEPT
iptables -t raw -A RAW_PRE_L3 -i $TUN_L3 -j CT --zone 1                           -m comment --comment "[l3-tun] CT zone"
iptables -t raw -A RAW_PRE_L3 -i $TUN_L3 -j MARK --set-mark 0x14000000/0xFF000000 -m comment --comment "[l3-tun] inbound MARK"
iptables -t raw -A RAW_PRE_L3 -i $TUN_L3 -j ACCEPT

# Set Zone-2 and packet mark for Linux bridge filtering interface @QBF-WAN and restore the CONNMARK if the packet was mangled by the TCP Splicer
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L2 -j CONNMARK --restore-mark -m comment --comment "[qbf-wan] Restore inbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L2 -j LOG --log-level 7
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L3 -j CONNMARK --restore-mark -m comment --comment "[qbf-wan] Restore outbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L3 -j LOG --log-level 7
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L2 -j CT --zone 2                           -m comment --comment "[qbf-wan] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L2 -j MARK --set-mark 0x20000000/0xFF000000 -m comment --comment "[qbf-wan] inbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L2 -j ACCEPT
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L3 -j CT --zone 2                           -m comment --comment "[qbf-wan] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L3 -j MARK --set-mark 0x21000000/0xFF000000 -m comment --comment "[qbf-wan] outbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_WAN_L3 -j ACCEPT
# Set Zone-3 and packet mark for Linux bridge filtering interface @QBF-LAN
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L2 -j CT --zone 3                           -m comment --comment "[qbf-lan] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L2 -j MARK --set-mark 0x30000000/0xFF000000 -m comment --comment "[qbf-lan] inbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L2 -j ACCEPT
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L3 -j CT --zone 3                           -m comment --comment "[qbf-lan] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L3 -j MARK --set-mark 0x31000000/0xFF000000 -m comment --comment "[qbf-lan] outbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_LAN_L3 -j ACCEPT
# Set Zone-4 and packet mark for Linux bridge filtering interface @QBF-TUN
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L2 -j CT --zone 4                           -m comment --comment "[qbf-tun] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L2 -j MARK --set-mark 0x40000000/0xFF000000 -m comment --comment "[qbf-tun] inbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L2 -j ACCEPT
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L3 -j CT --zone 4                           -m comment --comment "[qbf-tun] CT zone"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L3 -j MARK --set-mark 0x41000000/0xFF000000 -m comment --comment "[qbf-tun] outbound MARK"
iptables -t raw -A RAW_PRE_QBF -m physdev --physdev-in $QBF_TUN_L3 -j ACCEPT


# Flush PREROUTING & OUTPUT chains of RAW table
iptables -t raw -F PREROUTING
iptables -t raw -F OUTPUT
## Jump to RAW_PRE_xyz chain to set conntrack zone and packet mark
iptables -t raw -A PREROUTING -i $QBF_PREFIX -j RAW_PRE_QBF
iptables -t raw -A PREROUTING -i $L3_PREFIX  -j RAW_PRE_L3
## NOTRACK rest of traffic
iptables -t raw -A PREROUTING -j NOTRACK
iptables -t raw -A OUTPUT     -j NOTRACK

## Trace traffic for debugging
#iptables -t raw -A PREROUTING -m mark ! --mark 0x00000000/0xFF000000 -j TRACE
#iptables -t raw -I PREROUTING -i qbf-+ -j TRACE
#iptables -t raw -I PREROUTING -i l3-+  -j TRACE
#Alternatively
iptables -t raw -I PREROUTING -i $QBF_PREFIX -j LOG --log-level 7 --log-prefix "RAW.PRE "
iptables -t raw -I PREROUTING -i $L3_PREFIX  -j LOG --log-level 7 --log-prefix "RAW.PRE "


# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE PREROUTING table
iptables -t mangle -N MANGLE_PRE_QBF
iptables -t mangle -F MANGLE_PRE_QBF
iptables -t mangle -N MANGLE_PRE_L3
iptables -t mangle -F MANGLE_PRE_L3

# Populate custom chains of MANGLE PREROUTING table
## Match only incoming connections in l3-wan for processing in Circular Pool
iptables -t mangle -A MANGLE_PRE_L3 -m mark --mark 0x12000000/0xFF000000 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j NFQUEUE --queue-num 2 -m comment --comment "Process in Circular Pool"
iptables -t mangle -A MANGLE_PRE_L3 -j ACCEPT
## EXPERIMENTAL: Match packets in qbf-wan (both directions) - Testing TCP Splice function attached to QBF-WAN filtering bridge
#iptables -t mangle -A MANGLE_PRE_QBF -m mark --mark 0x20000000/0xFF000000 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j LOG --log-level 7 --log-prefix "MANGLE.PRE.L2 Splice in"
#iptables -t mangle -A MANGLE_PRE_QBF -m mark --mark 0x20000000/0xFF000000 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j NFQUEUE --queue-num 1 -m comment --comment "To TCPSplice in"
#iptables -t mangle -A MANGLE_PRE_QBF -m mark --mark 0x21000001/0xFF00000F -m set --match-set circularpool_set src                            -j LOG --log-level 7 --log-prefix "MANGLE.PRE.L2 Splice out"
#iptables -t mangle -A MANGLE_PRE_QBF -m mark --mark 0x21000001/0xFF00000F -m set --match-set circularpool_set src                            -j NFQUEUE --queue-num 1 -m comment --comment "To TCPSplice out"
#iptables -t mangle -A MANGLE_PRE_QBF -j ACCEPT

# Flush PREROUTING chain of MANGLE table
iptables -t mangle -F PREROUTING
## Jump to MANGLE_PRE_xyz chains
iptables -t mangle -A PREROUTING -i $QBF_PREFIX -j MANGLE_PRE_QBF
iptables -t mangle -A PREROUTING -i $L3_PREFIX  -j MANGLE_PRE_L3

## Trace traffic for debugging
iptables -t mangle -I PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.PRE "



# --- NAT TABLE ---  #

# Definition of chains for MANGLE PREROUTING table
iptables -t nat -N NAT_PRE_QBF
iptables -t nat -F NAT_PRE_QBF
iptables -t nat -N NAT_PRE_L3
iptables -t nat -F NAT_PRE_L3
iptables -t nat -N NAT_PRE_L3_CPOOL
iptables -t nat -F NAT_PRE_L3_CPOOL


# Populate custom chains of MANGLE PREROUTING table
# Match only incoming connections @L3-WAN that have been processed by the Control Plane via NFQUEUE
iptables -t nat -A NAT_PRE_L3 -m mark ! --mark 0x12000000/0xFFFFFFFF -m set --match-set circularpool_set dst -j NAT_PRE_L3_CPOOL -m comment --comment "DNAT CircularPool"
iptables -t nat -A NAT_PRE_L3 -j ACCEPT
## Do DNAT towards private host @L3-WAN - Add 1 rule per private host
iptables -t nat -A NAT_PRE_L3_CPOOL -j LOG --log-level 7 --log-prefix "NAT.PRE.L3.CPOOL DNAT " -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_L3_CPOOL -m mark --mark 0x00A80065/0x00FFFFFF -j DNAT --to-destination 192.168.0.101 -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_L3_CPOOL -m mark --mark 0x00A80066/0x00FFFFFF -j DNAT --to-destination 192.168.0.102 -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_L3_CPOOL -m mark --mark 0x00A80067/0x00FFFFFF -j DNAT --to-destination 192.168.0.103 -m comment --comment "DNAT to private host"
## EXPERIMENTAL: Match packets in qbf-wan (both directions) - Testing TCP Splice function attached to QBF-WAN filtering bridge
#iptables -t nat -A NAT_PRE_QBF -m mark --mark 0x20000001/0xFF00000F -j LOG --log-level 7 --log-prefix "NAT.PRE.WAN.L2 save-mark IN "
#iptables -t nat -A NAT_PRE_QBF -m mark --mark 0x20000001/0xFF00000F -j CONNMARK --save-mark

# Flush PREROUTING chain of NAT table
iptables -t nat -F PREROUTING
## Jump to NAT_PRE_xyz chains
iptables -t nat -A PREROUTING -i $QBF_PREFIX -j NAT_PRE_QBF
iptables -t nat -A PREROUTING -i $L3_PREFIX  -j NAT_PRE_L3

## Trace traffic for debugging
iptables -t nat -I PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "NAT.PRE "



# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE FORWARD table
iptables -t mangle -N MANGLE_FWD_QBF
iptables -t mangle -F MANGLE_FWD_QBF
iptables -t mangle -N MANGLE_FWD_L3
iptables -t mangle -F MANGLE_FWD_L3


# Populate custom chains of MANGLE FORWARD table
# Match forwarded traffic at Layer-3 interfaces and set directionality
iptables -t mangle -A MANGLE_FWD_L3 -m mark --mark 0x12000000/0xFF000000 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_WAN/0x000000FF -m comment --comment "Ingress WAN to LAN"
iptables -t mangle -A MANGLE_FWD_L3 -m mark --mark 0x13000000/0xFF000000 -o $WAN_L3 -j MARK --set-mark $hMARK_EGRESS_to_WAN/0x000000FF    -m comment --comment "Egress LAN to WAN"
iptables -t mangle -A MANGLE_FWD_L3 -m mark --mark 0x13000000/0xFF000000 -o $TUN_L3 -j MARK --set-mark $hMARK_EGRESS_to_TUN/0x000000FF    -m comment --comment "Egress LAN to TUN"
iptables -t mangle -A MANGLE_FWD_L3 -m mark --mark 0x14000000/0xFF000000 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_TUN/0x000000FF -m comment --comment "Ingress TUN to LAN"


# Flush FORWARD chain of MANGLE table
iptables -t mangle -F FORWARD
## Jump to MANGLE_FWD_xyz chains
iptables -t mangle -A FORWARD -i $QBF_PREFIX -j MANGLE_FWD_QBF
iptables -t mangle -A FORWARD -i $L3_PREFIX  -j MANGLE_FWD_L3

## Trace traffic for debugging
iptables -t mangle -I FORWARD -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.FWD "


# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE INPUT table
iptables -t mangle -N MANGLE_INPUT_L3
iptables -t mangle -F MANGLE_INPUT_L3


# Populate custom chains of MANGLE INPUT table
# Match input traffic at Layer-3 interfaces and set directionality
iptables -t mangle -A MANGLE_INPUT_L3 -m mark --mark 0x12000000/0xFF000000 -j MARK --set-mark $hMARK_INGRESS_to_CES/0x000000FF -m comment --comment "Ingress WAN to CES"
iptables -t mangle -A MANGLE_INPUT_L3 -m mark --mark 0x13000000/0xFF000000 -j MARK --set-mark $hMARK_EGRESS_to_CES/0x000000FF  -m comment --comment "Egress LAN to CES"
iptables -t mangle -A MANGLE_INPUT_L3 -m mark --mark 0x14000000/0xFF000000 -j MARK --set-mark $hMARK_EGRESS_to_CES/0x000000FF -m comment --comment "Ingress TUN to CES"


# Flush INPUT chain of MANGLE table
iptables -t mangle -F INPUT
## Jump to MANGLE_FWD_xyz chains
iptables -t mangle -A INPUT -i $L3_PREFIX  -j MANGLE_INPUT_L3

## Trace traffic for debugging
iptables -t mangle -I FORWARD -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.FWD "



# Create rules for FORWARDED traffic - Mark packet according to traffic direction for later filtering
iptables -t mangle -F FORWARD

# Create chains in MANGLE table for packet processing at L3 and QBF interfaces
# NIC: l3-wan
iptables -t mangle -N MANGLE_FWD_WAN_L3
iptables -t mangle -F MANGLE_FWD_WAN_L3
iptables -t mangle -A MANGLE_FWD_WAN_L3 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_WAN/0x000000FF -m comment --comment "Ingress WAN to LAN"
iptables -t mangle -A MANGLE_FWD_WAN_L3 -j ACCEPT
# NIC: qbf-wan (both directions)
iptables -t mangle -N MANGLE_FWD_WAN_L2
iptables -t mangle -F MANGLE_FWD_WAN_L2
iptables -t mangle -A MANGLE_FWD_WAN_L2 -j ACCEPT
# NIC: l3-lan
iptables -t mangle -N MANGLE_FWD_LAN_L3
iptables -t mangle -F MANGLE_FWD_LAN_L3
iptables -t mangle -A MANGLE_FWD_LAN_L3 -o $WAN_L3 -j MARK --set-mark $hMARK_EGRESS_to_WAN/0x000000FF    -m comment --comment "Egress LAN to WAN"
iptables -t mangle -A MANGLE_FWD_LAN_L3 -o $TUN_L3 -j MARK --set-mark $hMARK_EGRESS_to_TUN/0x000000FF    -m comment --comment "Egress LAN to TUN"

iptables -t mangle -A MANGLE_FWD_LAN_L3 -j ACCEPT
# NIC: qbf-lan (both directions)
iptables -t mangle -N MANGLE_FWD_LAN_L2
iptables -t mangle -F MANGLE_FWD_LAN_L2
iptables -t mangle -A MANGLE_FWD_LAN_L2 -j ACCEPT
# NIC: l3-tun
iptables -t mangle -N MANGLE_FWD_TUN_L3
iptables -t mangle -F MANGLE_FWD_TUN_L3
iptables -t mangle -A MANGLE_FWD_TUN_L3 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_TUN/0x000000FF -m comment --comment "Ingress TUN to LAN"
iptables -t mangle -A MANGLE_FWD_TUN_L3 -j ACCEPT
# NIC: qbf-tun (both directions)
iptables -t mangle -N MANGLE_FWD_TUN_L2
iptables -t mangle -F MANGLE_FWD_TUN_L2
iptables -t mangle -A MANGLE_FWD_TUN_L2 -j ACCEPT

# Add flows to main chain in MANGLE table
iptables -t mangle -A FORWARD -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.PRE "
iptables -t mangle -A FORWARD -m mark --mark 0x12000000/0xFF000000 -j MANGLE_FWD_WAN_L3
iptables -t mangle -A FORWARD -m mark --mark 0x13000000/0xFF000000 -j MANGLE_FWD_LAN_L3
iptables -t mangle -A FORWARD -m mark --mark 0x14000000/0xFF000000 -j MANGLE_FWD_TUN_L3
iptables -t mangle -A FORWARD -m mark --mark 0x20000000/0xF0000000 -j MANGLE_FWD_WAN_L2
iptables -t mangle -A FORWARD -m mark --mark 0x30000000/0xF0000000 -j MANGLE_FWD_LAN_L2
iptables -t mangle -A FORWARD -m mark --mark 0x40000000/0xF0000000 -j MANGLE_FWD_TUN_L2


# Create rules for INPUT traffic - Mark packet according to traffic direction for later filtering
iptables -t mangle -F INPUT

# Create chains in MANGLE table for packet processing at L3 and QBF interfaces
# NIC: l3-wan
iptables -t mangle -N MANGLE_INPUT_WAN_L3
iptables -t mangle -F MANGLE_INPUT_WAN_L3
iptables -t mangle -A MANGLE_INPUT_WAN_L3 -j MARK --set-mark $hMARK_INGRESS_to_CES/0x000000FF -m comment --comment "Ingress WAN to CES"
iptables -t mangle -A MANGLE_INPUT_WAN_L3 -j ACCEPT
# NIC: l3-lan
iptables -t mangle -N MANGLE_INPUT_LAN_L3
iptables -t mangle -F MANGLE_INPUT_LAN_L3
iptables -t mangle -A MANGLE_INPUT_LAN_L3 -j MARK --set-mark $hMARK_EGRESS_to_CES/0x000000FF  -m comment --comment "Egress LAN to CES"
iptables -t mangle -A MANGLE_INPUT_LAN_L3 -j ACCEPT
# NIC: l3-tun
iptables -t mangle -N MANGLE_INPUT_TUN_L3
iptables -t mangle -F MANGLE_INPUT_TUN_L3
iptables -t mangle -A MANGLE_INPUT_TUN_L3 -j DROP
#iptables -t mangle -A MANGLE_INPUT_TUN_L3 -j ACCEPT

# Add flows to main chain in MANGLE table
iptables -t mangle -A INPUT -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.INPUT "
iptables -t mangle -A INPUT -m mark --mark 0x12000000/0xFF000000 -j MANGLE_INPUT_WAN_L3
iptables -t mangle -A INPUT -m mark --mark 0x13000000/0xFF000000 -j MANGLE_INPUT_LAN_L3
iptables -t mangle -A INPUT -m mark --mark 0x14000000/0xFF000000 -j MANGLE_INPUT_TUN_L3





# LOG FOR EASY READING
iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "######### END ######### "



# PACKET MARKS FOR MATCHING
iptables -t mangle -A PREROUTING -m mark --mark 0x12000000/0xFF000000 -j MANGLE_PRE_WAN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x13000000/0xFF000000 -j MANGLE_PRE_LAN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x14000000/0xFF000000 -j MANGLE_PRE_TUN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x20000000/0xF0000000 -j MANGLE_PRE_WAN_L2
iptables -t mangle -A PREROUTING -m mark --mark 0x30000000/0xF0000000 -j MANGLE_PRE_LAN_L2
iptables -t mangle -A PREROUTING -m mark --mark 0x40000000/0xF0000000 -j MANGLE_PRE_TUN_L2


# Create table
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset #Some people prefer icmp-port-unreachable
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# DEFINITION OF FILTERING POLICIES TO PROTECT FROM ATTACKS
iptables -N QBR_FILTER
iptables -F QBR_FILTER



# Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
# http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -A QBR_FILTER -m physdev --physdev-in $QBF_LAN_L2 --physdev-is-bridged ! -s $LAN_NET   -j DROP -m comment --comment "[E] IP Spoofing"
iptables -A QBR_FILTER -m physdev --physdev-in $QBF_TUN_L2 --physdev-is-bridged ! -s $PROXY_NET -j DROP -m comment --comment "[I] IP Spoofing"
## Drop other spoofed traffic
for ip in $SPOOF_IPS
do
    iptables -A QBR_FILTER -m physdev --physdev-in $QBF_WAN_L2 --physdev-is-bridged -s $ip -j DROP -m comment --comment "[I] IP Spoofing"
done

# Forward traffic specific chain
sudo iptables -A QBR_FILTER -m physdev --physdev-in $QBF_LAN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from LAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $QBF_WAN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from WAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $QBF_TUN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from TUN bridge interface" -j ACCEPT

# Apply filtering only in qbf interfaces
sudo iptables -A FORWARD -m physdev --physdev-in $QBF_LAN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $QBF_WAN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $QBF_TUN_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER

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




###############################################################################
# Configure raw PREROUTING for specific conntrack zones
## Note: Use conntrack zone 1 for default connection track and zones 2/3/4 for packet filtering via qbf filtering bridges

## Definition of CONNTRACK ZONES
#iptables -t raw -N CT_ZONES
#iptables -t raw -F CT_ZONES
## Set Zone-1 for L3-routing interfaces
#iptables -t raw -A CT_ZONES -i $LAN_L3 -j CT --zone 1
#iptables -t raw -A CT_ZONES -i $WAN_L3 -j CT --zone 1
#iptables -t raw -A CT_ZONES -i $TUN_L3 -j CT --zone 1
## Set Zone-2 for BridgeFiltering @WAN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_WAN_L3  -j CT --zone 2
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_WAN_L2 -j CT --zone 2
## Set Zone-3 for BridgeFiltering @LAN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_LAN_L3  -j CT --zone 3
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_LAN_L2 -j CT --zone 3
## Set Zone-4 for BridgeFiltering @TUN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_TUN_L3  -j CT --zone 4
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $QBF_TUN_L2 -j CT --zone 4
## Set notrack for everything else
#iptables -t raw -A CT_ZONES -j CT --notrack
#
## Definition of PACKET MARK ZONES
#iptables -t raw -N PKT_ZONES
#iptables -t raw -F PKT_ZONES
## Set Zone-1 for L3-routing interfaces
#iptables -t raw -A PKT_ZONES -i $LAN_L3 -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-lan"
#iptables -t raw -A PKT_ZONES -i $WAN_L3 -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-wan"
#iptables -t raw -A PKT_ZONES -i $TUN_L3 -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-tun"
## Set Zone-2 for BridgeFiltering @WAN interface
### Restore the CONNMARK if the packet was mangled by the TCP Splicer
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_WAN_L2 -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_WAN_L3  -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
## Set MARK if no CONNMARK was set
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_WAN_L2 -m mark --mark 0x00 -j MARK --set-mark 0x20000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-wan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_WAN_L3  -m mark --mark 0x00 -j MARK --set-mark 0x21000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-wan"
## Set Zone-3 for BridgeFiltering @LAN interface
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_LAN_L2 -j MARK --set-mark 0x30000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-lan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_LAN_L3  -j MARK --set-mark 0x31000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-lan"
## Set Zone-4 for BridgeFiltering @TUN interface
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_TUN_L2 -j MARK --set-mark 0x40000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-tun"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $QBF_TUN_L3  -j MARK --set-mark 0x41000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-tun"


# Flush PREROUTING chain in RAW table
#iptables -t raw -F PREROUTING
# Jump to CT_ZONES and set appropriate conntrack zone
#iptables -t raw -A PREROUTING -j CT_ZONES
# Jump to PKT_ZONES and set packet mark according to zone
#iptables -t raw -A PREROUTING -j PKT_ZONES




#iptables -t mangle -F FORWARD
#iptables -t mangle -F INPUT
## Packet clasification with mark in MANGLE table only for L3-routing interfaces
#iptables -t mangle -A FORWARD -m physdev --physdev-is-in -j ACCEPT -m comment --comment "Traffic from QBF"
#### LAN & WAN
#iptables -t mangle -A FORWARD -i $LAN_L3 -o $WAN_L3 -j MARK --set-mark $hMARK_EGRESS_to_WAN/0x000000FF    -m comment --comment "Egress LAN to WAN"
#iptables -t mangle -A FORWARD -i $WAN_L3 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_WAN/0x000000FF -m comment --comment "Ingress WAN to LAN"
#### LAN & TUN
#iptables -t mangle -A FORWARD -i $LAN_L3 -o $TUN_L3 -j MARK --set-mark $hMARK_EGRESS_to_TUN/0x000000FF    -m comment --comment "Egress LAN to TUN"
#iptables -t mangle -A FORWARD -i $TUN_L3 -o $LAN_L3 -j MARK --set-mark $hMARK_INGRESS_from_TUN/0x000000FF -m comment --comment "Ingress TUN to LAN"
#### LAN & WAN to CES Local
#iptables -t mangle -A INPUT   -i $LAN_L3             -j MARK --set-mark $hMARK_EGRESS_to_CES/0x000000FF    -m comment --comment "Egress LAN to CES"
#iptables -t mangle -A INPUT   -i $WAN_L3             -j MARK --set-mark $hMARK_INGRESS_to_CES/0x000000FF   -m comment --comment "Ingress WAN to CES"
#iptables -t mangle -A INPUT   -i $TUN_L3             -j DROP                                               -m comment --comment "Ingress TUN to CES"


## Packet processing for Circular Pool
### Note: We can rate limit the number of packets that are sent to the Control Plane to prevent DoS
#iptables -t mangle -A PREROUTING -m physdev --physdev-is-in -j ACCEPT
#iptables -t mangle -A PREROUTING -i $WAN_L3 -j CONNMARK --restore-mark
#iptables -t mangle -A PREROUTING -i $LAN_L3 -j CONNMARK --restore-mark


