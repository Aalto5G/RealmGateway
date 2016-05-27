
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

PHYSDEV_LAN_NIC_L3="qve-l3-lana"
PHYSDEV_WAN_NIC_L3="qve-l3-wana"
PHYSDEV_TUN_NIC_L3="qve-l3-tuna"

PHYSDEV_LAN_NIC_L2="qve-phy-lana"
PHYSDEV_WAN_NIC_L2="qve-phy-wana"
PHYSDEV_TUN_NIC_L2="qve-phy-tuna"

PHYSDEV_LAN_NIC_BR="qbf-lana"
PHYSDEV_WAN_NIC_BR="qbf-wana"
PHYSDEV_TUN_NIC_BR="qbf-tuna"

#PHYSDEV_LAN_NIC_L2_pair="qvi-phy-lana"
#PHYSDEV_WAN_NIC_L2_pair="qvi-phy-wana"
#PHYSDEV_TUN_NIC_L2_pair="qvi-phy-tuna"

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

# Definition of connection tracking zones and packet marks for Layer-3 routing interfaces
iptables -t raw -N RAW_CT_ZONES_MARK_L3
iptables -t raw -F RAW_CT_ZONES_MARK_L3
# Set Zone-1 and packet mark for Layer-3 routing interfaces
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $WAN_NIC -j CT --zone 1                           -m comment --comment "[l3-wan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $WAN_NIC -j MARK --set-mark 0x12000000/0xFF000000 -m comment --comment "[l3-wan] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $WAN_NIC -j ACCEPT
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $LAN_NIC -j CT --zone 1                           -m comment --comment "[l3-lan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $LAN_NIC -j MARK --set-mark 0x13000000/0xFF000000 -m comment --comment "[l3-lan] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $LAN_NIC -j ACCEPT
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $TUN_NIC -j CT --zone 1                           -m comment --comment "[l3-tun] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $TUN_NIC -j MARK --set-mark 0x14000000/0xFF000000 -m comment --comment "[l3-tun] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L3 -i $TUN_NIC -j ACCEPT

# Definition of connection tracking zones and packet marks for Linux filtering bridge interfaces
iptables -t raw -N RAW_CT_ZONES_MARK_L2
iptables -t raw -F RAW_CT_ZONES_MARK_L2
# Restore the CONNMARK if the packet was mangled by the TCP Splicer
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j CONNMARK --restore-mark -m comment --comment "[qbf-wan] Restore inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j LOG --log-level 7
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3 -j CONNMARK --restore-mark -m comment --comment "[qbf-wan] Restore outbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3 -j LOG --log-level 7
# Set Zone-2 and packet mark for Linux bridge filtering interface @QBF-WAN
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j CT --zone 2                           -m comment --comment "[qbf-wan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j MARK --set-mark 0x20000000/0xFF000000 -m comment --comment "[qbf-wan] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j ACCEPT
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3 -j CT --zone 2                           -m comment --comment "[qbf-wan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3 -j MARK --set-mark 0x21000000/0xFF000000 -m comment --comment "[qbf-wan] outbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3 -j ACCEPT
# Set Zone-3 and packet mark for Linux bridge filtering interface @QBF-LAN
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 -j CT --zone 3                           -m comment --comment "[qbf-lan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 -j MARK --set-mark 0x30000000/0xFF000000 -m comment --comment "[qbf-lan] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 -j ACCEPT
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L3 -j CT --zone 3                           -m comment --comment "[qbf-lan] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L3 -j MARK --set-mark 0x31000000/0xFF000000 -m comment --comment "[qbf-lan] outbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_LAN_NIC_L3 -j ACCEPT
# Set Zone-4 and packet mark for Linux bridge filtering interface @QBF-TUN
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 -j CT --zone 4                           -m comment --comment "[qbf-tun] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 -j MARK --set-mark 0x40000000/0xFF000000 -m comment --comment "[qbf-tun] inbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 -j ACCEPT
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L3 -j CT --zone 4                           -m comment --comment "[qbf-tun] CT zone"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L3 -j MARK --set-mark 0x41000000/0xFF000000 -m comment --comment "[qbf-tun] outbound MARK"
iptables -t raw -A RAW_CT_ZONES_MARK_L2 -m physdev --physdev-in $PHYSDEV_TUN_NIC_L3 -j ACCEPT



# Flush PREROUTING & OUTPUT chains of RAW table
iptables -t raw -F PREROUTING
iptables -t raw -F OUTPUT
# Populate PREROUTING chain of RAW table
## Jump to RAW_CT_ZONES_MARK_Lx to appropriate conntrack zone and packet mark
iptables -t raw -A PREROUTING -i qbf-+ -j RAW_CT_ZONES_MARK_L2
iptables -t raw -A PREROUTING -i l3-+  -j RAW_CT_ZONES_MARK_L3
## Note: Alternative way of matching incoming interface
#iptables -t raw -A PREROUTING -m physdev --physdev-in qve-+ -j RAW_CT_ZONES_MARK_L2


# NOTRACK loopback traffic
iptables -t raw -A PREROUTING -i lo -j NOTRACK
iptables -t raw -A OUTPUT     -o lo -j NOTRACK
# NOTRACK eth1 traffic
iptables -t raw -A PREROUTING -i eth1 -j NOTRACK
iptables -t raw -A OUTPUT     -o eth1 -j NOTRACK
# NOTRACK rest of incoming traffic
iptables -t raw -A PREROUTING -j NOTRACK

# Trace traffic for debugging
#iptables -t raw -A PREROUTING -m mark ! --mark 0x00000000/0xFF000000 -j TRACE
#iptables -t raw -I PREROUTING -i qbf-+ -j TRACE
#iptables -t raw -I PREROUTING -i l3-+  -j TRACE
#Alternatively
iptables -t raw -I PREROUTING -i qbf-+ -j LOG --log-level 7 --log-prefix "RAW.PRE "
iptables -t raw -I PREROUTING -i l3-+  -j LOG --log-level 7 --log-prefix "RAW.PRE "


# --- MANGLE TABLE ---  #

iptables -t mangle -F PREROUTING
# Create chains in MANGLE table for packet processing at L3 and QBF interfaces
# NIC: l3-wan - Packet processing for Circular Pool @L3-WAN
iptables -t mangle -N MANGLE_PRE_WAN_L3
iptables -t mangle -F MANGLE_PRE_WAN_L3
iptables -t mangle -A MANGLE_PRE_WAN_L3 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j NFQUEUE --queue-num 2 -m comment --comment "Process in Circular Pool"
iptables -t mangle -A MANGLE_PRE_WAN_L3 -j ACCEPT
# NIC: qbf-wan (both directions) - Testing TCP Splice function attached to QBF-WAN filtering bridge
iptables -t mangle -N MANGLE_PRE_WAN_L2
iptables -t mangle -F MANGLE_PRE_WAN_L2
# Send packets through the bridge - do not attempt splice
#iptables -t mangle -A MANGLE_PRE_WAN_L2 -m mark --mark 0x20000000/0xFF000000 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j LOG --log-level 7 --log-prefix "MANGLE.PRE.L2 Splice in"
#iptables -t mangle -A MANGLE_PRE_WAN_L2 -m mark --mark 0x20000000/0xFF000000 -m set --match-set circularpool_set dst -m conntrack --ctstate NEW -j NFQUEUE --queue-num 1 -m comment --comment "To TCPSplice in"
#iptables -t mangle -A MANGLE_PRE_WAN_L2 -m mark --mark 0x21000001/0xFF00000F -m set --match-set circularpool_set src                            -j LOG --log-level 7 --log-prefix "MANGLE.PRE.L2 Splice out"
#iptables -t mangle -A MANGLE_PRE_WAN_L2 -m mark --mark 0x21000001/0xFF00000F -m set --match-set circularpool_set src                            -j NFQUEUE --queue-num 1 -m comment --comment "To TCPSplice out"
iptables -t mangle -A MANGLE_PRE_WAN_L2 -j ACCEPT
# NIC: l3-lan
iptables -t mangle -N MANGLE_PRE_LAN_L3
iptables -t mangle -F MANGLE_PRE_LAN_L3
iptables -t mangle -A MANGLE_PRE_LAN_L3 -j ACCEPT
# NIC: qbf-lan (both directions)
iptables -t mangle -N MANGLE_PRE_LAN_L2
iptables -t mangle -F MANGLE_PRE_LAN_L2
iptables -t mangle -A MANGLE_PRE_LAN_L2 -j ACCEPT
# NIC: l3-tun
iptables -t mangle -N MANGLE_PRE_TUN_L3
iptables -t mangle -F MANGLE_PRE_TUN_L3
iptables -t mangle -A MANGLE_PRE_TUN_L3 -j ACCEPT
# NIC: qbf-tun (both directions)
iptables -t mangle -N MANGLE_PRE_TUN_L2
iptables -t mangle -F MANGLE_PRE_TUN_L2
iptables -t mangle -A MANGLE_PRE_TUN_L2 -j ACCEPT

# Add flows to main chain in MANGLE table
iptables -t mangle -A PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.PRE "
iptables -t mangle -A PREROUTING -m mark --mark 0x12000000/0xFF000000 -j MANGLE_PRE_WAN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x13000000/0xFF000000 -j MANGLE_PRE_LAN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x14000000/0xFF000000 -j MANGLE_PRE_TUN_L3
iptables -t mangle -A PREROUTING -m mark --mark 0x20000000/0xF0000000 -j MANGLE_PRE_WAN_L2
iptables -t mangle -A PREROUTING -m mark --mark 0x30000000/0xF0000000 -j MANGLE_PRE_LAN_L2
iptables -t mangle -A PREROUTING -m mark --mark 0x40000000/0xF0000000 -j MANGLE_PRE_TUN_L2


# --- NAT TABLE ---  #

iptables -t nat -F PREROUTING
# Create chains in NAT table for packet processing at L3 and QBF interfaces
# NIC: l3-wan
## Do DNAT towards private host @L3-WAN - Add 1 rule per private host
iptables -t nat -N NAT_PRE_WAN_L3_CPOOL
iptables -t nat -F NAT_PRE_WAN_L3_CPOOL
iptables -t nat -A NAT_PRE_WAN_L3_CPOOL -j LOG --log-level 7 --log-prefix "NAT.PRE.WAN.L3.CPOOL DNAT " -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_WAN_L3_CPOOL -m mark --mark 0x12A80065/0xFFFFFFFF -j DNAT --to-destination 192.168.0.101 -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_WAN_L3_CPOOL -m mark --mark 0x12A80066/0xFFFFFFFF -j DNAT --to-destination 192.168.0.102 -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_WAN_L3_CPOOL -m mark --mark 0x12A80067/0xFFFFFFFF -j DNAT --to-destination 192.168.0.103 -m comment --comment "DNAT to private host"
## Divert to Circular Pool chain for DNAT if packet was mangled in Control Plane
iptables -t nat -N NAT_PRE_WAN_L3
iptables -t nat -F NAT_PRE_WAN_L3
iptables -t nat -A NAT_PRE_WAN_L3 -m mark ! --mark 0x12000000/0xFFFFFFFF -m set --match-set circularpool_set dst -j NAT_PRE_WAN_L3_CPOOL -m comment --comment "Send to CPool for DNAT"
iptables -t nat -A NAT_PRE_WAN_L3 -j ACCEPT
# NIC: qbf-wan (both directions)
iptables -t nat -N NAT_PRE_WAN_L2
iptables -t nat -F NAT_PRE_WAN_L2
# Send packets through the bridge - do not attempt splice
#iptables -t nat -A NAT_PRE_WAN_L2 -m mark --mark 0x20000001/0xFF00000F -j LOG --log-level 7 --log-prefix "NAT.PRE.WAN.L2 save-mark IN "
#iptables -t nat -A NAT_PRE_WAN_L2 -m mark --mark 0x20000001/0xFF00000F -j CONNMARK --save-mark
iptables -t nat -A NAT_PRE_WAN_L2 -j ACCEPT
# NIC: l3-lan
iptables -t nat -N NAT_PRE_LAN_L3
iptables -t nat -F NAT_PRE_LAN_L3
iptables -t nat -A NAT_PRE_LAN_L3 -j ACCEPT
# NIC: qbf-lan (both directions)
iptables -t nat -N NAT_PRE_LAN_L2
iptables -t nat -F NAT_PRE_LAN_L2
iptables -t nat -A NAT_PRE_LAN_L2 -j ACCEPT
# NIC: l3-tun
iptables -t nat -N NAT_PRE_TUN_L3
iptables -t nat -F NAT_PRE_TUN_L3
iptables -t nat -A NAT_PRE_TUN_L3 -j ACCEPT
# NIC: qbf-tun (both directions)
iptables -t nat -N NAT_PRE_TUN_L2
iptables -t nat -F NAT_PRE_TUN_L2
iptables -t nat -A NAT_PRE_TUN_L2 -j ACCEPT

# Add flows to main chain in NAT table
iptables -t nat -A PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "NAT.PRE "
iptables -t nat -A PREROUTING -m mark --mark 0x12000000/0xFF000000 -j NAT_PRE_WAN_L3
iptables -t nat -A PREROUTING -m mark --mark 0x13000000/0xFF000000 -j NAT_PRE_LAN_L3
iptables -t nat -A PREROUTING -m mark --mark 0x14000000/0xFF000000 -j NAT_PRE_TUN_L3
iptables -t nat -A PREROUTING -m mark --mark 0x20000000/0xF0000000 -j NAT_PRE_WAN_L2
iptables -t nat -A PREROUTING -m mark --mark 0x30000000/0xF0000000 -j NAT_PRE_LAN_L2
iptables -t nat -A PREROUTING -m mark --mark 0x40000000/0xF0000000 -j NAT_PRE_TUN_L2


# --- MANGLE TABLE ---  #

Continue here with specific tables per interface as in previous cases

iptables -t mangle -F FORWARD
iptables -t mangle -F INPUT
# Packet clasification with mark in MANGLE table only for L3-routing interfaces
iptables -t mangle -A FORWARD -m physdev --physdev-is-in -j ACCEPT -m comment --comment "Traffic from QBF"
### LAN & WAN
iptables -t mangle -A FORWARD -i $LAN_NIC -o $WAN_NIC -j MARK --set-mark $hMARK_EGRESS_to_WAN/0x000000FF    -m comment --comment "Egress LAN to WAN"
iptables -t mangle -A FORWARD -i $WAN_NIC -o $LAN_NIC -j MARK --set-mark $hMARK_INGRESS_from_WAN/0x000000FF -m comment --comment "Ingress WAN to LAN"
### LAN & TUN
iptables -t mangle -A FORWARD -i $LAN_NIC -o $TUN_NIC -j MARK --set-mark $hMARK_EGRESS_to_TUN/0x000000FF    -m comment --comment "Egress LAN to TUN"
iptables -t mangle -A FORWARD -i $TUN_NIC -o $LAN_NIC -j MARK --set-mark $hMARK_INGRESS_from_TUN/0x000000FF -m comment --comment "Ingress TUN to LAN"
### LAN & WAN to CES Local
iptables -t mangle -A INPUT   -i $LAN_NIC             -j MARK --set-mark $hMARK_EGRESS_to_CES/0x000000FF    -m comment --comment "Egress LAN to CES"
iptables -t mangle -A INPUT   -i $WAN_NIC             -j MARK --set-mark $hMARK_INGRESS_to_CES/0x000000FF   -m comment --comment "Ingress WAN to CES"
iptables -t mangle -A INPUT   -i $TUN_NIC             -j DROP                                               -m comment --comment "Ingress TUN to CES"



# LOG FOR EASY READING
iptables -t nat -A POSTROUTING -j LOG --log-level 7 --log-prefix "######### END ######### "














# Create table
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset #Some people prefer icmp-port-unreachable
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# DEFINITION OF FILTERING POLICIES TO PROTECT FROM ATTACKS
iptables -N QBR_FILTER
iptables -F QBR_FILTER


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
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 --physdev-is-bridged ! -s $LAN_NET   -j DROP -m comment --comment "[E] IP Spoofing"
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 --physdev-is-bridged ! -s $PROXY_NET -j DROP -m comment --comment "[I] IP Spoofing"
## Drop other spoofed traffic
for ip in $SPOOF_IPS
do
    iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 --physdev-is-bridged -s $ip -j DROP -m comment --comment "[I] IP Spoofing"
done

# Forward traffic specific chain
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from LAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from WAN bridge interface" -j ACCEPT
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from TUN bridge interface" -j ACCEPT

# Apply filtering only in qbf interfaces
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER

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
#iptables -t raw -A CT_ZONES -i $LAN_NIC -j CT --zone 1
#iptables -t raw -A CT_ZONES -i $WAN_NIC -j CT --zone 1
#iptables -t raw -A CT_ZONES -i $TUN_NIC -j CT --zone 1
## Set Zone-2 for BridgeFiltering @WAN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3  -j CT --zone 2
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j CT --zone 2
## Set Zone-3 for BridgeFiltering @LAN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_LAN_NIC_L3  -j CT --zone 3
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 -j CT --zone 3
## Set Zone-4 for BridgeFiltering @TUN interface
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_TUN_NIC_L3  -j CT --zone 4
#iptables -t raw -A CT_ZONES -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 -j CT --zone 4
## Set notrack for everything else
#iptables -t raw -A CT_ZONES -j CT --notrack
#
## Definition of PACKET MARK ZONES
#iptables -t raw -N PKT_ZONES
#iptables -t raw -F PKT_ZONES
## Set Zone-1 for L3-routing interfaces
#iptables -t raw -A PKT_ZONES -i $LAN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-lan"
#iptables -t raw -A PKT_ZONES -i $WAN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-wan"
#iptables -t raw -A PKT_ZONES -i $TUN_NIC -j MARK --set-mark 0x10000000/0xFF000000 -m comment --comment "[L3] via l3-tun"
## Set Zone-2 for BridgeFiltering @WAN interface
### Restore the CONNMARK if the packet was mangled by the TCP Splicer
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3  -j CONNMARK --restore-mark -m comment --comment "[QBF] Restore mark at qbf-wan"
## Set MARK if no CONNMARK was set
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L2 -m mark --mark 0x00 -j MARK --set-mark 0x20000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-wan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_WAN_NIC_L3  -m mark --mark 0x00 -j MARK --set-mark 0x21000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-wan"
## Set Zone-3 for BridgeFiltering @LAN interface
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_LAN_NIC_L2 -j MARK --set-mark 0x30000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-lan"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_LAN_NIC_L3  -j MARK --set-mark 0x31000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-lan"
## Set Zone-4 for BridgeFiltering @TUN interface
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_TUN_NIC_L2 -j MARK --set-mark 0x40000000/0xFF000000 -m comment --comment "[QBF] via qve-phy-tun"
#iptables -t raw -A PKT_ZONES -m physdev --physdev-in $PHYSDEV_TUN_NIC_L3  -j MARK --set-mark 0x41000000/0xFF000000 -m comment --comment "[QBF] via qve-l3-tun"


# Flush PREROUTING chain in RAW table
#iptables -t raw -F PREROUTING
# Jump to CT_ZONES and set appropriate conntrack zone
#iptables -t raw -A PREROUTING -j CT_ZONES
# Jump to PKT_ZONES and set packet mark according to zone
#iptables -t raw -A PREROUTING -j PKT_ZONES
