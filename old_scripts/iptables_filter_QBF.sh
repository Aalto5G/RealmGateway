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
PHYSDEV_LAN_NIC="qve-phy-lana"
PHYSDEV_WAN_NIC="qve-phy-wana"
PHYSDEV_TUN_NIC="qve-phy-tuna"
LAN_NET="192.168.0.0/24"
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


# Create table
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# DEFINITION OF FILTERING POLICIES TO PROTECT FROM ATTACKS
iptables -N QBR_FILTER
iptables -F QBR_FILTER

iptables -N QBR_FILTER_LAN
iptables -F QBR_FILTER_LAN
iptables -N QBR_FILTER_WAN
iptables -F QBR_FILTER_WAN
iptables -N QBR_FILTER_TUN
iptables -F QBR_FILTER_TUN


# Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
# http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged ! -s $LAN_NET   -j DROP -m comment --comment "[E] IP Spoofing"
iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged ! -s $PROXY_NET -j DROP -m comment --comment "[I] IP Spoofing"
## Drop other spoofed traffic
for ip in $SPOOF_IPS
do
    iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -s $ip -j DROP -m comment --comment "[I] IP Spoofing"
done

# Drop vulnerable multiport TCP services
# http://howtonixnux.blogspot.fi/2008/03/iptables-using-multiport.html
TCP_MULTIPORTS="135,137,138,139"
iptables -A QBR_FILTER -p tcp -m conntrack --ctstate NEW -m multiport --dports $TCP_MULTIPORTS -j doREJECT -m comment --comment "Reject vulnerable multiport TCP services"
iptables -A QBR_FILTER -p tcp                            -m multiport --dports $TCP_MULTIPORTS -j DROP     -m comment --comment "Drop vulnerable multiport TCP services"


# Forward traffic specific chain
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from LAN bridge interface" -j QBR_FILTER_LAN
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from WAN bridge interface" -j QBR_FILTER_WAN
sudo iptables -A QBR_FILTER -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from TUN bridge interface" -j QBR_FILTER_TUN


# [Force Fragments packets check]
# Populate LAN filtering
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP fragmented"
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_drop --hashlimit-upto 5/sec --hashlimit-burst 1 -j DROP
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_warn --hashlimit-upto 1/sec --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP fragmented"
iptables -A QBR_FILTER_LAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -j DROP
# Populate WAN filtering
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP fragmented"
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_drop --hashlimit-upto 5/sec --hashlimit-burst 1 -j DROP
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_warn --hashlimit-upto 1/sec --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP fragmented"
iptables -A QBR_FILTER_WAN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -j DROP
# Populate TUN filtering
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP fragmented"
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_drop --hashlimit-upto 5/sec --hashlimit-burst 1 -j DROP
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_warn --hashlimit-upto 1/sec --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP fragmented"
iptables -A QBR_FILTER_TUN --fragment -m comment --comment "[E] Invalid IP fragmented packet" -j DROP


# [Invalid IP/TCP packet]
# Populate LAN filtering
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP/TCP"
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 -j doREJECT
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP/TCP"
iptables -A QBR_FILTER_LAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -j DROP
# Populate WAN filtering
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP/TCP"
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 -j doREJECT
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP/TCP"
iptables -A QBR_FILTER_WAN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -j DROP
# Populate WAN filtering
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Invalid IP/TCP"
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 -j doREJECT
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Invalid IP/TCP"
iptables -A QBR_FILTER_TUN -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -j DROP



# [New TCP connections]
### Notes: iptables will only match -conntrack --ctstate NEW if the segment comes with TCP SYN only flag.
# Populate LAN filtering
### Notes: Limit the traffic originating from the LAN network -> Number of hosts are known and limited
iptables -F QBR_FILTER_LAN
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_ok   --hashlimit-upto 5/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j RETURN
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Excess TCP.SYN"
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 -j doREJECT
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Excess TCP.SYN"
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_LAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -j DROP
# Populate WAN filtering
### Notes: Accept up to an upper threshold, then report excess traffic based on srcip with VLSM (Variable-Length Subnet Masking)
iptables -F QBR_FILTER_WAN
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_ok   --hashlimit-upto 20/sec  --hashlimit-burst 1 --hashlimit-mode dstip -j RETURN
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Excess TCP.SYN"
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode dstip,srcip --hashlimit-srcmask 27 -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 --hashlimit-mode dstip -j doREJECT
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Excess TCP.SYN"
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode dstip,srcip --hashlimit-srcmask 27 -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_WAN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -j DROP
# Populate TUN filtering
### Notes: Limit the traffic originating from the TUN network -> Number of hosts are known and limited on srcip with VLSM (Variable-Length Subnet Masking)
iptables -F QBR_FILTER_TUN
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_ok   --hashlimit-upto 20/sec --hashlimit-burst 1 --hashlimit-mode srcip --hashlimit-srcmask 27 -j RETURN
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "INFO: Excess TCP.SYN"
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip,dstip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_drop --hashlimit-upto 5/sec  --hashlimit-burst 1 -j doREJECT
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "WARN: Excess TCP.SYN"
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip,dstip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A QBR_FILTER_TUN -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -j DROP


# Apply filtering only in qbr-filter interfaces
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_LAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_WAN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER
sudo iptables -A FORWARD -m physdev --physdev-in $PHYSDEV_TUN_NIC --physdev-is-bridged -m comment --comment "Incoming traffic from 'physical' interface" -j QBR_FILTER

# Set last rule to accept
sudo iptables -A FORWARD -m physdev --physdev-is-in -m comment --comment "Traffic from other bridge interface" -j ACCEPT
