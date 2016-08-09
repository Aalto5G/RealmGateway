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

# Definition of variables
VTEP_NIC="cesa-vetp"
WAN_NIC="cesa-wan"
LAN_NIC="cesa-lan"
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

# DEFINITION OF FIREWALL POLICIES TO PROTECT FROM ATTACKS
iptables -N FIREWALL_POLICY
iptables -F FIREWALL_POLICY

# Drop invalid TCP packets
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -m hashlimit --hashlimit-name eTcpInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -m conntrack --ctstate INVALID -p tcp -m comment --comment "[E] Invalid IP/TCP packet" -j DROP

iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name iTcpInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name iTcpInvalid_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -m hashlimit --hashlimit-name iTcpInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -m conntrack --ctstate INVALID -p tcp -m comment --comment "[I] Invalid IP/TCP packet" -j DROP


# Force Fragments packets check
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  --fragment -m comment --comment "[E] Invalid IP fragmented packet" -m hashlimit --hashlimit-name eFragInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  --fragment -m comment --comment "[E] Invalid IP fragmented packet" -j DROP

iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK --fragment -m comment --comment "[I] Invalid IP fragmented packet" -m hashlimit --hashlimit-name iFragInvalid_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK --fragment -m comment --comment "[I] Invalid IP fragmented packet" -m hashlimit --hashlimit-name iFragInvalid_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK --fragment -m comment --comment "[I] Invalid IP fragmented packet" -m hashlimit --hashlimit-name iFragInvalid_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK --fragment -m comment --comment "[I] Invalid IP fragmented packet" -j DROP


# Force SYN packets check for new connections
# Notes: iptables will only match -conntrack --ctstate NEW if the segment comes with TCP SYN only flag.
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_ok   --hashlimit-upto 10/sec --hashlimit-burst 1 --hashlimit-mode srcip -j RETURN
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -m hashlimit --hashlimit-name eTcpSyn_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[E] New TCP.SYN packet" -j DROP

# Use different approach on INGRESS: Mark packets
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_all  --hashlimit-upto 20/sec --hashlimit-burst 1 --hashlimit-mode dstip -j MARK --set-mark 0xF000/0xF000
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_log  --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode dstip -j LOG
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_ok   --hashlimit-upto 5/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j RETURN
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_info --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 0 #LOG #NFQUEUE --queue-num 0
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_drop --hashlimit-upto 10/sec --hashlimit-burst 1 -j doREJECT
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -m hashlimit --hashlimit-name iTcpSyn_warn --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip -j NFQUEUE --queue-num 1 #LOG #NFQUEUE --queue-num 1
iptables -A FIREWALL_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -p tcp --syn -m conntrack --ctstate NEW -m comment --comment "[I] New TCP.SYN packet" -j DROP

# Drop vulnerable multiport TCP services
# http://howtonixnux.blogspot.fi/2008/03/iptables-using-multiport.html
TCP_MULTIPORTS="135,137,138,139"
iptables -A FIREWALL_POLICY -p tcp -m conntrack --ctstate NEW -m multiport --dports $TCP_MULTIPORTS -j doREJECT -m comment --comment "Drop vulnerable multiport TCP services"


# Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
# http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -A FIREWALL_POLICY -i $LAN_NIC  ! -s $LAN_NET   -j doREJECT -m comment --comment "[E] IP Spoofing"
iptables -A FIREWALL_POLICY -i $VTEP_NIC ! -s $PROXY_NET -j doREJECT -m comment --comment "[I] IP Spoofing"
## Drop other spoofed traffic
for ip in $SPOOF_IPS
do
    iptables -A FIREWALL_POLICY -i $WAN_NIC -s $ip -j doREJECT -m comment --comment "[I] IP Spoofing"
done


# Linux Iptables allow or block ICMP ping request
# http://www.cyberciti.biz/tips/linux-iptables-9-allow-icmp-ping.html
