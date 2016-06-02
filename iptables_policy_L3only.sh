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

## Interface names
LAN_L3="l3-lana"
WAN_L3="l3-wana"
TUN_L3="l3-tuna"
PREFIX_L3="l3-+"
## Networks
LAN_NET="192.168.0.0/24"
CPOOL_NET="198.18.0.21/32 198.18.0.22/32 198.18.0.23/32"
CPOOL_MAC="00:00:00:00:01:bb"
PROXY_NET="172.16.0.0/24"
SPOOF_LAN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 224.0.0.0/3"
SPOOF_WAN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"
SPOOF_TUN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 192.168.0.0/16 224.0.0.0/3"
## Conntrack Zone
CT_ZONE="1"
## Netfilter Queues
NFQUEUE_CPOOL="2"
## IPSets
SPOOF_LAN_IPSET="spoof_lan_ipset"
SPOOF_WAN_IPSET="spoof_wan_ipset"
SPOOF_TUN_IPSET="spoof_tun_ipset"
CPOOL_IPSET="circularpool_ipset"
BLACKLIST_IPSET="blacklist_ipset"
WHITELIST_IPSET="whitelist_ipset"
## Packet mark for traffic directionality
FWD_LAN_INGRESS="0x0111"
FWD_LAN_EGRESS="0x0112"
INPUT_LAN="0x0211"
INPUT_WAN="0x0221"
INPUT_TUN="0x0231"
MASK_INGRESS="0x0001/0x0001"
MASK_EGRESS="0x0002/0x0002"
MASK_FWD="0x0100/0x0100"
MASK_INPUT="0x0200/0x0200"

#################################### EBTABLES #################################
# Build ARP Responder with ebtables
ebtables -t nat -F
for ip in $CPOOL_NET
do
    ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst $ip -j arpreply --arpreply-mac $CPOOL_MAC --arpreply-target ACCEPT
done


#################################### IPTABLES #################################

# Build ipset for the addresses of the Circular Pool
ipset create $CPOOL_IPSET hash:ip
ipset flush  $CPOOL_IPSET
for ip in $CPOOL_NET;do ipset add $CPOOL_IPSET $ip;done
# Build ipset for the spoofed addresses in the different interfaces
ipset create $SPOOF_LAN_IPSET hash:net
ipset flush  $SPOOF_LAN_IPSET
for ip in $SPOOF_LAN_NET;do ipset add $SPOOF_LAN_IPSET $ip;done
ipset create $SPOOF_WAN_IPSET hash:net
ipset flush  $SPOOF_LAN_IPSET
for ip in $SPOOF_WAN_NET;do ipset add $SPOOF_WAN_IPSET $ip;done
ipset create $SPOOF_TUN_IPSET hash:net
ipset flush  $SPOOF_TUN_IPSET
for ip in $SPOOF_TUN_NET;do ipset add $SPOOF_TUN_IPSET $ip;done

# Experimental ipsets
ipset create $BLACKLIST_IPSET hash:ip
ipset flush  $BLACKLIST_IPSET
ipset create $WHITELIST_IPSET hash:ip
ipset flush  $WHITELIST_IPSET


# --- RAW TABLE ---  #

# Note: Use conntrack zone $CT_ZONE for default connection track

# Flush PREROUTING & OUTPUT chains of RAW table
iptables -t raw -F PREROUTING
iptables -t raw -F OUTPUT
# Populate chain of RAW table
## Match interface to set conntrack zone
iptables -t raw -A PREROUTING -i $LAN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$LAN_L3] CT zone $CT_ZONE"
iptables -t raw -A PREROUTING -i $WAN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$WAN_L3] CT zone $CT_ZONE"
iptables -t raw -A PREROUTING -i $TUN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$TUN_L3] CT zone $CT_ZONE"
## NOTRACK rest of traffic
#iptables -t raw -A PREROUTING -j NOTRACK
#iptables -t raw -A OUTPUT     -j NOTRACK

## Trace traffic for debugging
#iptables -t raw -I PREROUTING -i "l3-+" -j TRACE
#iptables -t raw -I PREROUTING -i "l3-+"  -j LOG --log-level 7 --log-prefix "RAW.PRE "


# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE PREROUTING table
iptables -t mangle -N MANGLE_PRE_CPOOL_POLICY
iptables -t mangle -F MANGLE_PRE_CPOOL_POLICY
# Flush PREROUTING chain of MANGLE table
iptables -t mangle -F PREROUTING
# Populate chain of MANGLE table
iptables -t mangle -A PREROUTING -i $WAN_L3 -m set --match-set $CPOOL_IPSET dst -j MANGLE_PRE_CPOOL_POLICY -m comment --comment "[$WAN_L3] CircularPool chain"
# Populate custom chains of MANGLE PREROUTING table
## Match only incoming connections in $WAN_L3 for processing in Circular Pool
## We can apply different policies, rate limitation, protocol matches, etc...
iptables -t mangle -A MANGLE_PRE_CPOOL_POLICY -p tcp --syn -m conntrack --ctstate NEW -j NFQUEUE --queue-num $NFQUEUE_CPOOL -m comment --comment "[CircularPool] Send to ControlPlane"
iptables -t mangle -A MANGLE_PRE_CPOOL_POLICY -p udp       -m conntrack --ctstate NEW -j NFQUEUE --queue-num $NFQUEUE_CPOOL -m comment --comment "[CircularPool] Send to ControlPlane"
iptables -t mangle -A MANGLE_PRE_CPOOL_POLICY -p icmp      -m conntrack --ctstate NEW -j NFQUEUE --queue-num $NFQUEUE_CPOOL -m comment --comment "[CircularPool] Send to ControlPlane"

## Trace traffic for debugging
#iptables -t mangle -I PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "MANGLE.PRE "


# --- NAT TABLE ---  #

# Definition of chains for NAT PREROUTING table
iptables -t nat -N NAT_PRE_CPOOL
iptables -t nat -F NAT_PRE_CPOOL
# Flush PREROUTING chain of NAT table
iptables -t nat -F PREROUTING
# Populate chain of NAT table
iptables -t nat -A PREROUTING -i $WAN_L3 -m mark ! --mark 0x00 -j NAT_PRE_CPOOL -m comment --comment "[CircularPool] Send to DNAT chain"
## Do DNAT towards private host @L3-WAN - Add 1 rule per private host
iptables -t nat -A NAT_PRE_CPOOL -j LOG --log-level 7 --log-prefix "NAT.PRE.CPOOL " -m comment --comment "DNAT to private host"
iptables -t nat -A NAT_PRE_CPOOL -m mark --mark 0xC0A80065 -j DNAT --to-destination 192.168.0.101
iptables -t nat -A NAT_PRE_CPOOL -m mark --mark 0xC0A80066 -j DNAT --to-destination 192.168.0.102
iptables -t nat -A NAT_PRE_CPOOL -m mark --mark 0xC0A80067 -j DNAT --to-destination 192.168.0.103

## Trace traffic for debugging
#iptables -t nat -I PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "NAT.PRE "


# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE FORWARD & INPUT table
iptables -t mangle -N MANGLE_FWD_MARK
iptables -t mangle -F MANGLE_FWD_MARK
iptables -t mangle -N MANGLE_INPUT_MARK
iptables -t mangle -F MANGLE_INPUT_MARK
# Flush FORWARD & INPUT chains of MANGLE table
iptables -t mangle -F FORWARD
iptables -t mangle -F INPUT
# Populate chains of MANGLE tables
iptables -t mangle -A FORWARD -i $PREFIX_L3 -j MANGLE_FWD_MARK
iptables -t mangle -A INPUT   -i $PREFIX_L3 -j MANGLE_INPUT_MARK
# Populate custom chains of MANGLE PREROUTING table
iptables -t mangle -A MANGLE_FWD_MARK -i $WAN_NIC -o $LAN_NIC -j MARK --set-mark $FWD_LAN_INGRESS -m comment --comment "Mark INGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $TUN_NIC -o $LAN_NIC -j MARK --set-mark $FWD_LAN_INGRESS -m comment --comment "Mark INGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_NIC -o $WAN_NIC -j MARK --set-mark $FWD_LAN_EGRESS  -m comment --comment "Mark EGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_NIC -o $TUN_NIC -j MARK --set-mark $FWD_LAN_EGRESS  -m comment --comment "Mark EGRESS"
iptables -t mangle -A MANGLE_INPUT_MARK -i $LAN_NIC           -j MARK --set-mark $INPUT_LAN       -m comment --comment "Mark INPUT"
iptables -t mangle -A MANGLE_INPUT_MARK -i $WAN_NIC           -j MARK --set-mark $INPUT_WAN       -m comment --comment "Mark INPUT"
iptables -t mangle -A MANGLE_INPUT_MARK -i $TUN_NIC           -j MARK --set-mark $INPUT_TUN       -m comment --comment "Mark INPUT"


# --- FILTER TABLE ---  #

# Definition of chains for FILTER FORWARD & INPUT table
iptables -t filter -N FILTER_IP_SPOOFING
iptables -t filter -F FILTER_IP_SPOOFING
iptables -t filter -N FILTER_IP_BLACKLIST
iptables -t filter -F FILTER_IP_BLACKLIST
iptables -t filter -N FILTER_IP_WHITELIST
iptables -t filter -F FILTER_IP_WHITELIST
iptables -t filter -N FILTER_SYSTEM_WIDE
iptables -t filter -F FILTER_SYSTEM_WIDE
iptables -t filter -N FILTER_HOST_POLICY
iptables -t filter -F FILTER_HOST_POLICY
iptables -t filter -N FILTER_LOCAL_POLICY
iptables -t filter -F FILTER_LOCAL_POLICY
# Create specific table for REJECT target
iptables -t filter -N doREJECT
iptables -t filter -F doREJECT
iptables -t filter -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -t filter -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# Populate chains of FILTER table
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_IP_SPOOFING -m comment --comment "Drop spoofed packets"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_IP_SPOOFING -m comment --comment "Drop spoofed packets"
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_IP_BLACKLIST -m comment --comment "Drop blacklisted sources"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_IP_BLACKLIST -m comment --comment "Drop blacklisted sources"
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_IP_WHITELIST -m comment --comment "Accept whitelisted sources / sysadmin"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_IP_WHITELIST -m comment --comment "Accept whitelisted sources / sysadmin"
## Accept established traffic only after initial filtering
iptables -t filter -A FORWARD -i $PREFIX_L3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Accept established traffic"
iptables -t filter -A INPUT   -i $PREFIX_L3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Accept established traffic"
## Continue filtering new connections
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_SYSTEM_WIDE -m comment --comment "Apply system wide policy"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_SYSTEM_WIDE -m comment --comment "Apply system wide policy"
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_HOST_POLICY -m comment --comment "Apply host specific policy"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_HOST_POLICY -m comment --comment "Apply host specific policy"
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_LOCAL_POLICY -m comment --comment "Apply system wide policy"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_LOCAL_POLICY -m comment --comment "Apply system wide policy"

# Populate custom chains of FILTER tables
## Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
## http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -t filter -A FILTER_IP_SPOOFING -i $LAN_NIC -m set --match-set $SPOOF_LAN_IPSET src -j DROP -m comment --comment "[$LAN_NIC] IP Spoofing"
iptables -t filter -A FILTER_IP_SPOOFING -i $WAN_NIC -m set --match-set $SPOOF_WAN_IPSET src -j DROP -m comment --comment "[$WAN_NIC] IP Spoofing"
iptables -t filter -A FILTER_IP_SPOOFING -i $TUN_NIC -m set --match-set $SPOOF_TUN_IPSET src -j DROP -m comment --comment "[$TUN_NIC] IP Spoofing"
## Create ipset for blacklist/whitelist sources - both hash:ip and hash:net?
iptables -t filter -A FILTER_IP_BLACKLIST -m set --match-set $BLACKLIST_IPSET src -j DROP   -m comment --comment "Drop blacklisted sources"
iptables -t filter -A FILTER_IP_WHITELIST -m set --match-set $WHITELIST_IPSET src -j ACCEPT -m comment --comment "Accept whitelisted sources"
## Apply system wide policy
### Filter IP packets with invalid connection state
#iptables -t filter -A FILTER_SYSTEM_WIDE -m conntrack --ctstate INVALID -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "Invalid IP/TCP " -m comment --comment "Invalid IP packet"
iptables -t filter -A FILTER_SYSTEM_WIDE -m conntrack --ctstate INVALID -j DROP -m comment --comment "Invalid IP packet"
### Force TCP SYN checks for new connections
iptables -t filter -A FILTER_SYSTEM_WIDE -p tcp ! --syn -m conntrack --ctstate NEW -j DROP -m comment --comment "Invalid TCP SYN packet"
### Force check of TCP flags
iptables -t filter -A FILTER_SYSTEM_WIDE -p tcp --tcp-flags ALL ALL  -j DROP -m comment --comment "Invalid TCP flags / Christmas in July"
iptables -t filter -A FILTER_SYSTEM_WIDE -p tcp --tcp-flags ALL NONE -j DROP -m comment --comment "Invalid TCP flags / Nothing to See Here"
### Filter vulnerable TCP services
### http://howtonixnux.blogspot.fi/2008/03/iptables-using-multiport.html
TCP_MULTIPORTS="135,137,138,139"
iptables -t filter -A FILTER_SYSTEM_WIDE -p tcp -m conntrack --ctstate NEW -m multiport --dports $TCP_MULTIPORTS -j doREJECT -m comment --comment "Reject vulnerable multiport TCP services"
iptables -t filter -A FILTER_SYSTEM_WIDE -p tcp                            -m multiport --dports $TCP_MULTIPORTS -j DROP     -m comment --comment "Drop vulnerable multiport TCP services"
### Filter new connections
iptables -t filter -A FILTER_SYSTEM_WIDE -i $LAN_NIC -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connections -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_SYSTEM_WIDE -i $WAN_NIC -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connections -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_SYSTEM_WIDE -i $TUN_NIC -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connections -j DROP -m comment --comment "New connection"
## Apply host specific policy
#iptables -t filter -A FILTER_HOST_POLICY
## Apply CES local specific policy
#iptables -t filter -A FILTER_LOCAL_POLICY


# --- Examples of HOST POLICY in FILTER TABLE ---  #
# HOST_POLICY - Specific host policies (e.g. legacy / CES services)
iptables -t filter -N HOST_192.168.0.101
iptables -t filter -F HOST_192.168.0.101
iptables -t filter -N HOST_192.168.0.101_LEGACY
iptables -t filter -F HOST_192.168.0.101_LEGACY
iptables -t filter -N HOST_192.168.0.101_CES_SSH
iptables -t filter -F HOST_192.168.0.101_CES_SSH

iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_INGRESS  -s 192.168.0.101 -j HOST_192.168.0.101
iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_EGRESS   -d 192.168.0.101 -j HOST_192.168.0.101


# Define general host firewall policies
## First apply strict policies for all traffic then Legacy or CES
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_EGRESS -p udp --dport 53 -m hashlimit --hashlimit-above 2/sec --hashlimit-burst 3 --hashlimit-name lan_dns --hashlimit-mode srcip -j DROP
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_EGRESS  -o $WAN_NIC -j HOST_192.168.0.101_LEGACY -m comment --comment "Forward to Legacy chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_INGRESS -i $WAN_NIC -j HOST_192.168.0.101_LEGACY -m comment --comment "Forward to Legacy chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_EGRESS  -d 172.16.0.1 -j HOST_192.168.0.101_CES_SSH  -m comment --comment "Forward to CES service chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_INGRESS -s 172.16.0.1 -j HOST_192.168.0.101_CES_SSH  -m comment --comment "Forward to CES service chain"

# Define legacy host firewall policies
iptables -t filter -A HOST_192.168.0.101_LEGACY -m mark --mark $MASK_INGRESS -p tcp --dport 22 -j RETURN
iptables -t filter -A HOST_192.168.0.101_LEGACY -j DROP

# Define CES service host firewall policies
### Example of SSH-only service chain established via CETP connection
iptables -t filter -A HOST_192.168.0.101_CES_SSH -m mark --mark $MASK_INGRESS -p tcp --dport 22 -j RETURN
iptables -t filter -A HOST_192.168.0.101_CES_SSH -m mark --mark $MASK_EGRESS  -p tcp --sport 22 -j RETURN
iptables -t filter -A HOST_192.168.0.101_CES_SSH -j DROP
