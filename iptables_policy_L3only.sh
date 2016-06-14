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

# NEWS: This is no longer valid because packets that are generated locally by the router are always matched in default CT_ZONE.
#       Using different CTs may lead to INVALID state or UNSEEN / UNREPLIED responses in the conntrack.
#       The use of CT zones is therefore recommended for bridge-filtering functionality, where only ACCEPT & DROP are executed.
#iptables -t raw -A PREROUTING -i $LAN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$LAN_L3] CT zone $CT_ZONE"
#iptables -t raw -A PREROUTING -i $WAN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$WAN_L3] CT zone $CT_ZONE"
#iptables -t raw -A PREROUTING -i $TUN_L3 -j CT --zone $CT_ZONE -m comment --comment "[$TUN_L3] CT zone $CT_ZONE"

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
iptables -t mangle -A MANGLE_FWD_MARK -i $WAN_L3 -o $LAN_L3 -j MARK --set-mark $FWD_LAN_INGRESS -m comment --comment "Mark INGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $TUN_L3 -o $LAN_L3 -j MARK --set-mark $FWD_LAN_INGRESS -m comment --comment "Mark INGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_L3 -o $WAN_L3 -j MARK --set-mark $FWD_LAN_EGRESS  -m comment --comment "Mark EGRESS"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_L3 -o $TUN_L3 -j MARK --set-mark $FWD_LAN_EGRESS  -m comment --comment "Mark EGRESS"
iptables -t mangle -A MANGLE_INPUT_MARK -i $LAN_L3          -j MARK --set-mark $INPUT_LAN       -m comment --comment "Mark INPUT"
iptables -t mangle -A MANGLE_INPUT_MARK -i $WAN_L3          -j MARK --set-mark $INPUT_WAN       -m comment --comment "Mark INPUT"
iptables -t mangle -A MANGLE_INPUT_MARK -i $TUN_L3          -j MARK --set-mark $INPUT_TUN       -m comment --comment "Mark INPUT"


# --- FILTER TABLE ---  #

# Definition of chains for FILTER FORWARD & INPUT table
## Apply basic filtering policy in CES
iptables -t filter -N FILTER_PREEMPTIVE
iptables -t filter -F FILTER_PREEMPTIVE
## Apply host-based policy
iptables -t filter -N FILTER_HOST_POLICY
iptables -t filter -F FILTER_HOST_POLICY
iptables -t filter -N FILTER_HOST_POLICY_ACCEPT
iptables -t filter -F FILTER_HOST_POLICY_ACCEPT
## Apply local-based policy for accepting traffic
iptables -t filter -N FILTER_LOCAL_POLICY
iptables -t filter -F FILTER_LOCAL_POLICY

# Create specific table for REJECT target
iptables -t filter -N doREJECT
iptables -t filter -F doREJECT
iptables -t filter -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -t filter -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# Populate chains of FILTER table
## Add default values for loopback and IPSec
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A INPUT -p esp -j MARK --set-xmark 0x1/0x1
iptables -t filter -A INPUT -p udp -m udp --dport 4500 -j MARK --set-xmark 0x1/0x1
## Apply basic filtering policy in CES
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_PREEMPTIVE -m comment --comment "Continue in FILTER_PREEMPTIVE chain"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_PREEMPTIVE -m comment --comment "Continue in FILTER_PREEMPTIVE chain"

## Apply host-based policy
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_HOST_POLICY -m comment --comment "Continue in host specific policy"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_HOST_POLICY -m comment --comment "Continue in host specific policy"

# There should be a call for accepted traffic from FILTER_HOST_POLICY_*** to FILTER_LOCAL_POLICY, not RETURNed here!
## Apply local-based policy for accepting traffic
iptables -t filter -A FORWARD -i $PREFIX_L3 -j FILTER_LOCAL_POLICY -m comment --comment "Continue in system wide policy"
iptables -t filter -A INPUT   -i $PREFIX_L3 -j FILTER_LOCAL_POLICY -m comment --comment "Continue in system wide policy"


# Populate custom chains of FILTER tables

## Create ipset for blacklist sources - both hash:ip and hash:net?
iptables -t filter -A FILTER_PREEMPTIVE -m set --match-set $BLACKLIST_IPSET src -j DROP   -m comment --comment "Drop blacklisted sources"

## Create ipset for whitelist sources - both hash:ip and hash:net?
iptables -t filter -A FILTER_PREEMPTIVE -m set --match-set $WHITELIST_IPSET src -j ACCEPT -m comment --comment "Accept whitelisted sources"

## Filter fragmented packets
iptables -t filter -A FILTER_PREEMPTIVE -f -j DROP -m comment --comment "Fragmented packets"

## Accept established traffic after initial filtering
iptables -t filter -A FILTER_PREEMPTIVE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Accept established traffic"
iptables -t filter -A FILTER_PREEMPTIVE -m conntrack --ctstate INVALID             -j DROP   -m comment --comment "Drop invalid traffic"

## Linux Iptables Avoid IP Spoofing And Bad Addresses Attacks
## http://www.cyberciti.biz/tips/linux-iptables-8-how-to-avoid-spoofing-and-bad-addresses-attack.html
iptables -t filter -A FILTER_PREEMPTIVE -i $LAN_L3 -m set --match-set $SPOOF_LAN_IPSET src -j DROP -m comment --comment "[$LAN_L3] IP Spoofing"
iptables -t filter -A FILTER_PREEMPTIVE -i $WAN_L3 -m set --match-set $SPOOF_WAN_IPSET src -j DROP -m comment --comment "[$WAN_L3] IP Spoofing"
iptables -t filter -A FILTER_PREEMPTIVE -i $TUN_L3 -m set --match-set $SPOOF_TUN_IPSET src -j DROP -m comment --comment "[$TUN_L3] IP Spoofing"

### Filter vulnerable TCP services
### http://howtonixnux.blogspot.fi/2008/03/iptables-using-multiport.html
TCP_MULTIPORTS_BLOCKED="135,137,138,139"
iptables -t filter -A FILTER_PREEMPTIVE -p tcp -m conntrack --ctstate NEW -m multiport --dports $TCP_MULTIPORTS_BLOCKED -j doREJECT -m comment --comment "Reject vulnerable multiport TCP services"
iptables -t filter -A FILTER_PREEMPTIVE -p tcp                            -m multiport --dports $TCP_MULTIPORTS_BLOCKED -j DROP     -m comment --comment "Drop vulnerable multiport TCP services"

### Force TCP SYN checks for new connections
iptables -t filter -A FILTER_PREEMPTIVE -p tcp ! --syn -m conntrack --ctstate NEW  -j DROP -m comment --comment "Invalid TCP SYN packet"
iptables -t filter -A FILTER_PREEMPTIVE -p tcp --tcp-flags ALL ALL                 -j DROP -m comment --comment "Invalid TCP flags / Christmas in July"
iptables -t filter -A FILTER_PREEMPTIVE -p tcp --tcp-flags ALL NONE                -j DROP -m comment --comment "Invalid TCP flags / Nothing to See Here"

### Set upper bound for potentially accepting new connections
iptables -t filter -A FILTER_PREEMPTIVE -i $LAN_L3 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_PREEMPTIVE -i $WAN_L3 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_PREEMPTIVE -i $TUN_L3 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"


## Apply HOST specific policy
### Examples are described below
## Define FILTER_HOST_POLICY_ACCEPT as an ACCEPT target abstraction from host perspective -> GoTo next table FILTER_LOCAL_POLICY
iptables -t filter -A FILTER_HOST_POLICY_ACCEPT -g FILTER_LOCAL_POLICY -m comment --comment "Accept target for FILTER_HOST_POLICY"
## Apply CES local specific policy
### Examples are described below



# --- NAT TABLE ---  #

# Populate POSTROUTING chain of NAT table with specific Source NAT for the LAN network
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -s $LAN_NET -o $WAN_L3 -j SNAT --to-source 198.18.0.11 -m comment --comment "SNAT to 198.18.0.11"



# --- Examples of HOST POLICY in FILTER TABLE ---  #
# HOST_POLICY - Specific host policies (e.g. legacy / CES services)
iptables -t filter -N HOST_192.168.0.101
iptables -t filter -F HOST_192.168.0.101
iptables -t filter -N HOST_192.168.0.101_ADMIN
iptables -t filter -F HOST_192.168.0.101_ADMIN
iptables -t filter -N HOST_192.168.0.101_LEGACY
iptables -t filter -F HOST_192.168.0.101_LEGACY
iptables -t filter -N HOST_192.168.0.101_CES
iptables -t filter -F HOST_192.168.0.101_CES
iptables -t filter -N HOST_192.168.0.101_CES_SSH
iptables -t filter -F HOST_192.168.0.101_CES_SSH
iptables -t filter -N HOST_192.168.0.101_CES_xyz
iptables -t filter -F HOST_192.168.0.101_CES_xyz

# Populate custom chain FILTER_HOST_POLICY of FILTER table - 2 entries per host / 1 entry per traffic direction
iptables -t filter -F FILTER_HOST_POLICY
#iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_INGRESS  -d 192.168.0.101 -g HOST_192.168.0.101
#iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_EGRESS   -s 192.168.0.101 -g HOST_192.168.0.101
## MARKS ARE GIVING ISSUES WHEN HOST-A PINGS CES 192.168.0.101 TO 192.168.0.1
iptables -t filter -A FILTER_HOST_POLICY -d 192.168.0.101 -g HOST_192.168.0.101
iptables -t filter -A FILTER_HOST_POLICY -s 192.168.0.101 -g HOST_192.168.0.101
iptables -t filter -A FILTER_HOST_POLICY -j DROP


# Define general host firewall policies
## First apply strict policies for all traffic then Legacy or CES
iptables -t filter -F HOST_192.168.0.101
iptables -t filter -A HOST_192.168.0.101 -j HOST_192.168.0.HOST_192.168.0.101_ADMIN -m comment --comment "First process ADMIN rules"

iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_EGRESS  ! -d $PROXY_NET -j HOST_192.168.0.101_LEGACY   -m comment --comment "To Legacy chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_INGRESS ! -s $PROXY_NET -j HOST_192.168.0.101_LEGACY   -m comment --comment "To Legacy chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_EGRESS    -d $PROXY_NET -j HOST_192.168.0.101_CES      -m comment --comment "To CES chain"
iptables -t filter -A HOST_192.168.0.101 -m mark --mark $MASK_INGRESS   -s $PROXY_NET -j HOST_192.168.0.101_CES      -m comment --comment "To CES chain"
iptables -t filter -A HOST_192.168.0.101 -j DROP                                                                     -m comment --comment "Should not be here"

# Define admin host rules
iptables -t filter -F HOST_192.168.0.101_ADMIN
#iptables -t filter -A HOST_192.168.0.101_ADMIN -m mark --mark $MASK_EGRESS -p udp --dport 53 -m hashlimit --hashlimit-above 1/sec --hashlimit-burst 1 --hashlimit-name lan_dns --hashlimit-mode srcip -j DROP
#iptables -t filter -A HOST_192.168.0.101_ADMIN -m mark --mark $MASK_EGRESS -p udp --dport 53 -g FILTER_HOST_POLICY_ACCEPT
iptables -t filter -A HOST_192.168.0.101_ADMIN -m mark --mark $MASK_EGRESS -p udp --dport 53 -m hashlimit --hashlimit-upto 1/sec --hashlimit-burst 1 --hashlimit-name lan_dns --hashlimit-mode srcip -g FILTER_HOST_POLICY_ACCEPT
iptables -t filter -A HOST_192.168.0.101_ADMIN -m mark --mark $MASK_EGRESS -p udp --dport 53 -j DROP


# Define legacy host firewall policies
iptables -t filter -F HOST_192.168.0.101_LEGACY
iptables -t filter -A HOST_192.168.0.101_LEGACY -m mark --mark $MASK_INGRESS -p tcp --dport 22    -g FILTER_HOST_POLICY_ACCEPT -m comment --comment "Ingress: ACCEPT"
iptables -t filter -A HOST_192.168.0.101_LEGACY -m mark --mark $MASK_INGRESS                      -j DROP                      -m comment --comment "Ingress: DROP"
iptables -t filter -A HOST_192.168.0.101_LEGACY -m mark --mark $MASK_EGRESS  -p tcp --dport 12345 -j DROP                      -m comment --comment "Egress: DROP"
iptables -t filter -A HOST_192.168.0.101_LEGACY -m mark --mark $MASK_EGRESS                       -g FILTER_HOST_POLICY_ACCEPT -m comment --comment "Egress: ACCEPT"
iptables -t filter -A HOST_192.168.0.101_LEGACY -j DROP                                           -m comment --comment "Should not be here"

# Define CES connections policies
iptables -t filter -A HOST_192.168.0.101_CES -m mark --mark $MASK_EGRESS  -d 172.16.0.1 -j HOST_192.168.0.101_CES_SSH  -m comment --comment "To CES SSH service chain"
iptables -t filter -A HOST_192.168.0.101_CES -m mark --mark $MASK_INGRESS -s 172.16.0.1 -j HOST_192.168.0.101_CES_SSH  -m comment --comment "To CES SSH service chain"
iptables -t filter -A HOST_192.168.0.101_CES -m mark --mark $MASK_EGRESS  -d 172.16.0.2 -j HOST_192.168.0.101_CES_xyz  -m comment --comment "To CES SSH service chain"
iptables -t filter -A HOST_192.168.0.101_CES -m mark --mark $MASK_INGRESS -s 172.16.0.2 -j HOST_192.168.0.101_CES_xyz  -m comment --comment "To CES SSH service chain"
iptables -t filter -A HOST_192.168.0.101_CES -j DROP                                                                   -m comment --comment "Should not be here"

# Define CES service host firewall policies
### Example of SSH-only service chain established via CETP connection
iptables -t filter -F HOST_192.168.0.101_CES_SSH
iptables -t filter -A HOST_192.168.0.101_CES_SSH -m mark --mark $MASK_INGRESS -p tcp --dport 22 -g FILTER_HOST_POLICY_ACCEPT -m comment --comment "Ingress: ACCEPT"
iptables -t filter -A HOST_192.168.0.101_CES_SSH -m mark --mark $MASK_EGRESS                    -j DROP                      -m comment --comment "Egress: Default DROP"
iptables -t filter -A HOST_192.168.0.101_CES_SSH -j DROP                                                                     -m comment --comment "Should not be here"

### Example of outgoing-only service chain established via CETP connection
iptables -t filter -F HOST_192.168.0.101_CES_xyz
iptables -t filter -A HOST_192.168.0.101_CES_xyz -m mark --mark $MASK_INGRESS                   -j DROP                      -m comment --comment "Ingress: Default DROP"
iptables -t filter -A HOST_192.168.0.101_CES_xyz -m mark --mark $MASK_EGRESS                    -g FILTER_HOST_POLICY_ACCEPT -m comment --comment "Egress: ACCEPT"
iptables -t filter -A HOST_192.168.0.101_CES_xyz -j DROP                                                                     -m comment --comment "Should not be here"



# --- Examples of CES POLICY in FILTER TABLE ---  #

# CES_POLICY - Specific CES policies for INPUT and FWD traffic (e.g. DNS, DHCP, HTTP(S))

# Definition of chains for CES_POLICY
iptables -t filter -N CES_DHCP
iptables -t filter -F CES_DHCP
iptables -t filter -N CES_HTTP
iptables -t filter -F CES_HTTP
iptables -t filter -N CES_DNS
iptables -t filter -F CES_DNS
# Specific chains for CES_DNS
iptables -t filter -N CES_DNS_WAN
iptables -t filter -F CES_DNS_WAN
iptables -t filter -N CES_DNS_LAN
iptables -t filter -F CES_DNS_LAN
iptables -t filter -N CES_DNS_TUN
iptables -t filter -F CES_DNS_TUN

# Populate custom chain FILTER_LOCAL_POLICY of FILTER table
iptables -t filter -A FILTER_LOCAL_POLICY -p udp              --dport 67      -g CES_DHCP -m comment --comment "Jump to DHCP local chain"
iptables -t filter -A FILTER_LOCAL_POLICY -p tcp -m multiport --dports 80,443 -g CES_HTTP -m comment --comment "Jump to HTTP local chain"
iptables -t filter -A FILTER_LOCAL_POLICY -p udp              --dport 53      -g CES_DNS  -m comment --comment "Jump to DNS  local chain"
iptables -t filter -A FILTER_LOCAL_POLICY                                     -j ACCEPT   -m comment --comment "Accept"

# Set policy for DHCP traffic
## Add rate limitations ?
iptables -t filter -A CES_DHCP -m mark --mark $INPUT_LAN  -p udp --sport 68 --dport 67 -j ACCEPT -m comment --comment "Accept DHCP"
iptables -t filter -A CES_DHCP -m mark --mark $MASK_INPUT -p udp            --dport 67 -j DROP   -m comment --comment "Drop"
# Set policy for HTTP(S) traffic
## Add rate limitations ?
iptables -t filter -A CES_HTTP -m mark --mark $INPUT_WAN  -p tcp --syn -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "Accept HTTP(S) @WAN"
iptables -t filter -A CES_HTTP -m mark --mark $MASK_INPUT -p tcp       -m multiport --dports 80,443                            -j DROP   -m comment --comment "Drop"
# Set policy for DNS traffic
iptables -t filter -A CES_DNS -m mark --mark $INPUT_WAN -p udp --dport 53 -j CES_DNS_WAN -m comment --comment "Continue in DNS WAN chain"
iptables -t filter -A CES_DNS -m mark --mark $INPUT_LAN -p udp --dport 53 -j CES_DNS_LAN -m comment --comment "Continue in DNS LAN chain"
iptables -t filter -A CES_DNS -m mark --mark $INPUT_TUN -p udp --dport 53 -j CES_DNS_TUN -m comment --comment "Continue in DNS TUN chain"


# Specific chains for CES_DNS_WAN
iptables -t filter -N CES_DNS_WAN_BLACKLIST
iptables -t filter -F CES_DNS_WAN_BLACKLIST
iptables -t filter -N CES_DNS_WAN_WHITELIST
iptables -t filter -F CES_DNS_WAN_WHITELIST
iptables -t filter -N CES_DNS_WAN_WKGREYLIST
iptables -t filter -F CES_DNS_WAN_WKGREYLIST
iptables -t filter -N CES_DNS_WAN_GREYLIST
iptables -t filter -F CES_DNS_WAN_GREYLIST
iptables -t filter -N CES_DNS_WAN_GLOBAL_LIMIT
iptables -t filter -F CES_DNS_WAN_GLOBAL_LIMIT
iptables -t filter -N CES_DNS_WAN_DOMAIN_LIMIT
iptables -t filter -F CES_DNS_WAN_DOMAIN_LIMIT
# Specific chains for CES_DNS_LAN
iptables -t filter -N CES_DNS_LAN_BLACKLIST
iptables -t filter -F CES_DNS_LAN_BLACKLIST
iptables -t filter -N CES_DNS_LAN_GLOBAL_LIMIT
iptables -t filter -F CES_DNS_LAN_GLOBAL_LIMIT

# Build ipsets for the DNS server classification
DNS_BLACKLIST_IPSET="dns_blacklist_ipset"
DNS_WHITELIST_IPSET="dns_whitelist_ipset"
DNS_WKGREYLIST_IPSET="dns_wkgreylist_ipset"

for ips in $DNS_BLACKLIST_IPSET $DNS_WHITELIST_IPSET $DNS_WKGREYLIST_IPSET
do
    ipset create $ips hash:ip
    ipset flush  $ips
done

# Populate custom chain CES_DNS_WAN of FILTER table
iptables -t filter -A CES_DNS_WAN                                              -j CES_DNS_WAN_BLACKLIST    -m comment --comment "Apply blacklist"
iptables -t filter -A CES_DNS_WAN                                              -j CES_DNS_WAN_DOMAIN_LIMIT -m comment --comment "Apply domain limitation"
iptables -t filter -A CES_DNS_WAN -m set --match-set $DNS_WHITELIST_IPSET  src -j CES_DNS_WAN_WHITELIST    -m comment --comment "Apply whitelist"
iptables -t filter -A CES_DNS_WAN -m set --match-set $DNS_WKGREYLIST_IPSET src -j CES_DNS_WAN_WKGREYLIST   -m comment --comment "Apply wellknown greylist"
iptables -t filter -A CES_DNS_WAN                                              -j CES_DNS_WAN_GREYLIST     -m comment --comment "Apply greylist"
iptables -t filter -A CES_DNS_WAN                                              -j DROP                     -m comment --comment "Should not be here"

## Drop blacklisted IP addresses or matching domains
iptables -t filter -A CES_DNS_WAN_BLACKLIST -m set --match-set $DNS_BLACKLIST_IPSET src                 -j DROP -m comment --comment "Drop blacklist DNS source"
iptables -t filter -A CES_DNS_WAN_BLACKLIST -m string --algo bm ! --hex-string "|0B|mysoarecord|03|ces" -j DROP -m comment --comment "Drop not SOA record"
## Accept whitelisted servers up to threshold else goto wellknown greylist chain
iptables -t filter -A CES_DNS_WAN_WHITELIST  -m hashlimit --hashlimit-upto 10/sec --hashlimit-burst 10 --hashlimit-name wan_dns_wl   --hashlimit-mode srcip -j ACCEPT -m comment --comment "SLA Whitelist"
iptables -t filter -A CES_DNS_WAN_WHITELIST                                                             -g CES_DNS_WAN_WKGREYLIST -m comment --comment "Continue as WK-Greylist"
## Pseudo-acccept wellknown greylist servers up to threshold else goto greylist chain
iptables -t filter -A CES_DNS_WAN_WKGREYLIST -m hashlimit --hashlimit-upto 20/sec --hashlimit-burst 20 --hashlimit-name wan_dns_wkgl                        -g CES_DNS_WAN_GLOBAL_LIMIT -m comment --comment "Preferred WK-Greylist"
iptables -t filter -A CES_DNS_WAN_WKGREYLIST                                                            -g CES_DNS_WAN_GREYLIST   -m comment --comment "Continue as Greylist"
## Pseudo-acccept greylist servers up to threshold else DROP
iptables -t filter -A CES_DNS_WAN_GREYLIST   -m hashlimit --hashlimit-upto 15/sec --hashlimit-burst 15 --hashlimit-name wan_dns_gl                          -g CES_DNS_WAN_GLOBAL_LIMIT -m comment --comment "Best effort Greylist"
iptables -t filter -A CES_DNS_WAN_GREYLIST                                                              -j DROP                   -m comment --comment "Drop excess in Greylist"
## Apply global limit to WK-Greylist and Greylist
iptables -t filter -A CES_DNS_WAN_GLOBAL_LIMIT  -m hashlimit --hashlimit-upto 25/sec --hashlimit-burst 25 --hashlimit-name wan_dns_gl                       -j ACCEPT -m comment --comment "Accept Non-SLA traffic"
iptables -t filter -A CES_DNS_WAN_GLOBAL_LIMIT                                                          -j DROP                   -m comment --comment "Drop excess"


# Populate custom chain CES_DNS_LAN of FILTER table
iptables -t filter -A CES_DNS_LAN                                                                       -j CES_DNS_LAN_BLACKLIST    -m comment --comment "Apply blacklist"
iptables -t filter -A CES_DNS_LAN                                                                       -j CES_DNS_LAN_GLOBAL_LIMIT -m comment --comment "Apply global limitation"
iptables -t filter -A CES_DNS_LAN                                                                       -j DROP                     -m comment --comment "Should not be here"
## Drop blacklisted IP addresses or matching domains
iptables -t filter -A CES_DNS_LAN_BLACKLIST -m string --algo bm ! --hex-string "|07|youtube|03|com"     -j DROP -m comment --comment "Drop not SOA record"
## Apply global limit to WK-Greylist and Greylist
iptables -t filter -A CES_DNS_LAN_GLOBAL_LIMIT  -m hashlimit --hashlimit-upto 25/sec --hashlimit-burst 25 --hashlimit-name lan_dns  -j ACCEPT -m comment --comment "Accept LAN traffic"
iptables -t filter -A CES_DNS_LAN_GLOBAL_LIMIT                                                                                      -j DROP   -m comment --comment "Drop excess"


# Populate custom chain CES_DNS_TUN of FILTER table
iptables -t filter -A CES_DNS_TUN                                                                       -j DROP                     -m comment --comment "Drop DNS @TUN"
