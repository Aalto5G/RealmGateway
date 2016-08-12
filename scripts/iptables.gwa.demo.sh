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

# Enable IP FORWARDING
sysctl -w net.ipv4.ip_forward=1

# Definition of variables

## Interface names
LAN_L3="eth0"
WAN_L3="eth1"
TUN_L3="tun0"
## Networks
LAN_NET="192.168.0.0/24"
CPOOL_NET="198.18.1.133/32 198.18.1.134/32 198.18.1.135/32 198.18.1.136/32 198.18.1.137/32 198.18.1.138/32 198.18.1.139/32 198.18.1.140/32 198.18.1.141/32 198.18.1.142/32"
CPOOL_SNAT="198.18.1.133-198.18.1.142"
#CPOOL_NET="198.18.1.133/32 198.18.1.134/32 198.18.1.135/32"
#CPOOL_SNAT="198.18.1.133-198.18.1.135"
PROXY_NET="172.16.0.0/16"
SPOOF_LAN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 224.0.0.0/3"
SPOOF_WAN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"
SPOOF_TUN_NET="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 192.168.0.0/16 224.0.0.0/3"
## Netfilter Queues
NFQUEUE_CPOOL="1"
## IPSets
SPOOF_LAN_IPSET="spoof_lan_ipset"
SPOOF_WAN_IPSET="spoof_wan_ipset"
SPOOF_TUN_IPSET="spoof_tun_ipset"
CPOOL_IPSET="circularpool_ipset"
BLACKLIST_IPSET="blacklist_ipset"
WHITELIST_IPSET="whitelist_ipset"
## DNS settings
DNS_SOA1="|03|gwa|04|demo|00|"
DNS_SOA2="|07|in-addr|04|arpa|00|"
## Definition of specific packet MARK for traffic
MARK_LOCAL_FROM_LAN="0xFF121212/0xFFFFFFFF"
MARK_LOCAL_TO_LAN="0xFF211221/0xFFFFFFFF"
MARK_LOCAL_FROM_WAN="0xFF021113/0xFFFFFFFF"
MARK_LOCAL_TO_WAN="0xFF011131/0xFFFFFFFF"
MARK_LOCAL_FROM_TUN="0xFF021114/0xFFFFFFFF"
MARK_LOCAL_TO_TUN="0xFF011141/0xFFFFFFFF"
MARK_LAN_TO_WAN="0xFF222232/0xFFFFFFFF"
MARK_LAN_FROM_WAN="0xFF112223/0xFFFFFFFF"
MARK_LAN_TO_TUN="0xFF222342/0xFFFFFFFF"
MARK_LAN_FROM_TUN="0xFF112324/0xFFFFFFFF"
## Definition of packet MASKS for traffic
### Classified by traffic scope and direction
MASK_LOCAL="0xFF001010/0xFF00F0F0"
MASK_LOCAL_INGRESS="0xFF021010/0xFF0FF0F0"
MASK_LOCAL_EGRESS="0xFF011001/0xFF0FF00F"
MASK_HOST_INGRESS="0xFF000020/0xFF0000F0"
MASK_HOST_EGRESS="0xFF000002/0xFF00000F"
MASK_HOST_LEGACY="0xFF000200/0xFF000F00"
MASK_HOST_LEGACY_INGRESS="0xFF000220/0xFF000FF0"
MASK_HOST_LEGACY_EGRESS="0xFF000202/0xFF000F0F"
MASK_HOST_CES="0xFF000300/0xFF000F00"
MASK_HOST_CES_INGRESS="0xFF000320/0xFF000FF0"
MASK_HOST_CES_EGRESS="0xFF000302/0xFF000F0F"
### Classified by ingress or egress interface
MASK_LAN_INGRESS="0xFF000002/0xFF00000F"
MASK_WAN_INGRESS="0xFF000003/0xFF00000F"
MASK_TUN_INGRESS="0xFF000004/0xFF00000F"
MASK_LAN_EGRESS="0xFF000020/0xFF0000F0"
MASK_WAN_EGRESS="0xFF000030/0xFF0000F0"
MASK_TUN_EGRESS="0xFF000040/0xFF0000F0"


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


## Trace traffic for debugging
#iptables -t nat -I PREROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "NAT.PRE "


# --- MANGLE TABLE ---  #

# Definition of chains for MANGLE FORWARD & INPUT table
iptables -t mangle -N MANGLE_FWD_MARK
iptables -t mangle -F MANGLE_FWD_MARK
iptables -t mangle -N MANGLE_INPUT_MARK
iptables -t mangle -F MANGLE_INPUT_MARK
iptables -t mangle -N MANGLE_OUTPUT_MARK
iptables -t mangle -F MANGLE_OUTPUT_MARK
# Flush FORWARD & INPUT chains of MANGLE table
iptables -t mangle -F FORWARD
iptables -t mangle -F INPUT
iptables -t mangle -F OUTPUT
# Populate chains of MANGLE tables
iptables -t mangle -A FORWARD -j MANGLE_FWD_MARK
iptables -t mangle -A INPUT   -j MANGLE_INPUT_MARK
iptables -t mangle -A OUTPUT  -j MANGLE_OUTPUT_MARK
# Populate custom chains of MANGLE PREROUTING table
iptables -t mangle -A MANGLE_FWD_MARK -i $WAN_L3 -o $LAN_L3 -j MARK --set-mark $MARK_LAN_FROM_WAN   -m comment --comment "Mark LAN_FROM_WAN"
iptables -t mangle -A MANGLE_FWD_MARK -i $TUN_L3 -o $LAN_L3 -j MARK --set-mark $MARK_LAN_FROM_TUN   -m comment --comment "Mark LAN_FROM_TUN"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_L3 -o $WAN_L3 -j MARK --set-mark $MARK_LAN_TO_WAN     -m comment --comment "Mark LAN_TO_WAN"
iptables -t mangle -A MANGLE_FWD_MARK -i $LAN_L3 -o $TUN_L3 -j MARK --set-mark $MARK_LAN_TO_TUN     -m comment --comment "Mark LAN_TO_TUN"
iptables -t mangle -A MANGLE_INPUT_MARK  -i $LAN_L3         -j MARK --set-mark $MARK_LOCAL_FROM_LAN -m comment --comment "Mark LOCAL_FROM_LAN"
iptables -t mangle -A MANGLE_INPUT_MARK  -i $WAN_L3         -j MARK --set-mark $MARK_LOCAL_FROM_WAN -m comment --comment "Mark LOCAL_FROM_WAN"
iptables -t mangle -A MANGLE_INPUT_MARK  -i $TUN_L3         -j MARK --set-mark $MARK_LOCAL_FROM_TUN -m comment --comment "Mark LOCAL_FROM_TUN"
iptables -t mangle -A MANGLE_OUTPUT_MARK -o $LAN_L3         -j MARK --set-mark $MARK_LOCAL_TO_LAN   -m comment --comment "Mark LOCAL_TO_LAN"
iptables -t mangle -A MANGLE_OUTPUT_MARK -o $WAN_L3         -j MARK --set-mark $MARK_LOCAL_TO_WAN   -m comment --comment "Mark LOCAL_TO_WAN"
iptables -t mangle -A MANGLE_OUTPUT_MARK -o $TUN_L3         -j MARK --set-mark $MARK_LOCAL_TO_TUN   -m comment --comment "Mark LOCAL_TO_TUN"



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
iptables -t filter -N FILTER_SELF_POLICY
iptables -t filter -F FILTER_SELF_POLICY

# Create specific table for REJECT target
iptables -t filter -N doREJECT
iptables -t filter -F doREJECT
iptables -t filter -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -t filter -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# Populate chains of FILTER table
## Add default values for loopback and IPSec
iptables -t filter -A INPUT -i lo -j ACCEPT
#iptables -t filter -A INPUT -p esp -j MARK --set-xmark 0x1/0x1
#iptables -t filter -A INPUT -p udp -m udp --dport 4500 -j MARK --set-xmark 0x1/0x1
## Apply basic filtering policy in CES
iptables -t filter -A FORWARD -j FILTER_PREEMPTIVE -m comment --comment "Continue in FILTER_PREEMPTIVE chain"
iptables -t filter -A INPUT   -j FILTER_PREEMPTIVE -m comment --comment "Continue in FILTER_PREEMPTIVE chain"

## Apply host-based policy
iptables -t filter -A FORWARD -j FILTER_HOST_POLICY -m comment --comment "Continue in host specific policy"
iptables -t filter -A INPUT   -j FILTER_HOST_POLICY -m comment --comment "Continue in host specific policy"

# There should be a call for accepted traffic from FILTER_HOST_POLICY_*** to FILTER_SELF_POLICY, not RETURNed here!
## Apply local-based policy for accepting traffic
### NB: The problem is that WAN_INCOMING traffic leaks from FILTER_HOST_POLICY because it does not match with a private host per se
iptables -t filter -A FORWARD -j FILTER_SELF_POLICY -m comment --comment "We should not be here"
iptables -t filter -A INPUT   -j FILTER_SELF_POLICY -m comment --comment "We should not be here"

# Should we apply OUTPUT filtering for CES locally initiated connections?
## We are already MARKing packets in MANGLE.OUTPUT
iptables -t filter -A OUTPUT -j ACCEPT

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
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_LAN_INGRESS -m set --match-set $SPOOF_LAN_IPSET src -j DROP -m comment --comment "[$LAN_L3] IP Spoofing"
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_WAN_INGRESS -m set --match-set $SPOOF_WAN_IPSET src -j DROP -m comment --comment "[$WAN_L3] IP Spoofing"
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_TUN_INGRESS -m set --match-set $SPOOF_TUN_IPSET src -j DROP -m comment --comment "[$TUN_L3] IP Spoofing"

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
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_LAN_INGRESS -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_WAN_INGRESS -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"
iptables -t filter -A FILTER_PREEMPTIVE -m mark --mark $MASK_TUN_INGRESS -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 120 --hashlimit-name new_connection -j DROP -m comment --comment "New connection"


## Apply HOST specific policy
### Examples are described below
## Define FILTER_HOST_POLICY_ACCEPT as an ACCEPT target abstraction from host perspective -> GoTo next table FILTER_SELF_POLICY
iptables -t filter -A FILTER_HOST_POLICY_ACCEPT -g FILTER_SELF_POLICY -m comment --comment "Accept target for FILTER_HOST_POLICY"
## Apply CES local specific policy
### Examples are described below



# --- NAT TABLE ---  #

# Populate POSTROUTING chain of NAT table with specific Source NAT for the LAN network
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -s $LAN_NET -o $WAN_L3 -j SNAT --to-source $CPOOL_SNAT --persistent -m comment --comment "SNAT to $CPOOL_SNAT"


# Populate custom chain FILTER_HOST_POLICY of FILTER table - 2 entries per host / 1 entry per traffic direction
#iptables -t filter -F FILTER_HOST_POLICY
#iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_HOST_INGRESS -d 192.168.0.101 -g HOST_192.168.0.101
#iptables -t filter -A FILTER_HOST_POLICY -m mark --mark $MASK_HOST_EGRESS  -s 192.168.0.101 -g HOST_192.168.0.101
#iptables -t filter -A FILTER_HOST_POLICY -j DROP



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

# Populate custom chain FILTER_SELF_POLICY of FILTER table
iptables -t filter -A FILTER_SELF_POLICY -p udp              --dport 67      -g CES_DHCP -m comment --comment "Jump to DHCP local chain"
iptables -t filter -A FILTER_SELF_POLICY -p tcp -m multiport --dports 80,443 -g CES_HTTP -m comment --comment "Jump to HTTP local chain"
iptables -t filter -A FILTER_SELF_POLICY -p udp              --dport 53      -g CES_DNS  -m comment --comment "Jump to DNS  local chain"
iptables -t filter -A FILTER_SELF_POLICY                                     -j ACCEPT   -m comment --comment "Accept"

# Set policy for DHCP traffic
## Add rate limitations ?
iptables -t filter -A CES_DHCP -m mark --mark $MASK_LAN_INGRESS   -p udp --sport 68 --dport 67 -j ACCEPT -m comment --comment "Accept DHCP"
iptables -t filter -A CES_DHCP -m mark --mark $MASK_LOCAL_INGRESS -p udp            --dport 67 -j DROP   -m comment --comment "Drop"
# Set policy for HTTP(S) traffic
## Add rate limitations ?
iptables -t filter -A CES_HTTP -m mark --mark $MASK_WAN_INGRESS   -p tcp --syn -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "Accept HTTP(S) @WAN"
iptables -t filter -A CES_HTTP -m mark --mark $MASK_LOCAL_INGRESS -p tcp       -m multiport --dports 80,443                            -j DROP   -m comment --comment "Drop"
# Set policy for DNS traffic
iptables -t filter -A CES_DNS -m mark --mark $MASK_WAN_INGRESS -p udp --dport 53 -j CES_DNS_WAN -m comment --comment "Continue in DNS WAN chain"
iptables -t filter -A CES_DNS -m mark --mark $MASK_LAN_INGRESS -p udp --dport 53 -j CES_DNS_LAN -m comment --comment "Continue in DNS LAN chain"
iptables -t filter -A CES_DNS -m mark --mark $MASK_TUN_INGRESS -p udp --dport 53 -j CES_DNS_TUN -m comment --comment "Continue in DNS TUN chain"


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
iptables -t filter -A CES_DNS_WAN_BLACKLIST -m set --match-set $DNS_BLACKLIST_IPSET src                     -j DROP -m comment --comment "Drop blacklist DNS source"
iptables -t filter -A CES_DNS_WAN_BLACKLIST -m u32 --u32 "28&0x0000F800=0x8000" -m conntrack --ctstate NEW  -j DROP -m comment --comment "DNS unexpected response"
#>> Disabled for testing
#iptables -t filter -A CES_DNS_WAN_BLACKLIST -m u32 --u32 "28&0x0000FF00=0x0100"                             -j DROP -m comment --comment "DNS recursive query"

## Drop blacklisted IP addresses or matching domains
#iptables -t filter -A CES_DNS_WAN_DOMAIN_LIMIT -m string --algo bm ! --hex-string "|0B|mysoarecord|03|ces|00|" -j DROP -m comment --comment "Drop !SOA record"
iptables -t filter -A CES_DNS_WAN_DOMAIN_LIMIT -m string --algo bm --hex-string $DNS_SOA1 -j RETURN -m comment --comment "Accept SOA record"
iptables -t filter -A CES_DNS_WAN_DOMAIN_LIMIT -m string --algo bm --hex-string $DNS_SOA2 -j RETURN -m comment --comment "Accept SOA record"
iptables -t filter -A CES_DNS_WAN_DOMAIN_LIMIT -j DROP -m comment --comment "Drop \!SOA allowed records"

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
## Example:
## iptables -t filter -A CES_DNS_LAN_BLACKLIST -m string --algo bm ! --hex-string "|07|youtube|03|com|00|" -j DROP -m comment --comment "Drop not SOA record"
## Apply global limit to WK-Greylist and Greylist
iptables -t filter -A CES_DNS_LAN_GLOBAL_LIMIT  -m hashlimit --hashlimit-upto 25/sec --hashlimit-burst 25 --hashlimit-name lan_dns  -j ACCEPT -m comment --comment "Accept LAN traffic"
iptables -t filter -A CES_DNS_LAN_GLOBAL_LIMIT                                                                                      -j DROP   -m comment --comment "Drop excess"

# Populate custom chain CES_DNS_TUN of FILTER table
iptables -t filter -A CES_DNS_TUN                                                                       -j DROP                     -m comment --comment "Drop DNS @TUN"
