# Notes and links
#
## DROP vs REJECT
## http://www.chiark.greenend.org.uk/~peterb/network/drop-vs-reject
#
## Reject with error code
## https://wiki.archlinux.org/index.php/Simple_stateful_firewall
#
# Enable iptables TRACE:
## modprobe nf_log_ipv4 
## sysctl 'net.netfilter.nf_log.2=nf_log_ipv4'
## iptables -t raw -A OUTPUT -p icmp -j TRACE
## iptables -t raw -A PREROUTING -p icmp -j TRACE

# Definition of variables
LAN_NIC="l3-lana"
WAN_NIC="l3-wana"
TUN_NIC="l3-tuna"
BRIDGE_INTERFACES="qbf-lana qbf-wana qbf-tuna"

LAN_NET="192.168.0.0/24"
CPOOL_NET="100.64.0.21/32 100.64.0.22/32 100.64.0.23/32"
PROXY_NET="172.16.0.0/24"

# Packet marks per interface
hMARK_EGRESS_to_CES="0x4"       #0b00100
hMARK_EGRESS_to_WAN="0x6"       #0b00110
hMARK_EGRESS_to_TUN="0x7"       #0b00111
hMARK_INGRESS_to_CES="0x18"     #0b11000
hMARK_INGRESS_from_WAN="0x19"   #0b11001
hMARK_INGRESS_from_TUN="0x1d"   #0b11101
hMARK_MASK="0x10"               #0b10000
hMARK_EGRESS_MASK="0x00"        #0b00000
hMARK_INGRESS_MASK="0x10"       #0b10000


# doREJECT table - https://wiki.archlinux.org/index.php/Simple_stateful_firewall
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable


# doREJECTnLOG table - https://wiki.archlinux.org/index.php/Simple_stateful_firewall
iptables -N doREJECTnLOG
iptables -A doREJECTnLOG -m hashlimit --hashlimit-name doREJECTnLOG --hashlimit-upto 1/sec  --hashlimit-burst 1 --hashlimit-mode srcip,dstip -j LOG --log-prefix "doREJECTnLOG: " --log-level 7
iptables -A doREJECTnLOG -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECTnLOG -p tcp -j REJECT --reject-with tcp-reset
iptables -A doREJECTnLOG -j REJECT --reject-with icmp-proto-unreachable


# Configure raw PREROUTING for specific conntrack zones
## Note: Use conntrack zone 1 for default connection track and zone 2 for packet filtering via qbf-xyz
iptables -t raw -A PREROUTING -i $LAN_NIC -j CT --zone 1
iptables -t raw -A PREROUTING -i $WAN_NIC -j CT --zone 1
iptables -t raw -A PREROUTING -i $TUN_NIC -j CT --zone 1
for nic in $BRIDGE_INTERFACES
do
    iptables -t raw -A PREROUTING -i $nic -j CT --zone 2
done

## Note: for debugging, we could enable TRACE and --notrack on the other interfaces
#iptables -t raw -F PREROUTING
#iptables -t raw -A PREROUTING -i lo   -j CT --notrack
#iptables -t raw -A PREROUTING -i eth1 -j CT --notrack
#iptables -t raw -A PREROUTING -i eth0 -j CT --notrack
#iptables -t raw -A PREROUTING -i lo   -j ACCEPT
#iptables -t raw -A PREROUTING -i eth0 -j ACCEPT
#iptables -t raw -A PREROUTING -i eth1 -j ACCEPT

#iptables -t raw -A PREROUTING -j TRACE
#iptables -t raw -A PREROUTING -j ACCEPT


## Packet processing for Circular Pool
### Note: We can rate limit the number of packets that are sent to the Control Plane to prevent DoS
iptables -t mangle -A PREROUTING -m physdev --physdev-is-in -j ACCEPT
for ip in $CPOOL_NET
do
    iptables -t mangle -A PREROUTING -i $WAN_NIC -d $ip -m mark --mark 0x00 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 10 -m comment --comment "New connection to Circular Pool $ip"
done

### Note: Create new chain in nat table for Circular Pool connections and DNAT target with NEW conntrack state
iptables -t nat -N CIRCULAR_POOL
iptables -t nat -A PREROUTING -m mark ! --mark 0x00 -i $WAN_NIC -j CIRCULAR_POOL -m comment --comment "Continue to Circular Pool DNAT chain"
### Add rule per private host for DNAT operation
iptables -t nat -A CIRCULAR_POOL -m mark --mark 0xC0A80065 -i $WAN_NIC -j DNAT --to-destination 192.168.0.101 -m comment --comment "Forward to 192.168.0.101"
iptables -t nat -A CIRCULAR_POOL -m mark --mark 0xC0A80066 -i $WAN_NIC -j DNAT --to-destination 192.168.0.102 -m comment --comment "Forward to 192.168.0.102"
iptables -t nat -A CIRCULAR_POOL -m mark --mark 0xC0A80067 -i $WAN_NIC -j DNAT --to-destination 192.168.0.103 -m comment --comment "Forward to 192.168.0.103"


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


# DEFINITION OF CES POLICIES AND CHAINS

# CES_POLICY - System wide policies (e.g. DHCP / DNS / HTTP Proxy)
iptables -N CES_POLICY
iptables -N CES_POLICY_DNS
iptables -N CES_POLICY_DHCP
iptables -N CES_POLICY_HTTP
iptables -A CES_POLICY -j CES_POLICY_DNS
iptables -A CES_POLICY -j CES_POLICY_DHCP
iptables -A CES_POLICY -j CES_POLICY_HTTP

## Add rules to service chains
### CES_POLICY_DNS chain
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS LAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p tcp --dport 53 -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p tcp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS LAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p tcp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS WAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p udp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p tcp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p tcp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS WAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_INGRESS_to_CES -p tcp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -j RETURN
### CES_POLICY_DHCP chain
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_EGRESS_to_CES -p udp --sport 68 --dport 67 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_EGRESS_to_CES -p udp --sport 68 --dport 67 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DHCP WAN: " --log-level 7
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_EGRESS_to_CES -p udp --sport 68 --dport 67 -j doREJECT
iptables -A CES_POLICY_DHCP -j RETURN
### CES_POLICY_HTTP chain
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_INGRESS_to_CES -p tcp -m state --state RELATED,ESTABLISHED -j RETURN
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_INGRESS_to_CES -p tcp --dport 80  -m state --state NEW     -j RETURN
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_INGRESS_to_CES -p tcp --dport 443 -m state --state NEW     -j RETURN



# DEFINITION OF HOST POLICIES AND CHAINS

# HOST_POLICY - Specific host policies (e.g. legacy / CES services)
iptables -N HOST_POLICY
iptables -N HOST_192.168.0.101
iptables -N HOST_192.168.0.102
iptables -A HOST_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -s 192.168.0.101 -j HOST_192.168.0.101
iptables -A HOST_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -d 192.168.0.101 -j HOST_192.168.0.101
iptables -A HOST_POLICY -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK  -s 192.168.0.102 -j HOST_192.168.0.102
iptables -A HOST_POLICY -m mark --mark $hMARK_INGRESS_MASK/$hMARK_MASK -d 192.168.0.102 -j HOST_192.168.0.102


### EXAMPLE ###
# DEFINITION OF HOST POLICY for 192.168.0.101

# Create host 192.168.0.101 service chains related to CES connections
iptables -N HOST_192.168.0.101_SERVICE1
iptables -N HOST_192.168.0.101_SERVICE2

## Set host DNS policy
### Example of traffic type OUT for DNS over UDP
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2LOCAL for DNS over UDP - DNS requests to CES
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_CES -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_CES -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_CES -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2WAN for DNS over UDP - DNS requests to public DNS server
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_WAN -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_WAN -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_WAN -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2WAN for SSH over TCP - Connecting to public SSH servers
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_WAN -p tcp --dport 22 -j doREJECT
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_INGRESS_from_WAN  -p tcp --dport 22 -j doREJECT

## CES traffic - Maybe mark are a bit pedantic here
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_TUN    -d 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_INGRESS_from_TUN -s 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_TUN    -d 172.16.0.2 -j HOST_192.168.0.101_SERVICE2
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_INGRESS_from_TUN -s 172.16.0.2 -j HOST_192.168.0.101_SERVICE2

## Reject unallocated outgoing traffic to PROXY_NET
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_to_TUN -j doREJECT
## Accept any other outgoing traffic
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_EGRESS_MASK/$hMARK_MASK -j RETURN

## Define specific host policies per service
iptables -A HOST_192.168.0.101_SERVICE1 -j RETURN
iptables -A HOST_192.168.0.101_SERVICE2 -j RETURN


# Definition of BLACKLIST & WHITELIST for enhanced packet filtering
iptables -N BLACKLIST_SOURCES
iptables -N WHITELIST_SOURCES
## Test
#iptables -A BLACKLIST_SOURCES -s 192.168.0.102 -j doREJECT
#iptables -A WHITELIST_SOURCES -s 192.168.0.101 -j ACCEPT


## CES LOCAL PROCESS (INPUT chain)
#iptables -A INPUT -j BLACKLIST_SOURCES                           # Drop   if source is blacklisted
#iptables -A INPUT -j WHITELIST_SOURCES                           # Accept if source is whitelisted
#iptables -A INPUT -j FIREWALL_POLICY                             # Return if not an attack
iptables -A INPUT -m mark ! --mark 0x00 -j HOST_POLICY           # Return if the host policy was accepted
iptables -A INPUT -m mark ! --mark 0x00 -j CES_POLICY            # Return if the CES policy was accepted
iptables -A INPUT -j ACCEPT                                      # Accept traffic if not dropped previously


## CES FORWARDING PROCESS (FORWARD chain)
iptables -I FORWARD 1 -j BLACKLIST_SOURCES                       # Drop   if source is blacklisted - Insert at position 1
iptables -I FORWARD 2 -j WHITELIST_SOURCES                       # Accept if source is whitelisted - Insert at position 2
#iptables -A FORWARD -j FIREWALL_POLICY                           # Return if not an attack
iptables -A FORWARD -m mark ! --mark 0x00 -j HOST_POLICY         # Return if the host policy was accepted
iptables -A FORWARD -m mark ! --mark 0x00 -j CES_POLICY          # Return if the CES policy was accepted
iptables -A FORWARD -j ACCEPT                                    # Accept traffic if not dropped previously


## Enable NAT
#iptables -t nat -A POSTROUTING -m physdev --physdev-is-bridged  -j ACCEPT -m comment --comment "Traffic from bridged interface"
#iptables -t nat -F
#iptables -t nat -I POSTROUTING -o lo -j ACCEPT
#iptables -t nat -I POSTROUTING -o eth0 -j ACCEPT
#iptables -t nat -I POSTROUTING -o eth1 -j ACCEPT

#iptables -t nat -A POSTROUTING -m mark ! --mark 0x00 -j LOG --log-level 7 --log-prefix "nat.POST: mark!=0 "
#iptables -t nat -A POSTROUTING -m mark   --mark 0x00 -j LOG --log-level 7 --log-prefix "nat.POST: mark==0 "
iptables -t nat -A POSTROUTING -m mark --mark $hMARK_EGRESS_to_WAN -s $LAN_NET -j SNAT --to-source 100.64.0.11 -m comment --comment "Outgoing SNAT to 100.64.0.11"



# Testing TCP Splice
iptables -t mangle -I FORWARD -i $WAN_NIC -o $LAN_NIC -m mark ! --mark 0x00 -m tos --tos 0x04 -m conntrack  --ctstate NEW,DNAT   -j LOG --log-level 7 --log-prefix "mangle.fwd: tos 0x04 "
iptables -t mangle -I FORWARD -i $WAN_NIC -o $LAN_NIC -m mark ! --mark 0x00 -m conntrack --ctstate NEW,DNAT   -j LOG --log-level 7 --log-prefix "mangle.fwd: NEW,DNAT "
iptables -t mangle -I FORWARD -i $WAN_NIC -o $LAN_NIC -m mark ! --mark 0x00 -m conntrack --ctstate NEW,DNAT   -j TOS --set-tos 0x04 -m comment --comment "mangle.fwd: set-tos "

iptables -t mangle -I PREROUTING -i $WAN_NIC -j CONNMARK --restore-mark
iptables -t mangle -I PREROUTING -i $LAN_NIC -j CONNMARK --restore-mark
#iptables -A POSTROUTING -p tcp --dport 80 -t mangle -j MARK --set-mark 2
iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark



###############################################################################################################################################################
###############################################################################################################################################################
###############################################################################################################################################################

# Debugging
# Enable iptables TRACE:
## sysctl 'net.netfilter.nf_log.2=nf_log_ipv4'
## iptables -t raw -A OUTPUT -p icmp -j TRACE
## iptables -t raw -A PREROUTING -p icmp -j TRACE
#
# sudo iptables -t raw -A PREROUTING -i lo   -j ACCEPT
# sudo iptables -t raw -A PREROUTING -i eth0 -j ACCEPT
# sudo iptables -t raw -A PREROUTING -i eth1 -j ACCEPT
# sudo iptables -t raw -A PREROUTING -j TRACE
# sudo iptables -t raw -A PREROUTING -j ACCEPT
#