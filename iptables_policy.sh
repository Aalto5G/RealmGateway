# Notes and links
#
## DROP vs REJECT
## http://www.chiark.greenend.org.uk/~peterb/network/drop-vs-reject
#
## Reject with error code
## https://wiki.archlinux.org/index.php/Simple_stateful_firewall
#
#

# Definition of variables
VTEP_NIC="cesa-vetp"
WAN_NIC="cesa-wan"
LAN_NIC="cesa-lan"
LAN_NET="192.168.0.0/24"
PROXY_NET="172.16.0.0/24"

# Packet marks per interface
hMARK_OUT_LAN2LOCAL="0x4" #0b00100
hMARK_OUT_LAN2WAN="0x6"   #0b00110
hMARK_OUT_LAN2CES="0x7"   #0b00111
hMARK_IN_WAN2LOCAL="0x18" #0b11000
hMARK_IN_WAN2LAN="0x19"   #0b11001
hMARK_IN_CES2LAN="0x1d"   #0b11101

hMARK_INOUT_MASK="0x10"   #0b10000
hMARK_OUT_MASK="0x00"     #0b00000
hMARK_IN_MASK="0x10"      #0b10000


## Enable NAT
iptables -t nat -A POSTROUTING -s $LAN_NET -j MASQUERADE

## Packet clasification with mark in MANGLE table
### LAN & WAN
iptables -t mangle -A FORWARD -i $LAN_NIC   -s $LAN_NET ! -d $PROXY_NET -j MARK --set-mark $hMARK_OUT_LAN2WAN
iptables -t mangle -A FORWARD -i $WAN_NIC ! -s $PROXY_NET -d $LAN_NET   -j MARK --set-mark $hMARK_IN_WAN2LAN
### LAN & CES
iptables -t mangle -A FORWARD -i $LAN_NIC   -s $LAN_NET   -d $PROXY_NET -j MARK --set-mark $hMARK_OUT_LAN2CES
iptables -t mangle -A FORWARD -i $VTEP_NIC  -s $PROXY_NET -d $LAN_NET   -j MARK --set-mark $hMARK_IN_CES2LAN
### LAN & WAN via CES input
iptables -t mangle -A INPUT   -i $LAN_NIC                               -j MARK --set-mark $hMARK_OUT_LAN2LOCAL
iptables -t mangle -A INPUT   -i $WAN_NIC                               -j MARK --set-mark $hMARK_IN_WAN2LOCAL


# doREJECT table - https://wiki.archlinux.org/index.php/Simple_stateful_firewall
iptables -N doREJECT
iptables -A doREJECT -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECT -p tcp -j REJECT --reject-with tcp-reset
iptables -A doREJECT -j REJECT --reject-with icmp-proto-unreachable

# doREJECTnLOG table - https://wiki.archlinux.org/index.php/Simple_stateful_firewall
iptables -N doREJECTnLOG
iptables -A doREJECTnLOG -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "doREJECTnLOG: " --log-level 7
iptables -A doREJECTnLOG -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A doREJECTnLOG -p tcp -j REJECT --reject-with tcp-reset
iptables -A doREJECTnLOG -j REJECT --reject-with icmp-proto-unreachable


# DEFINITION OF BLACK & WHITE LISTS FOR ENHANCED PACKET FILTERING
iptables -N BLACKLIST_SOURCES
iptables -N WHITELIST_SOURCES
## Test
iptables -A BLACKLIST_SOURCES -s 192.168.0.102 -j doREJECT

# DEFINITION OF FIREWALL POLICIES TO PROTECT FROM ATTACKS
iptables -N FIREWALL_POLICY

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
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS LAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p tcp --dport 53 -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p tcp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS LAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p tcp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS WAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p udp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS WAN: " --log-level 7
iptables -A CES_POLICY_DNS -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp --dport 53 -j doREJECT
iptables -A CES_POLICY_DNS -j RETURN
### CES_POLICY_DHCP chain
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --sport 68 --dport 67 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --sport 68 --dport 67 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DHCP WAN: " --log-level 7
iptables -A CES_POLICY_DHCP -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --sport 68 --dport 67 -j doREJECT
iptables -A CES_POLICY_DHCP -j RETURN
### CES_POLICY_HTTP chain
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp -m state --state RELATED,ESTABLISHED -j RETURN
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp --dport 80  -m state --state NEW     -j RETURN
iptables -A CES_POLICY_HTTP -m mark --mark $hMARK_IN_WAN2LOCAL -p tcp --dport 443 -m state --state NEW     -j RETURN



# DEFINITION OF HOST POLICIES AND CHAINS

# HOST_POLICY - Specific host policies (e.g. legacy / CES services)
iptables -N HOST_POLICY
iptables -N HOST_192.168.0.101
iptables -N HOST_192.168.0.102
iptables -A HOST_POLICY -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -s 192.168.0.101 -j HOST_192.168.0.101
iptables -A HOST_POLICY -m mark --mark $hMARK_IN_MASK/$hMARK_INOUT_MASK  -d 192.168.0.101 -j HOST_192.168.0.101
iptables -A HOST_POLICY -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -s 192.168.0.102 -j HOST_192.168.0.102
iptables -A HOST_POLICY -m mark --mark $hMARK_IN_MASK/$hMARK_INOUT_MASK  -d 192.168.0.102 -j HOST_192.168.0.102


### EXAMPLE ###
# DEFINITION OF HOST POLICY for 192.168.0.101

# Create host 192.168.0.101 service chains related to CES connections
iptables -N HOST_192.168.0.101_SERVICE1
iptables -N HOST_192.168.0.101_SERVICE2

## Set host DNS policy
### Example of traffic type OUT for DNS over UDP
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2LOCAL for DNS over UDP - DNS requests to CES
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2LOCAL -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2WAN for DNS over UDP - DNS requests to public DNS server
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2WAN -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j RETURN
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2WAN -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2WAN -p udp --dport 53 -j doREJECT
### Example of traffic type LAN2WAN for SSH over TCP - Connecting to public SSH servers 
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2WAN -p tcp --dport 22 -j doREJECT
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_IN_WAN2LAN  -p tcp --dport 22 -j doREJECT

## CES traffic - Maybe mark are a bit pedantic here
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2CES -d 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_IN_CES2LAN  -s 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2CES -d 172.16.0.2 -j HOST_192.168.0.101_SERVICE2
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_IN_CES2LAN  -s 172.16.0.2 -j HOST_192.168.0.101_SERVICE2

## Reject unallocated outgoing traffic to PROXY_NET
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_LAN2CES -j doREJECT
## Accept any other outgoing traffic
iptables -A HOST_192.168.0.101 -m mark --mark $hMARK_OUT_MASK/$hMARK_INOUT_MASK -j RETURN

## Define specific host policies per service
iptables -A HOST_192.168.0.101_SERVICE1 -j RETURN
iptables -A HOST_192.168.0.101_SERVICE2 -j RETURN



## CES LOCAL PROCESS (INPUT chain)
iptables -A INPUT -j BLACKLIST_SOURCES   # Drop   if source is blacklisted
iptables -A INPUT -j WHITELIST_SOURCES   # Accept if source is whitelisted
iptables -A INPUT -j FIREWALL_POLICY     # Return if not an attack
iptables -A INPUT -j HOST_POLICY         # Return if the host policy was accepted
iptables -A INPUT -j CES_POLICY          # Return if the CES policy was accepted
iptables -A INPUT -j ACCEPT              # Accept traffic if not dropped previously


## CES FORWARDING PROCESS (FORWARD chain)
iptables -A FORWARD -j BLACKLIST_SOURCES # Drop   if source is blacklisted
iptables -A FORWARD -j WHITELIST_SOURCES # Accept if source is whitelisted
iptables -A FORWARD -j FIREWALL_POLICY   # Return if not an attack
iptables -A FORWARD -j HOST_POLICY       # Return if the host policy was accepted
iptables -A FORWARD -j CES_POLICY        # Return if the CES policy was accepted
iptables -A FORWARD -j ACCEPT            # Accept traffic if not dropped previously


###############################################################################################################################################################
###############################################################################################################################################################
###############################################################################################################################################################


## Debugging chains
## Create LOGnDROP chain
#iptables -N LOGnDROP
#iptables -A LOGnDROP -j LOG --log-prefix "LOGnDROP: " --log-level 7
#iptables -A LOGnDROP -j DROP
## Create LOGnACCEPT chain
#iptables -N LOGnACCEPT
#iptables -A LOGnACCEPT -j LOG --log-prefix "LOGnACCEPT: " --log-level 7
#iptables -A LOGnACCEPT -j ACCEPT
## Create LOGnRETURN chain
#iptables -N LOGnRETURN
#iptables -A LOGnRETURN -j LOG --log-prefix "LOGnRETURN: " --log-level 7
#iptables -A LOGnRETURN -j RETURN
#