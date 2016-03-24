# Notes and links
#
## Drop vs Reject
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

## Enable NAT
iptables -t nat -A POSTROUTING -s $LAN_NET -j MASQUERADE

## Packet clasification with mark
iptables -t mangle -A PREROUTING -i $LAN_NIC  -j MARK --set-mark 0x1
iptables -t mangle -A PREROUTING -i $WAN_NIC  -j MARK --set-mark 0x2
iptables -t mangle -A PREROUTING -i $VTEP_NIC -j MARK --set-mark 0x3


# DEFINITION OF CES POLICIES
# Create DHCP_LAN chain
iptables -N DHCP_LAN
iptables -A DHCP_LAN -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A DHCP_LAN -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DHCP LAN: " --log-level 7
iptables -A DHCP_LAN -j REJECT
# Create DNS_LAN chain
iptables -N DNS_LAN
iptables -A DNS_LAN -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A DNS_LAN -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS LAN: " --log-level 3
iptables -A DNS_LAN -j REJECT
# Create DNS_WAN chain
iptables -N DNS_WAN
iptables -A DNS_WAN -m limit --limit 3/s --limit-burst 5 -j RETURN
iptables -A DNS_WAN -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS WAN: " --log-level 7
iptables -A DNS_WAN -j REJECT


# DEFINITION OF HOST POLICIES
# Create host 192.168.0.101 chains (base + services)
iptables -N HOST_192.168.0.101
iptables -N HOST_192.168.0.101_SERVICE1
iptables -N HOST_192.168.0.101_SERVICE2
iptables -N HOST_192.168.0.101_LEGACY

## Set host DNS policy
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 -p udp --dport 53 -m limit --limit 2/s --limit-burst 3 -j ACCEPT
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 -p udp --dport 53 -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "Exceeded DNS host: " --log-level 7
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 -p udp --dport 53 -j REJECT

## Legacy traffic - Maybe mark are a bit pedantic here
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 ! -d $PROXY_NET -j HOST_192.168.0.101_LEGACY
iptables -A HOST_192.168.0.101 -m mark --mark 0x2 ! -s $PROXY_NET -j HOST_192.168.0.101_LEGACY

## CES traffic - Maybe mark are a bit pedantic here
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 -d 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark 0x3 -s 172.16.0.1 -j HOST_192.168.0.101_SERVICE1
iptables -A HOST_192.168.0.101 -m mark --mark 0x1 -d 172.16.0.2 -j HOST_192.168.0.101_SERVICE2
iptables -A HOST_192.168.0.101 -m mark --mark 0x3 -s 172.16.0.2 -j HOST_192.168.0.101_SERVICE2

## Reject any other traffic
#iptables -A HOST_192.168.0.101 -j LOG --log-prefix "REJECT: " --log-level 7
iptables -A HOST_192.168.0.101 -j REJECT
# This looks better, but adds complexity - https://wiki.archlinux.org/index.php/Simple_stateful_firewall
#iptables -A HOST_192.168.0.101 -p udp -j REJECT --reject-with icmp-port-unreachable
#iptables -A HOST_192.168.0.101 -p tcp -j REJECT --reject-with tcp-reset
#iptables -A HOST_192.168.0.101 -j REJECT --reject-with icmp-proto-unreachable

## Define specific host policies per service
iptables -A HOST_192.168.0.101_LEGACY    -j ACCEPT
iptables -A HOST_192.168.0.101_SERVICE1  -j ACCEPT
iptables -A HOST_192.168.0.101_SERVICE2  -j ACCEPT



## CES LOCAL PROCESSING (INPUT chain)
## From LAN
### DNS
iptables -A INPUT -m mark --mark 0x1 -p udp --dport 53 -j DNS_LAN
iptables -A INPUT -m mark --mark 0x1 -p udp --dport 53 -d 192.168.0.101 -j HOST_192.168.0.101
### DHCP
iptables -A INPUT -m mark --mark 0x1 -p udp --sport 68 --dport 67 -j DHCP_LAN

## From WAN
### DNS
iptables -A INPUT -m mark --mark 0x2 -p udp --dport 53 -j DNS_WAN
### HTTP Proxy
iptables -A INPUT -m mark --mark 0x2 -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m mark --mark 0x2 -p tcp --dport 80  -m state --state NEW     -j ACCEPT
iptables -A INPUT -m mark --mark 0x2 -p tcp --dport 443 -m state --state NEW     -j ACCEPT


## CES FORWARDING PROCESSING (FORWARD chain)
### Apply outgoing DNS policy rate limit
iptables -A FORWARD -m mark --mark 0x1 -p udp --dport 53 -j DNS_LAN
### Match on host IP address
iptables -A FORWARD -m mark --mark 0x1 -s 192.168.0.101 -j HOST_192.168.0.101
iptables -A FORWARD -m mark --mark 0x2 -d 192.168.0.101 -j HOST_192.168.0.101
iptables -A FORWARD -m mark --mark 0x3 -d 192.168.0.101 -j HOST_192.168.0.101
## Alternatively
#iptables -A FORWARD -s 192.168.0.101 -j HOST_192.168.0.101
#iptables -A FORWARD -d 192.168.0.101 -j HOST_192.168.0.101

### Packet counter
#iptables -A FORWARD -j LOG --log-prefix "FORWARD.ACCEPT: " --log-level 7
iptables -A FORWARD -j ACCEPT


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
#
## Flush FILTER table and chains
#iptables -F INPUT
#iptables -F OUTPUT
#iptables -F FORWARDING
#iptables -F LOGnDROP
#iptables -F LOGnACCEPT
#iptables -F LOGnRETURN
#iptables -F DHCP_LAN
#iptables -F DNS_LAN
#iptables -F DNS_WAN
#iptables -F HOST_192.168.0.101
#iptables -F HOST_192.168.0.101_SERVICE1
#iptables -F HOST_192.168.0.101_SERVICE2
#iptables -F HOST_192.168.0.101_LEGACY
