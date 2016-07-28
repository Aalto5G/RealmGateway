#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

# Define variables
WAN0="eth0"
WAN0proxy="eth1"

# Setting up TCP SYNPROXY in NS-PROXY - ipt_SYNPROXY
# https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
sysctl -w net.ipv4.tcp_syncookies=1 # This is not available in the network namespace
sysctl -w net.ipv4.tcp_timestamps=1 # This is not available in the network namespace
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
# Disable sending ICMP redirects
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.lo.send_redirects=0
#sysctl -w net.ipv4.conf.$WAN0.send_redirects=0
# Configure iptables for SYNPROXY
iptables -t raw    -F
iptables -t raw    -A PREROUTING -i $WAN0 -p tcp -m tcp --syn -j CT --notrack
iptables -t filter -F
iptables -t filter -A FORWARD -i $WAN0 -o $WAN0proxy -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP
## Inline TCP SYNProxy: Enable arp_proxy to answer ARP for known routes (RealmGateway)
sysctl -w net.ipv4.conf.$WAN0.proxy_arp=1
sysctl -w net.ipv4.conf.$WAN0proxy.proxy_arp=1

