# Introduction to CES (r)evolution 

This documents introduces the new framework for Customer Edge Switching (CES).
The system architecture has been redefined to improve performance.
The networking model is now fully based on iptables and OpenvSwitch for tunneling.

## Important Notes

iptables-extension list: http://manpages.ubuntu.com/manpages/trusty/man8/iptables-extensions.8.html
extensions to be considered:

* connlimit
* connmark
* cpu (For TCP Splice?)
* hashlimit
* limit
* mark
* recent
* physdev
* set (matching on ipset)
* tcpmss
* time
* statistics (nth match)
* string
* AUDIT
* CHECKSUM
* CONNMARK
* CT
* HMARK
* MIRROR - Removed from kernel
* NFQUEUE
* NFLOG?
* NOTRACK
* TCPMSS
* TEE
* TPROXY for TCPSplice?


## Networking Architecture

The following virtual network architecture has been devised to support the development
and testing of the CES platform.

### Virtual Networking

The model uses 3 different network interfaces with routing (Layer-3) capabilities.
* LAN: Connects to the private network where the local hosts are connected.
       e.g. 192.168.0.1/24
       e.g. 192.168.1.1/24
* WAN: Connects to the public network - Internet.
       e.g. 198.18.0.11/24 gateway: 198.18.0.1 - Circular Pool 198.18.0.[12-14]
       e.g. 198.18.0.21/24 gateway: 198.18.0.1 - Circular Pool 198.18.0.[22-24]
* TUN: Connects to the tunnel terminator (OpenvSwitch) for CES to CES communications.
       e.g. 1.1.1.1/32 NO ARP. Proxy Network 172.16.0.0/24 via tun-interface
       e.g. 1.1.1.2/32 NO ARP. Proxy Network 172.16.1.0/24 via tun-interface

### Network Interface Layout

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                NETWORK DIAGRAM FOR CUSTOMER EDGE SWITCHING V0.2                   +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+        LAN Network        |         TUN Network       |        WAN Network        +
+-----------------------------------------------------------------------------------+
+  l3-lana                  |  l3-tuna                  |  l3-wana                  |
+      |            (veth)  |      |            (veth)  |      |            (veth)  |
+  qve-l3-lana              |  qve-l3-tuna              |  qve-l3-wana              |
+     (+)                   |     (+)                   |     (+)                   |
+  qbf-lana          (br)   |  qbf-tuna          (br)   |  qbf-wana          (br)   |
+     (+)                   |     (+)                   |     (+)                   |
+  qve-phy-lana             |  qve-phy-tuna             |  qve-phy-wana             |
+      |            (veth)  |      |            (veth)  |      |            (veth)  |
+  qve-l2-lana              |  qve-l2-tuna              |  qve-l2-wana              |
+     (+)                   |     (+)                   |     (+)                   |
+  qbi-lana          (br)   |  qbi-tuna          (ovs)  |  qbi-wan           (br)   |
+-----------------------------------------------------------------------------------+

Minimal requirements:
* l3-xxxx: Layer-3 routing interfaces with IP addressing. Virtual Ethernet pair.
* qve-l3-xxxx: Layer-2 Virtual Ethernet pair connected to Linux bridge.
* qbf-xxxx: Layer-2 Linux bridge connecting qve-l3 with qve-phy. Used for packet filtering in iptables.
* qve-phy-xxxx: Layer-2 Virtual Ethernet pair. Represents the "physical" network card.

Extended requirements for virtualization in same host:
* qve-phy-xxxx: Layer-2 Virtual Ethernet pair connected to filtering Linux bridge.
* qve-l2-xxxx: Layer-2 Virtual Ethernet pair connected to integration Linux bridge.
* qbi-xxxx: Layer-2 Linux bridge connecting qve-l2 with qve-vhosts and network namespaces.



## Iptables 

### Iptables zones

There are a number of tweaks required in iptables for virtualizing several CES in the same machine without spawning Linux containers.
It would be possible to run the virtual CES in a Linux namespace, but certain iptables extensions do not appear to work properly, e.g. This 
is the case for TRACE(ing) packets and the LOG target.

To minimize the amount of tracked connections (conntrack), we will stop the tracking of packets in specific network interfaces.

Because the network architecture uses Linux bridges for packet filtering, we need to create different connection tracks when the packet flows through different interfaces.

Within a CES we make use of 2 different connection tracking zones "CT zone". 
- Zone 1: The packet enters via the Layer-3 routed interface l3-xxxx.
- Zone 2: The packet enters via the Layer-2 "physical" interface qve-phy-xxxx.

### Iptables chains

Depending on the input interface and tracking zone we will apply different rules.

Major packet filtering occurs when a packet enters the qbf-xxxx Linux bridge from a qve-phy-xxxx interface. This represents an incoming packet towards the CES.
The packet then traverses at least all iptables standard tables and chains, hitting a number of rules that may ACCEPT or DROP the packet, among other options.
If the incoming packet is ACCEPTed in the qbf-xxxx Linux bridge, it will continue it's way towards the Layer-3 routed interface l3-xxxx, where it will be processed
again by the kernel, this time entering a different connection track zone.


## Protecting Customer Edge Switching

### DNS

### Protecting DNS

The following chains apply in qbf-xxxx Linux bridge when an incoming packet is UDP port 53:

* WanBlacklist: Banned sources and/or domains.
  * Match IP source and DROP
  * Match (S)FQDN and DROP - Use string extension (include !string SOA record)
* WanWhitelist: Trusted sources with SLA, e.g. Elisa DNS. Accept traffic per SLA, report excess and leak to Greylist_WK.
  * [Match IP source] LIMIT and ACCEPT
  * [Match IP source] LIMIT and LOG - INFO
  * [Match IP source] LIMIT and JUMP to Greylist_WK
* WanGreylist_WK: Known sources with high traffic and no-SLA plus leaky bucket from Whitelist, e.g. Google DNS, Elisa DNS.
  * [Match IP source] LIMIT and RETURN
  * [Match IP source] LIMIT and LOG - INFO
  * [Match IP source] LIMIT and JUMP to Greylist
* WanGreylist: Unknown sources plus leaky bucket from Greylist_WK, e.g. Random DNS, Google DNS.
  * [Match IP source] LIMIT and RETURN
  * [Match IP source] LIMIT and LOG - INFO
  * [Match IP source] LIMIT and DROP
* WanGlobalLimit: Apply global rate limits for Greylist_WK and Greylist "accepted" traffic.
  * T1 LIMIT and ACCEPT (Max rate from non whitelist)
  * 1/sec LIMIT and LOG - WARN
  * T2 LIMIT and DROP
  * 1/sec LIMIT and LOG - WARN
  * T3 LIMIT and REJECT
  * 1/sec LIMIT and LOG - ERRO
  * T4 LIMIT and DROP
* WanDomainLimit: Apply specific domain rate limit. The chain can be called to apply limits for Whitelist, Greylist_WK and Greylist ipsets.
  * Match (S)FQDN and LIMIT and RETURN - Use string extension (include !string SOA record)
  * Match (S)FQDN and LIMIT and LOG - INFO
  * Match (S)FQDN and LIMIT and DROP - INFO
  
* LanBlacklist: Banned sources and/or domains.
  * Match IP source and DROP
  * Match (S)FQDN and DROP - Use string extension
* LanCESLimit: Apply global admision rate limit in LAN network.
  * Match IP source and LIMIT-75% and ACCEPT
  * Match IP source and LIMIT-1/s and LOG - INFO
  * Match IP source and 1/4th DROP
  * Match IP source and 1/4th REJECT
  * Match IP source and DROP and LOG - WARN
  
Processing pipeline for incoming DNS packets from WAN at the Filtering Bridge:

* Jump to WanBlacklist chain.
* Jump to WanDomainLimit chain. (Maybe this should be called from the Greylist chains only?)
* Match WanWhitelist_ipset and jump to WanWhitelist chain.
* Match WanGreylistWK_ipset and jump to WanGreylist_WK chain.
* !Match WanGreylistWK_ipset and jump to WanGreylist chain.
* Jump to WanGlobalLimit chain. (Packet can be ACCEPT, DROP or REJECT)

Processing pipeline for incoming DNS packets from LAN at the Filtering Bridge:
* Jump to LanBlacklist chain.
* Jump to LanCESLimit chain.


### Protecting HTTP Proxy



### Protecting from TCP SYN Spoofed Attacks

### Protecting from (D)DoS SYN Spoofed Attacks



# Misc notes

#NF_DROP vs NF_STOLEN
http://stackoverflow.com/questions/19342950/what-is-the-difference-between-nf-drop-and-nf-stolen-in-netfilter-hooks

sudo iptables -F OUTPUT

# Matching on packet content with STRING module
## FQDN in DNS are encoded following a specific pattern.
## The first byte (06) is the length of google, followed by the 6 ASCII characters, then a count byte (03) for the length of com followed by... 
## http://blog.nintechnet.com/how-to-block-w00tw00t-at-isc-sans-dfind-and-other-web-vulnerability-scanners/

sudo iptables -A OUTPUT -m string --algo bm --hex-string "|06|google|03|com" -j DROP

# Parental control matching on time of day with TIME module
## Note time goes in UTC time, so beware of the current time zone!
## http://www.cyberciti.biz/tips/iptables-for-restricting-access-by-time-of-day.html

sudo iptables -A OUTPUT -d 8.8.8.8/32 -m time --timestart 12:00:00 --timestop 12:59:59 -j DROP


# Using ebtables for ARP Response?
http://ebtables.netfilter.org/examples/basic.html#ex_arpreply
ebtables -t nat -A PREROUTING -p arp --arp-opcode Request -j arpreply \
--arpreply-mac 10:11:12:13:14:15 --arpreply-target ACCEPT

# If we want to let the packet go all the way
ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst 198.18.0.27 -j arpreply --arpreply-mac 10:11:12:13:14:15 --arpreply-target ACCEPT
# If we want to stop the packet at the given interface
ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst 198.18.0.28 -j arpreply --arpreply-mac 10:11:12:13:14:15 --arpreply-target DROP

