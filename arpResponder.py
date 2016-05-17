#!/usr/bin/env python3

# Can be replaced with
# ebtables -t nat -A PREROUTING -p arp --arp-opcode 1 --arp-ip-dst 1.2.3.4 -j arpreply --arpreply-mac 00:00:00:12:34:56 --arpreply-target ACCEPT


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

import argparse
import sys
import socket


class ArpResponder(object):
    def __init__(self, iface, macddr, ipaddrs):
        print('Binding to interface {} with MAC {} and IPs {}'.format(iface, macddr, ','.join(ipaddrs)))
        self._iface = iface
        self._macddr = macddr
        self._ipaddrs = ipaddrs
        
    def callback(self, packet):
        arp = packet.getlayer(ARP)
        ipaddr_src = arp.psrc
        ipaddr_req = arp.pdst
        mac_src    = self._macddr
        
        if int(arp.op) != 1:
            # Process only ARP requests
            return
        if not ipaddr_req in self._ipaddrs:
            # Process only ARP requests in IP address pool
            return
        
        print('Replied to ARP request for IP address %s' % (ipaddr_req))
        reply = Ether(dst=arp.hwsrc) / ARP(hwsrc=mac_src, hwdst=arp.hwsrc, pdst=ipaddr_src, psrc=ipaddr_req, op=2)
        sendp(reply, iface=self._iface, verbose=False)

    def run(self):
        try:
            sniff(iface=self._iface, filter="arp", prn=self.callback)
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
    
def validate_nic(nic):
    assert(conf.L2listen(iface=nic))

def validate_mac(mac):
    assert(re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()))

def validate_ip(ips):
    for ip in ips:
        assert(socket.inet_pton(socket.AF_INET, ip))
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse IPs, MAC and network interface.')
    parser.add_argument("--nic")
    parser.add_argument("--mac")
    parser.add_argument("--ip", nargs='*')
    args = parser.parse_args()
    
    try:
        validate_nic(args.nic)
        validate_mac(args.mac)
        validate_ip(args.ip)
    except AssertionError:
        print('Run as: ./arpResponder.py --nic l3-wana --mac 00:00:00:00:01:bb --ip 198.18.0.21 198.18.0.22')
        exit()
    
    arp_responder = ArpResponder(args.nic, args.mac, args.ip)
    arp_responder.run()

