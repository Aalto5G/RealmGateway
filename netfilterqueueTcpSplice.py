#!/usr/bin/env python3
import sys
import random
import hashlib

from netfilterqueue import NetfilterQueue

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *


class NetfilterTcpSplice(object):
    def __init__(self, queue):
        print('Binding to queue {}'.format(queue))
        self.queue = queue
        self._nfqueue = NetfilterQueue()
        self._nfqueue.bind(queue, self.callback)
        
        self._secret= 'mySecret'
        
        self._syn_wan = {}
        self._syn_lan = {}
        self._established = {}
        
    def _wan_syn_recv1(self, pkt, ip_r):
        #print('_do_wan_syn_recv1')
        eth = Ether(src='00:00:00:00:01:bb', dst='00:00:c6:12:00:65') / ip_r
        sendp(eth, iface='qve-phy-wana', verbose=False)
        print('\t>> {}'.format(ip_r.summary()))
        pkt.drop()
    
    def _wan_syn_recv2(self, pkt, ip_r):
        """
        This does not work because we cannot send the mangled packet back the same interface
        """
        #print('_do_wan_syn_recv2')
        pkt.set_payload(bytes(ip_r))
        print('\t>> {}'.format(ip_r.summary()))
        #mark = pkt.get_mark()
        # Set mark for DEBUG
        #pkt.set_mark(mark | 0x20)
        #pkt.repeat()
        pkt.accept()
    
    def _wan_synack_recv1(self, pkt, ip_r):
        #print('_wan_synack_recv1')
        eth = Ether(src='00:00:c6:12:00:65', dst='00:00:00:00:01:bb') / ip_r
        sendp(eth, iface='qve-l3-wana', verbose=False)
        print('\t>> {}'.format(ip_r.summary()))
        pkt.drop()
    
    def _wan_synack_recv2(self, pkt, ip_r):
        #print('_wan_synack_recv2')
        pkt.set_payload(bytes(ip_r))
        print('\t>> {}'.format(ip_r.summary()))
        # Set mark for CONNMARK
        #mark = pkt.get_mark()
        pkt.set_mark(0x222)
        pkt.accept()
        
    def callback(self, pkt):
        data = pkt.get_payload()
        ip = IP(data)
        
        print('#{}: {}'.format(self.queue, ip.summary()))
        assert(ip.proto == 6)
        ipsrc, ipdst, tcp = ip.src, ip.dst, ip.payload
        psrc, pdst, flags =  tcp.sport, tcp.dport, tcp.flags
        
        # Filter packet mark
        mark = pkt.get_mark()
        
        if (mark & 0xFF == 0x02):
            #print('MARK WanToLan')
            
            if flags == 0x02: #SYN
                print('WAN: SYN_RECV')
                
                ipsrc, ipdst, tcp = ip.src, ip.dst, ip.payload
                psrc, pdst, flags =  tcp.sport, tcp.dport, tcp.flags
                #cookie = self.generate_syn_cookie(ipsrc, ipdst, psrc, pdst)
                isn = 1
                
                if (ipsrc, ipdst, psrc, pdst) in self._syn_wan:
                    print('WAN: SYN_RECV skipping rtx packet')
                    pkt.drop()
                    return
                
                # Add state
                self._syn_wan[(ipsrc, ipdst, psrc, pdst)] = ('SYN_RECV', ip, tcp.seq, isn)
                # Option 1 - Drop packet and  sendp() with crafted Ethernet response
                tcp_r = TCP(sport=pdst, dport=psrc, flags="SA", seq=isn, ack=tcp.seq+1, window=0)
                ip_r = IP(src=ipdst, dst=ipsrc) / tcp_r
        
                # Receive SYN and send SYN,ACK via L2 raw socket
                self._wan_syn_recv1(pkt, ip_r)
                # Receive SYN and send SYN,ACK via packet mangling (Fails to send via the incoming interface)
                ## This does not work! Maybe with REJECT like behaviour, we could send something back.
                #self._wan_syn_recv2(pkt, ip)
                return
            
            elif flags == 0x10: #ACK
                
                # Get original packet from sender
                try:
                    (status, orig_ip, orig_seq, my_isn) = self._syn_wan[(ipsrc, ipdst, psrc, pdst)]
                except:
                    print('WAN: ACK unknown')
                    pkt.drop()
                    return
                
                if status == 'SYN_RECV':
                    # Up to this point we don't have any state in conntrack
                    print('WAN: ESTABLISHED')
                    self._syn_wan[(ipsrc, ipdst, psrc, pdst)] = ('ESTABLISHED', orig_ip, orig_seq, my_isn)
                else:
                    print('WAN: %s DATA STREAM' % status)
                
                #Validate response...
                # Send TCP SYN to Circular Pool
                ip_r = IP(src=ipsrc, dst=ipdst) / TCP(sport=psrc, dport=pdst, flags='S', seq=orig_seq, window=0)
                
                # Receive SYN,ACK and send SYN via L2 raw socket
                #self._wan_synack_recv1(pkt, ip_r)
                # Receive SYN,ACK and send SYN via packet mangling. Set MARK in packet for CONNMARK
                self._wan_synack_recv2(pkt, ip_r)
                return
        
        
        elif (mark & 0xFF == 0x12):
            #print('MARK LanToWan')
            if flags == 0x12: #SYN,ACK
                print('LAN: SYN,ACK_RECV')
                
                
                if (ipdst, ipsrc, pdst, psrc) not in self._syn_lan:
                    print('LAN: SYN,ACK unknown')
                
                # Up to this point we have created SYN_RECV state in CT 1 and CT 2
                #tcp      6 44 SYN_RECV src=198.18.0.101 dst=198.18.0.21 sport=54638 dport=4567 src=192.168.0.101 dst=198.18.0.101 sport=4567 dport=54638 mark=0 zone=1 use=1
                
                return
            
                # Craft response packet
                tcp_r = TCP(sport=pdst, dport=psrc, flags='A', seq=isn, ack=tcp.seq+1, window=0)
                ip_r = IP(src=ipdst, dst=ipsrc) / tcp_r
                eth = Ether(src='00:00:00:00:01:bb', dst='00:00:c6:12:00:65') / ip_r
                sendp(eth, iface='qve-phy-wana', verbose=False)

                print('\t>> {}'.format(ip_r.summary()))
                pkt.drop()
                return
    def run(self):
        try:
            self._nfqueue.run()
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
        self._nfqueue.unbind()
        
    def generate_syn_cookie(self, src_ip, dest_ip, src_port, dest_port):
        """ Function to generate cookie.
        Cookie Algorithm:    time.time() (5-bits) + Reserved (3-bits) + Hash(src_ip, dest_ip, src_port, dest_port, secret)) )[4:]
        """
        secret = self._secret
        text = str(src_ip) + str(dest_ip)+ str(src_port) + str(dest_port) + secret
        #md_hash = MD5.new(text).digest()
        
        md_hash = hashlib.md5(text.encode()).digest()
        
        mod32_time = bin(int(time.time())).split('0b')[1]
        cookie_head = int(mod32_time[21:26], 2) * 8 + 0             # Mod-32 of current time ~ Removes the last 5 bits.   3 Reserved bits inserted via 3-left shifts, (e.g. multiplying by 8)
        #cookie_head = int( bin(   int(time.time()) )[21:26], 2) * 8 + 0         # Mod-32 of current time ~ Removing last 5 bits,  3 reserved
        encoded = struct.pack('!B', cookie_head) + md_hash[-3:]
        syn_cookie=struct.unpack('!I', encoded)[0]
        return syn_cookie
    
    def verify_syn_cookie(self, syn_cookie, src_ip, dest_ip, src_port, dest_port, bot_test=False):
        """ Verify the received SYN-cookie against the received parameters"""
        decoded=struct.pack('!I', syn_cookie)
        
        '''
        cookie_time=struct.unpack('!B', decoded[0:1])[0]        
        mod32_time = bin(int(time.time())).split('0b')[1]
        
        current_cycle = int(mod32_time[21:26], 2)                    # Essentially, this time value increments after 64sec, as per RFC 4987
        previous_cycle = int(mod32_time[21:26],2)-1                  # Care for 0 ~ {(32)mod-32}, -1 case
        if previous_cycle == -1:
            previous_cycle = 31
        
        "The following checks if the Cookie belongs to either this (or previous) time-cycle??"        # This prevents false alarm, for the case when original cookie was generated at edge of the Mod-32 time cycle.
        if not ((cookie_time/8 == current_cycle) or (cookie_time/8 == previous_cycle)):
            self.logger.info("Expired cookie: The sender is attempting Spoofing/Replay Attack??")
            return False
        '''
        
        cookie_hash = decoded[-3:]
        secret = self._secret
        text = str(src_ip) + str(dest_ip)+ str(src_port) + str(dest_port) + secret
        
        #md_hash = MD5.new(text).digest()[-3:]
        md_hash = hashlib.md5(text.encode()).digest()[-3:]
        
        if md_hash == cookie_hash:
            print("Inbound cookie is valid, Sender is non-spoofed")
            return True
        else:
            print("Expired cookie: The sender is attempting Spoofing/Replay attack")
            return False
        
if __name__ == '__main__':
    try:
        nqueue = sys.argv[1]
    except Exception as e:
        print('sudo python{python3} netfilterqueueTcpSplice.py queueNum')
        print(sys.argv)
        sys.exit()

    nfrgw = NetfilterTcpSplice(int(nqueue))
    nfrgw.run()
