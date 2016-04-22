from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

import sys
import random

import hashlib

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
       
    def callback(self, pkt):
        data = pkt.get_payload()
        ip = IP(data)
        print('#{}: {}'.format(self.queue, ip.summary()))
        
        ipsrc, ipdst, psrc, pdst = ip.src, ip.dst, ip.payload.sport, ip.payload.dport
        tcp_flags = ip.payload.flags
        
        if tcp_flags == 0x02: #SYN
            cookie = self.generate_syn_cookie(ipsrc, ipdst, psrc, pdst)
            isn = 1
            # Craft response packet
            ip_response = IP(src=ipdst, dst=ipsrc)/TCP(sport=pdst, dport=psrc, seq=isn, ack=ip.payload.seq, window=0)
            # Add state
            self._syn_wan[(ipsrc, ipdst, psrc, pdst)] = ip.payload.seq
            
            send(ip_response)
            pkt.drop()
        
        elif tcp_flags == 0x12: #SYN,ACK
            pass
        
        else:
            pass
        
        #assert(ip.proto == 6)
        #pkt.set_mark(0xFFFFFFFE)
        
        pkt.accept()
        print('>> Set mark {}'.format(mark))
        
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
        print('sudo python{python3} netfilterqueuePRGW.py queueNum')
        print(sys.argv)
        sys.exit()
    
    nfrgw = NetfilterTcpSplice(int(nqueue))
    nfrgw.run()
