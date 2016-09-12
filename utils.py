import socket
import sys
import traceback

# For Scapy packet parsing
#from scapy.all import *
#from scapy.layers.inet import *
#from scapy.layers.inet6 import *
# For custom packet parsing
import struct

def parse_packet_scapy(data):
    ret = {}
    ip = IP(data)
    ret['src'] = ip.src
    ret['dst'] = ip.dst
    ret['proto'] = ip.proto
    if ip.proto == 1:
        ret['type'] = ip.payload.type
        ret['code'] = ip.payload.code
    elif ip.proto == 6 or ip.proto == 17:
        ret['sport'] = ip.payload.sport
        ret['dport'] = ip.payload.dport
    return ret

def parse_packet_custom(data):
    ret = {}
    ret['src'] = socket.inet_ntoa(data[12:16])
    ret['dst'] = socket.inet_ntoa(data[16:20])
    ret['proto'] = data[9]
    proto = data[9]
    ihl = (data[0] & 0x0F) * 4  #ihl comes in 32 bit words (32/8)
    if proto == 1:
        ret['icmp-type'] = data[ihl]
        ret['icmp-code'] = data[ihl+1]
    elif proto == 6 or proto == 17 or proto == 132:
        ret['sport'] = struct.unpack('!H', (data[ihl:ihl+2]))[0]
        ret['dport'] = struct.unpack('!H', (data[ihl+2:ihl+4]))[0]
    return ret

def trace():
    print('Exception in user code:')
    print('-' * 60)
    traceback.print_exc(file=sys.stdout)
    print('-' * 60)

def is_ipv4(ipaddr):
    try:
        assert(socket.inet_pton(socket.AF_INET, ipaddr))
        return True
    except:
        return False

def is_ipv6(ipaddr):
    try:
        assert(socket.inet_pton(socket.AF_INET6, ipaddr))
        return True
    except:
        return False

def set_attributes(obj, **kwargs):
    for k,v in kwargs.items():
        #print('setattr({},{})'.format(k, v))
        setattr(obj, k, v)

def set_default_attributes(obj, args, value=None):
    for arg in args:
        if hasattr(obj, arg):
            continue
        setattr(obj, arg, value)
