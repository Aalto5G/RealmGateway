import socket
import sys
import traceback

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
        setattr(obj, arg, value)