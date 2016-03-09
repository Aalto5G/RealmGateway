import socket

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