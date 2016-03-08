import dns

def sanitize_query(query):
    try:
        #assert (query.opcode() == dns.opcode.QUERY)  # Standard QUERY
        assert (query.rcode() == dns.rcode.NOERROR)  # No Error
        assert ((query.flags & dns.flags.QR) != dns.flags.QR)  # Message is query
        assert (len(query.question) == 1)  # Query contains 1 question
    except Exception as e:
        print('Failed to sanitize DNS query: {}'.format(e))
        return False
    return True


def sanitize_response(query, response):
    try:
        #assert (response.opcode() == dns.opcode.QUERY)  # Standard QUERY
        assert (response.rcode() == dns.rcode.NOERROR)  # No Error
        assert ((response.flags & dns.flags.QR) ==
                dns.flags.QR)  # Message is response
        assert (len(response.question) == 1)  # Query contains 1 question
        assert (query.is_response(response))  # Valid response for query
    except Exception as e:
        print('Failed to sanitize DNS response: {}'.format(e))
        return False
    return True

def is_ipv4(ipaddr):
    try:
        assert(dns.ipv4.inet_aton(ipaddr))
        return True
    except:
        return False
    
def is_ipv6(ipaddr):
    try:
        assert(dns.ipv6.inet_aton(ipaddr))
        return True
    except:
        return False

def hexify(data):
    """
    Obtain a hexadecimal representation of the data.
    
    @param data: The text to display. 
    """
    x = str(data)
    l = len(x)
    i = 0
    s = ''
    for i in range(0,l):
        s += '\\x%02X' % ord(x[i])
    s = '"%s"' % (s)
    return s