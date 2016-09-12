import dns
import dns.message
import dns.zone
import dns.rcode

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

'''
#Hack for dnspython (1.14.0)) - Monkey patch to_text() function
import dns.name
try:
    dns.name.Name.to_text = dns.name.Name.to_unicode
except AttributeError:
    pass
'''
def debug_data(data):
    return('({} bytes) "{}"'.format(len(data), data))

def debug_data_addr(data, addr):
    return('{}:{} ({} bytes) "{}"'.format(addr[0], addr[1], len(data), data))

def debug_msg(dnsmsg):
    q = dnsmsg.question[0]
    return('{} {}/{} {}'.format(dnsmsg.id, q.name, dns.rdatatype.to_text(q.rdtype),dns.rcode.to_text(dnsmsg.rcode())))

def debug_msg_addr(dnsmsg, addr):
    q = dnsmsg.question[0]
    return('{}:{} {} {}/{} {}'.format(addr[0], addr[1], dnsmsg.id, q.name, dns.rdatatype.to_text(q.rdtype),dns.rcode.to_text(dnsmsg.rcode())))

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
        #assert (response.rcode() == dns.rcode.NOERROR)  # No Error
        assert ((response.flags & dns.flags.QR) ==
                dns.flags.QR)  # Message is response
        assert (len(response.question) == 1)  # Query contains 1 question
        assert (query.is_response(response))  # Valid response for query
    except Exception as e:
        print('Failed to sanitize DNS response: {}'.format(e))
        return False
    return True

def make_response_rcode(query, rcode = dns.rcode.NOERROR):
    response = dns.message.make_response(query, recursion_available=True)
    response.set_rcode(rcode)
    return response

def make_response_answer_rr(query, name, rdtype, target, rdclass=1, ttl=60):
    response = dns.message.make_response(query, recursion_available=True)
#    response.flags |= dns.flags.CD
    response.answer = [dns.rrset.from_text(name, ttl, rdclass, rdtype, target)]
    return response

def get_first_record(response):
    try:
        return '{}'.format(response.answer[0][0].to_text())
    except Exception as e:
        return None