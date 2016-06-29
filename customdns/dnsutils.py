import dns
import dns.message
import dns.zone
import dns.rcode

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

def debug_data(data):
        return('({} bytes) "{}"'.format(len(data), data))

def debug_data_addr(data, addr):
        return('{}:{} ({} bytes) "{}"'.format(addr[0], addr[1], len(data), data))

def debug_msg(dnsmsg):
    q = dnsmsg.question[0]
    return('{} {}/{} {}'.format(dnsmsg.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype),dns.rcode.to_text(dnsmsg.rcode())))

def debug_msg_addr(dnsmsg, addr):
    q = dnsmsg.question[0]
    return('{}:{} {} {}/{} {}'.format(addr[0], addr[1], dnsmsg.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype),dns.rcode.to_text(dnsmsg.rcode())))

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

def _get_dummy(zone):
    return '{}.{}'.format('__secret', zone.origin.to_text())

def load_zone(zone_file, origin):
    return dns.zone.from_file(zone_file, origin, relativize=False)

def add_node(zone, name, rdtype, address, ttl=60):
    import dns.rdtypes.IN.A
    import dns.rdtypes.ANY.CNAME

    print('Add node {} {}'.format(name, address))
    assert(rdtype == A)

    # Make dns.name object
    dnsname = dns.name.from_text(name)
    if not zone.origin.is_superdomain(dnsname):
        dnsname = dns.name.from_text(name, zone.origin)

    # Create A record with given IP address
    rdataset = zone.find_rdataset(dnsname, rdtype, create=True)
    rdata = dns.rdtypes.IN.A.A(IN, A, address=address)
    rdataset.add(rdata, ttl=ttl)

    # Create CNAME record for NAPTR lookups
    target = dns.name.from_text(_get_dummy(zone))
    rdataset = zone.find_rdataset(dnsname, CNAME, create=True)
    rdata = dns.rdtypes.ANY.CNAME.CNAME(IN, CNAME, target)
    rdataset.add(rdata, ttl=ttl)

def delete_node(zone, name):
    try:
        print('Delete node {}'.format(name))
        # Make dns.name object
        dnsname = dns.name.from_text(name)
        if not zone.origin.is_superdomain(dnsname):
            dnsname = dns.name.from_text(name, zone.origin)
        del zone.nodes[dnsname]
    except Exception as e:
        print('Failed to delete node {}: {}'.format(name, e))


def make_response_rcode(query, rcode = dns.rcode.NOERROR):
    response = dns.message.make_response(query, recursion_available=True)
    response.set_rcode(rcode)
    return response

def make_response_answer_rr(query, name, rdtype, target, rdclass=1, ttl=60):
    response = dns.message.make_response(query, recursion_available=True)
    response.answer = [dns.rrset.from_text(name, ttl, rdclass, rdtype, target)]
    return response
