#!/usr/bin/env python3
import dns
import dns.message
import dns.name
import dns.edns
import dns.zone
import dns.rcode
import dns.rdatatype
import dns.inet
import dns.query

import struct
import math

'''
EDNS0 extension encoding TLV like:
    16 bits: Option Code
    16 bits: Option Length (length of data)
    n bits:  Option Data
'''

ENSID = 3
class EDNS0_ENSIDOption(dns.edns.Option):
    """DNS Name Server Identifier (NSID, RFC5001)"""
    def __init__(self, data):
        super(EDNS0_ENSIDOption, self).__init__(ENSID)
        self.data = data

    def to_wire(self, file):
        file.write(self.data)

    def to_text(self):
        #return "Generic %d" % self.otype
        return 'NSID {}'.format(self.data)

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        return cls(wire[current: current + olen])

    def _cmp(self, other):
        if self.data == other.data:
            return 0
        if self.data > other.data:
            return 1
        return -1

ECS = 8
class EDNS0_ECSOption(dns.edns.Option):
# Currently copied from official Github repo until included in the next release
    """EDNS Client Subnet (ECS, RFC7871)"""

    def __init__(self, address, srclen=None, scopelen=0):
        """*address*, a ``text``, is the client address information.
        *srclen*, an ``int``, the source prefix length, which is the
        leftmost number of bits of the address to be used for the
        lookup.  The default is 24 for IPv4 and 56 for IPv6.
        *scopelen*, an ``int``, the scope prefix length.  This value
        must be 0 in queries, and should be set in responses.
        """

        super(EDNS0_ECSOption, self).__init__(ECS)
        af = dns.inet.af_for_address(address)

        if af == dns.inet.AF_INET6:
            self.family = 2
            if srclen is None:
                srclen = 56
        elif af == dns.inet.AF_INET:
            self.family = 1
            if srclen is None:
                srclen = 24
        else:
            raise ValueError('Bad ip family')

        self.address = address
        self.srclen = srclen
        self.scopelen = scopelen

        addrdata = dns.inet.inet_pton(af, address)
        nbytes = int(math.ceil(srclen/8.0))

        # Truncate to srclen and pad to the end of the last octet needed
        # See RFC section 6
        self.addrdata = addrdata[:nbytes]
        nbits = srclen % 8
        if nbits != 0:
            last = struct.pack('B', ord(self.addrdata[-1:]) & (0xff << nbits))
            self.addrdata = self.addrdata[:-1] + last

    def to_text(self):
        return 'ECS {}/{} scope/{}'.format(self.address, self.srclen, self.scopelen)

    def to_wire(self, file):
        file.write(struct.pack('!H', self.family))
        file.write(struct.pack('!BB', self.srclen, self.scopelen))
        file.write(self.addrdata)

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        family, src, scope = struct.unpack('!HBB', wire[cur:cur+4])
        cur += 4

        addrlen = int(math.ceil(src/8.0))

        if family == 1:
            af = dns.inet.AF_INET
            pad = 4 - addrlen
        elif family == 2:
            af = dns.inet.AF_INET6
            pad = 16 - addrlen
        else:
            raise ValueError('unsupported family')

        addr = dns.inet.inet_ntop(af, wire[cur:cur+addrlen] + b'\x00' * pad)
        return cls(addr, src, scope)

    def _cmp(self, other):
        if self.addrdata == other.addrdata:
            return 0
        if self.addrdata > other.addrdata:
            return 1
        return -1

ECI = 0xFF01
class EDNS0_EClientInfoOption(dns.edns.Option):
    """
    EDNS Client Information (own development)
        * Client Information (0xFF01) (Encoded lenght 80 0x50 for IPv4 and 176 0xb0 for IPv6)
        -> 16 bits: Client Address Family (1 for IPv4, 2 for IPv6, x for custom UniqueLocalHostIdentifier)
        -> n  bits: Client Address
        -> 16 bits: Client Protocol
        -> 16 bits: Client Transaction ID
    """

    def __init__(self, address, protocol=17, query_id=0):
        super(EDNS0_EClientInfoOption, self).__init__(ECI)
        af = dns.inet.af_for_address(address)

        if af == dns.inet.AF_INET6:
            self.family = 2
        elif af == dns.inet.AF_INET:
            self.family = 1
        else:
            raise ValueError('Bad ip family')

        self.address = address
        self.protocol = protocol
        self.query_id = query_id
        self.addrdata = dns.inet.inet_pton(af, address)

    def to_text(self):
        return 'ECI source/{} proto/{} query_id/{}'.format(self.address, self.protocol, self.query_id)

    def to_wire(self, file):
        file.write(struct.pack('!H', self.family))
        file.write(self.addrdata)
        file.write(struct.pack('!HH', self.protocol, self.query_id))

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        family = struct.unpack('!H', wire[cur:cur+2])[0]
        cur += 2

        if family == 1:
            af = dns.inet.AF_INET
            addrlen = 4
        elif family == 2:
            af = dns.inet.AF_INET6
            addrlen = 16
        else:
            raise ValueError('unsupported family')

        addr = dns.inet.inet_ntop(af, wire[cur:cur+addrlen])
        cur += addrlen
        protocol, query_id = struct.unpack('!HH', wire[cur:cur+4])
        return cls(addr, protocol, query_id)

    def _cmp(self, other):
        if self.addrdata == other.addrdata and self.protocol == other.protocol and self.query_id == query_id:
            return 0
        return -1

ECID = 0xFF02
class EDNS0_EClientID(dns.edns.Option):
    """
    EDNS Client Identification (own development)
        * Client ID (0xFF02)
            -> n  bits: Client ID (ID generated by resolving server)
    """

    def __init__(self, id_data):
        super(EDNS0_EClientID, self).__init__(ECID)
        self.id_data = id_data

    def to_text(self):
        return 'ECID id/{}'.format(self.id_data)

    def to_wire(self, file):
        file.write(self.id_data)

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        id_data = wire[cur:cur+olen]
        return cls(id_data)

    def _cmp(self, other):
        if self.id_data == other.id_data:
            return 0
        if self.id_data > other.id_data:
            return 1
        return -1


EDR = 0xFF03
class EDNS0_EDomainRate(dns.edns.Option):
    """
    EDNS Rate Limitation (own development)
        -> Notes: We can match FQDN/subdomains exactly at the begining of the name record, after the fixed DNS header (12 bytes)
        -> If the extension is present in a QUERY, then we ask whether a domain/subdomain is rate limited and can be enforced locally.
           If the extension is present in a RESPONSE, the remote server indicates the local rate limitation that should be applied.
           The presense of this extension is conditioned to a request in a QUERY message.
        -> n  bits: Domain/Subdomain DNS encoded
        -> 32 bits: Average match rate
        -> 16 bits: Rate time unit (msec, sec, minute, hour, day)
        -> 32 bits: TTL (TTL=0 means limitation has expired)
    # Include BURST ?
    """
    _units_from_text = {
                        'psec':0x01,
                        'nsec':0x02,
                        'usec':0x03,
                        'msec':0x04,
                        'sec' :0x05,
                        'min' :0x06,
                        'hour':0x07,
                        'day': 0x08
                        }
    _units_from_int = {
                        0x01:'psec',
                        0x02:'nsec',
                        0x03:'usec',
                        0x04:'msec',
                        0x05:'sec' ,
                        0x06:'min' ,
                        0x07:'hour',
                        0x08:'day'
                        }

    def __init__(self, fqdn, rate, unit, ttl):
        super(EDNS0_EDomainRate, self).__init__(EDR)
        # Normalize domain name
        self.fqdn = dns.name.from_text(fqdn).to_text()
        self.rate = rate
        self.unit = unit
        self.ttl = ttl

    def to_text(self):
        return 'EDR name/{} rate/{}/{} ttl/{}'.format(self.fqdn, self.rate, self.unit, self.ttl)

    def to_wire(self, file):
        _name = dns.name.from_text(self.fqdn).to_wire()
        _unit = EDNS0_EDomainRate._units_from_text[self.unit]
        file.write(_name)
        file.write(struct.pack('!IHI', self.rate, _unit, self.ttl))

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        # Calculate name length based on
        name, n = dns.name.from_wire(wire, cur)
        rate, unit, ttl = struct.unpack('!IHI', wire[cur+n:cur+olen])
        _name = name.to_text()
        _unit = EDNS0_EDomainRate._units_from_int[unit]
        return cls(_name, rate, _unit, ttl)

    def _cmp(self, other):
        if self.fqdn == other.fqdn and self.rate == other.rate and self.unit == other.unit and self.ttl == other.ttl:
            return 0
        return -1

# Add extensions to dnspython dns.edns module
dns.edns._type_to_class[ENSID] = EDNS0_ENSIDOption
dns.edns._type_to_class[ECS]   = EDNS0_ECSOption
dns.edns._type_to_class[ECI]   = EDNS0_EClientInfoOption
dns.edns._type_to_class[ECID]  = EDNS0_EClientID
dns.edns._type_to_class[EDR]   = EDNS0_EDomainRate
'''
dns.edns._type_to_class = {
    ENSID: EDNS0_ENSIDOption,
    ECS:   EDNS0_ECSOption,
    ECI:   EDNS0_EClientInfoOption,
    ECID:  EDNS0_EClientID,
    EDR:   EDNS0_EDomainRate
}
'''

def fqdn_ipt_match(domain):
    # http://stackoverflow.com/questions/12638408/decorating-hex-function-to-pad-zeros
    data = ''
    if not domain.endswith('.'):
        domain += '.'
    for token in domain.split('.'):
        data += '|{0:0{1}x}|{2}'.format(len(token),2, token)
    return data

def ipt_build_match_domain(domain, mtype = 'DOMAIN_ONLY'):
    """
    mtype choices: 'DOMAIN_ONLY', 'SUBDOMAIN_ONLY', 'DOMAIN_SUBDOMAIN', 'LABEL', 'CONTAINS'

    #1. Matching of both domain and subdomains
    sudo iptables -t filter -A OUTPUT -p udp --dport 53  -m string --algo bm --hex-string "|07|example|03|com|00|" --from 40 --to 295 -m comment --comment "Match both domain and subdomains"

    #2. Matching of exact domain only
    sudo iptables -t filter -A OUTPUT -p udp --dport 53  -m string --algo bm --hex-string "|07|example|03|com|00|" --from 40 --to 41  -m comment --comment "Match domain only example.com."

    #3. Matching of subdomains only
    sudo iptables -t filter -A OUTPUT -p udp --dport 53  -m string --algo bm --hex-string "|07|example|03|com|00|" --from 41 --to 295 -m comment --comment "Match subdomain only *.example.com"

    #4. Matching of unsafe labels
    sudo iptables -t filter -A OUTPUT -p udp --dport 53  -m string --algo bm --hex-string "|04|nsfw"               --from 40 --to 295 -m comment --comment "Match nsfw unsafe label"

    #5. Matching of unsafe words
    sudo iptables -t filter -A OUTPUT -p udp --dport 53  -m string --algo bm --hex-string "nsfw"                   --from 40 --to 295 -m comment --comment "Match nsfw unsafe word"
    """
    normalize = lambda x: dns.name.from_text(x).to_text()
    hexstring = lambda x: ''.join('|{0:0{1}x}|{2}'.format(len(t),2, t) for t in x.split('.'))
    if mtype == 'DOMAIN_ONLY':
        _name = '"{}"'.format(hexstring(normalize(domain)))
        _from, _to = 40, 41
        return {'string':{'algo':'bm', 'hex-string':_name, 'from':_from, 'to':_to}}
    elif mtype == 'SUBDOMAIN_ONLY':
        _name = '"{}"'.format(hexstring(normalize(domain)))
        _from, _to = 41, 295
        return {'string':{'algo':'bm', 'hex-string':_name, 'from':_from, 'to':_to}}
    elif mtype == 'DOMAIN_SUBDOMAIN':
        _name = '"{}"'.format(hexstring(normalize(domain)))
        _from, _to = 40, 295
        return {'string':{'algo':'bm', 'hex-string':_name, 'from':_from, 'to':_to}}
    elif mtype == 'LABEL':
        # Do not normalize domain. It may include an intermediary label or a tld.
        _name = '"{}"'.format(hexstring(domain))
        _from, _to = 40, 295
        return {'string':{'algo':'bm', 'hex-string':_name, 'from':_from, 'to':_to}}
    elif mtype == 'CONTAINS':
        # Do not normalize domain or hexify it. Use given string.
        _name = '"{}"'.format(domain)
        _from, _to = 40, 295
        return {'string':{'algo':'bm', 'hex-string':_name, 'from':_from, 'to':_to}}
    else:
        raise ValueError('Unkown mtype')

def _random_string(size):
    import random, string
    chars = string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(size))

def _print_message(msg):
    print(msg)
    print(''.join('#{} {}\n'.format(i+1, opt.to_text()) for i, opt in enumerate(msg.options)))

def _print_options(msg):
    print(''.join('#{} {}\n'.format(i+1, opt.to_text()) for i, opt in enumerate(msg.options)))

def from_wire(data):
    msg = dns.message.from_wire(data)
    print('Parsed DNS message')
    _print_message(msg)

def options_to_wire(options):
    import io
    edns_options = [cls(*args) for cls, args in options]
    for i, opt in enumerate(edns_options):
        file = io.BytesIO()
        opt.to_wire(file)
        opt_data = file.getvalue()
        file.close()
        opt_header = struct.pack('!HH', opt.otype, len(opt_data))
        print('#{} {} wire/{}'.format(i+1, opt.to_text(), opt_header+opt_data))


def generic_edns_test(options):
    # Test encoding of EDNS0 options
    # options = [(cls, args)]
    fqdn = 'foo.bar'
    rdtype = dns.rdatatype.A
    msg = dns.message.make_query(fqdn, rdtype)
    edns_options = [cls(*args) for cls, args in options]
    msg.use_edns(options = edns_options)
    print('Built DNS message for {}/{}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), msg.id))
    #_print_message(msg)
    print('Wire representation: {}\n'.format(msg.to_wire()))
    # Test decoding of EDNS0 options
    from_wire(msg.to_wire())


def send_recv_query(fqdn, rdtype, options, address):
    import socket

    msg = dns.message.make_query(fqdn, rdtype)
    edns_options = [cls(*args) for cls, args in options]
    msg.use_edns(options = edns_options)

    print('Send DNS message {} to {}'.format(msg.id, address))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg.to_wire(), address)
    data, raddr = s.recvfrom(1024)
    s.close()
    response = dns.message.from_wire(data)
    print('Received DNS response to {} from {} options/{}'.format(response.id, raddr, len(response.options)))
    _print_options(response)


if __name__ == '__main__':
    # Build tests
    print('EDNS0_ECSOption')
    generic_edns_test([(EDNS0_ECSOption, ('192.168.0.100', 32, 0))])

    print('EDNS0_EClientInfoOption')
    generic_edns_test([(EDNS0_EClientInfoOption, ('192.168.0.100', 17, 47789))])

    print('EDNS0_EClientID')
    generic_edns_test([(EDNS0_EClientID, (b'\xde\xad\xbe\xef',))])

    print('EDNS0_EDomainRate')
    generic_edns_test([(EDNS0_EDomainRate, ('foo.bar.',10,'sec',60))])
    print('EDNS0_EDomainRate')
    generic_edns_test([(EDNS0_EDomainRate, ('*foo.bar.',10,'sec',60))])
    print('EDNS0_EDomainRate')
    generic_edns_test([(EDNS0_EDomainRate, ('*.foo.bar.',10,'sec',60))])

    print('EDNS0_ENSIDOption')
    generic_edns_test([(EDNS0_ENSIDOption, ('SomeServerId'.encode(),))])

    print('Mix of all options')
    options_to_wire([(EDNS0_ECSOption, ('192.168.0.100', 32, 0)),
                     (EDNS0_EClientInfoOption, ('192.168.0.100', 17, 47789)),
                     (EDNS0_EClientID, (b'\xde\xad\xbe\xef',)),
                     (EDNS0_EDomainRate, ('foo.bar.',10,'sec',60)),
                     (EDNS0_EDomainRate, ('*foo.bar.',10,'sec',60)),
                     (EDNS0_EDomainRate, ('*.foo.bar.',10,'sec',60)),
                     (EDNS0_ENSIDOption, ('SomeServerId'.encode(),))])


    # Query and extension propagation tests
    print('Send/Recv EDNS0_ECSOption')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_ECSOption, ('192.168.0.100', 32, 0))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_EClientInfoOption')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_EClientInfoOption, ('192.168.0.100', 17, 47789))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_EClientID')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_EClientID, (b'\xde\xad\xbe\xef',))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_EDomainRate')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_EDomainRate, ('foo.bar.',10,'sec',60))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_EDomainRate')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_EDomainRate, ('*foo.bar.',10,'sec',60))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_EDomainRate')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_EDomainRate, ('*.foo.bar.',10,'sec',60))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_ENSIDOption')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_ENSIDOption, ('SomeServerId'.encode(),))], ('8.8.8.8',53))
    print('Send/Recv EDNS0_ENSIDOption')
    send_recv_query(_random_string(10)+'.cloud.mobilesdn.org', 1, [(EDNS0_ENSIDOption, (''.encode(),))], ('8.8.8.8',53))

    # Build iptables string matches for the following: 'DOMAIN_ONLY', 'SUBDOMAIN_ONLY', 'DOMAIN_SUBDOMAIN', 'LABEL', 'CONTAINS'
    print('iptables match DOMAIN_ONLY:\n{}'.format(ipt_build_match_domain('example.com', mtype = 'DOMAIN_ONLY')))
    print('iptables match SUBDOMAIN_ONLY:\n{}'.format(ipt_build_match_domain('example.com', mtype = 'SUBDOMAIN_ONLY')))
    print('iptables match DOMAIN_SUBDOMAIN:\n{}'.format(ipt_build_match_domain('example.com', mtype = 'DOMAIN_SUBDOMAIN')))
    print('iptables match LABEL:\n{}'.format(ipt_build_match_domain('nsfw.', mtype = 'LABEL')))
    print('iptables match CONTAINS:\n{}'.format(ipt_build_match_domain('nsfw', mtype = 'CONTAINS')))
