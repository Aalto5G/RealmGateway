"""
BSD 3-Clause License

Copyright (c) 2018, Jesus Llorente Santos, Aalto University, Finland
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import dns
import dns.message
import dns.name
import dns.zone
import dns.rcode
import dns.reversename
import dns.rrset

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *


# Use dns.reversename functions and return a string instead of dns.Name object
## '1.2.3.4' -> '4.3.2.1.in-addr.arpa.'
from_address = lambda x: dns.reversename.from_address(x).to_text()
## '4.3.2.1.in-addr.arpa.' -> '1.2.3.4'
to_address = lambda x: dns.reversename.to_address(dns.name.from_text(x)).decode()

make_query = dns.message.make_query

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

def make_response_rcode(query, rcode = dns.rcode.NOERROR, recursion_available=False):
    response = dns.message.make_response(query, recursion_available=recursion_available)
    response.set_rcode(rcode)
    return response

def make_response_answer_rr(query, name, rdtype, target, rdclass=1, ttl=60, recursion_available=False):
    fqdn = format(query.question[0].name)
    if fqdn != name and fqdn.lower() == name.lower():
        # Use original fqdn formatted name instead of the given name (lowercase) for very strict DNS servers
        name = fqdn

    response = dns.message.make_response(query, recursion_available=recursion_available)
#    response.flags |= dns.flags.CD
    response.answer = [dns.rrset.from_text(name, ttl, rdclass, rdtype, target)]
    return response

def get_section_record(section, n):
    try:
        return format(section[n].to_text())
    except:
        return None

def create_ddns_message(soa, name, rdtype, ttl, rdata):
    msg = dns.message.Message()
    msg.set_opcode(dns.opcode.UPDATE)
    msg.set_rcode(dns.rcode.NOERROR)
    # Zone
    rrset = dns.rrset.from_text(soa, ttl, dns.rdataclass.IN, dns.rdatatype.SOA)
    msg.question.append(rrset)
    # Record
    rrset = dns.rrset.from_text(name, ttl, dns.rdataclass.IN, rdtype, rdata)
    msg.authority.append(rrset)
    return msg
