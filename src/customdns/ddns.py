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

import asyncio
import logging

from customdns.dnsutils import *

class DDNSProxy(asyncio.DatagramProtocol):
    def __init__(self, dns_addr = None, cb_add=None, cb_delete=None, cb_default=None):
        self._logger = logging.getLogger('DDNSProxy')
        # Set default functions
        self._do_add = self._do_add_default
        self._do_delete = self._do_delete_default
        self._do_process = self._do_process_default
        # Set specific functions
        if cb_add:
            self._do_add = cb_add
        if cb_delete:
            self._do_delete = cb_delete
        if cb_default:
            self._do_process = cb_default
        # Set DNS server address for zone update
        self._dns_addr = dns_addr

    def connection_made(self, transport):
        self._transport = transport

    def error_received(self, exc):
        addr = self._transport.get_extra_info('sockname')
        self._logger.error('Error received @{}:{} {}'.format(addr[0], addr[1], exc))

    def datagram_received(self, data, addr):
        try:
            self._logger.debug('Received data from {}"'.format(debug_data_addr(data, addr)))
            # Drop responses from DNS server
            if addr == self._dns_addr:
                return
            # Send proxied message to DNS server
            self._transport.sendto(data, self._dns_addr)
            # Process message locally
            query = dns.message.from_wire(data)
            self.process_message(query, addr)
        except Exception as e:
            self._logger.error('Failed to process DDNS message: {}'.format(e))

    def process_message(self, query, addr):
        """ Process a DNS message received by the DNS Server """
        self._logger.debug('Process message {}"'.format(debug_msg(query)))

        # Sanitize incoming query
        if not sanitize_query(query):
            self._send_error(query, addr, dns.rcode.FORMERR)
            return

        #Process only DNS Update message
        if query.opcode() != dns.opcode.UPDATE:
            self._logger.debug('Not a DNS UPDATE message')
            return

        self._do_process(query, addr, self.callback_sendto)

    def _do_add_default(self, name, rdtype, ipaddr):
        self._logger.info('Add user {} @{}'.format(name, ipaddr))

    def _do_delete_default(self, name, rdtype, ipaddr):
        self._logger.info('Delete user {} @{}'.format(name, ipaddr))

    def _do_process_default(self, query, addr, cback):
        """ Generate NoError DNS response """
        rr_a = None
        #Filter hostname and operation
        for rr in query.authority:
            #Filter out non A record types
            if rr.rdtype == dns.rdatatype.A:
                rr_a = rr
                break

        if not rr_a:
            # isc-dhcp-server uses additional TXT records -> don't process
            self._logger.warning('Not "A" record found')
            return

        name = format(rr_a.name)
        if rr_a.ttl:
            self._do_add(name, rr_a.rdtype, rr_a[0].address)
        else:
            self._do_delete(name, rr_a.rdtype, rr_a[0].address)

        # Send generic DDNS Response NOERROR
        response = make_response_rcode(query)
        self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
        cback(query, response, addr)

    def callback_sendto(self, query, addr, response=None):
        """ Send response to host """
        self._logger.debug('Callback for query {}'.format(query.id))
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
            return
        self._send_msg(response, addr)

    def _send_msg(self, dnsmsg, addr):
        self._logger.debug('Send message to {}"'.format(debug_msg_addr(dnsmsg, addr)))
        self._transport.sendto(dnsmsg.to_wire(), addr)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)


class DDNSServer(asyncio.DatagramProtocol):
    def __init__(self, cb_add=None, cb_delete=None, cb_default=None):
        self._logger = logging.getLogger('DDNSProxy')
        # Set default functions
        self._do_add = self._do_add_default
        self._do_delete = self._do_delete_default
        self._do_process = self._do_process_default
        # Set specific functions
        if cb_add:
            self._do_add = cb_add
        if cb_delete:
            self._do_delete = cb_delete
        if cb_default:
            self._do_process = cb_default

    def connection_made(self, transport):
        self._transport = transport

    def error_received(self, exc):
        addr = transport.get_extra_info('sockname')
        self._logger.error('Error received @{}:{} {}'.format(addr[0], addr[1], exc))

    def datagram_received(self, data, addr):
        self._logger.debug('Received data from {}"'.format(debug_data_addr(data, addr)))
        # Process message locally
        query = dns.message.from_wire(data)
        self.process_message(query, addr)

    def process_message(self, query, addr):
        """ Process a DNS message received by the DNS Server """
        self._logger.debug('Process message {}"'.format(debug_msg(query)))

        # Sanitize incoming query
        if not sanitize_query(query):
            self._send_error(query, addr, dns.rcode.FORMERR)
            return

        #Process only DNS Update message
        if query.opcode() != dns.opcode.UPDATE:
            self._logger.debug('Not a DNS UPDATE message')
            return

        self._do_process(query, addr, self.callback_sendto)

    def _do_add_default(self, name, rdtype, ipaddr):
        self._logger.info('Add user {} @{}'.format(name, ipaddr))

    def _do_delete_default(self, name, rdtype, ipaddr):
        self._logger.info('Delete user {} @{}'.format(name, ipaddr))

    def _do_process_default(self, query, addr, cback):
        """ Generate NoError DNS response """
        rr_a = None
        #Filter hostname and operation
        for rr in query.authority:
            #Filter out non A record types
            if rr.rdtype == dns.rdatatype.A:
                rr_a = rr
                break

        if not rr_a:
            # isc-dhcp-server uses additional TXT records -> don't process
            self._logger.warning('Not "A" record found')
            return

        name = format(rr_a.name)
        if rr_a.ttl:
            self._do_add(name, rr_a.rdtype, rr_a[0].address)
        else:
            self._do_delete(name, rr_a.rdtype, rr_a[0].address)

        # Send generic DDNS Response NOERROR
        response = make_response_rcode(query)
        self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
        cback(query, response, addr)

    def callback_sendto(self, query, addr, response=None):
        """ Send response to host """
        self._logger.debug('Callback for query {}'.format(query.id))
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
            return
        self._send_msg(response, addr)

    def _send_msg(self, dnsmsg, addr):
        self._logger.debug('Send message to {}"'.format(debug_msg_addr(dnsmsg, addr)))
        self._transport.sendto(dnsmsg.to_wire(), addr)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)
