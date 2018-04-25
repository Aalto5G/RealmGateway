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
import time
import socket

from customdns.dnsutils import *
from helpers_n_wrappers.asyncio_helper3 import AsyncSocketQueue

class DNSResolver(asyncio.DatagramProtocol):
    '''
    # Instantiated as follows
    resolver = DNSResolver(host_query, host_addr, cb_function, timeouts=[0.100,0.200])
    loop.create_task(
        loop.create_datagram_endpoint( lambda: resolver, remote_addr=addr)
        )
    '''
    def __init__(self, host_query, host_addr, cb_function, host_rtx=True, timeouts=None):
        self._logger = logging.getLogger('DNSResolver #{}'.format(id(self)))
        self._loop = asyncio.get_event_loop()
        self._query = host_query
        self._addr = host_addr
        self._cb_function = cb_function
        # Set the host retransmission parameter
        self._host_rtx = host_rtx
        # Set timeout parameters
        if timeouts is None:
            timeouts = [0]
        self._timeouts = list(timeouts)
        self._toutfuture = None
        # Get query parameters for printing
        q = self._query.question[0]
        self._name = q.name
        self._rdtype = q.rdtype
        self._rdclass = q.rdclass
        # Set time zero
        self._tref = time.time()
        self._logger.debug('Resolving with timeouts {}'.format(id(self), self._timeouts))

    def _get_runtime(self):
        return time.time() - self._tref

    def connection_made(self, transport):
        self._transport = transport
        self._peername = transport.get_extra_info('peername')
        self._sockname = transport.get_extra_info('sockname')

        self._logger.debug(
            'Resolve {0} {1}/{2} via {3}:{4} > {5}:{6} with timeouts {7}'.format(
                self._query.id, self._name, dns.rdatatype.to_text(self._rdtype),
                self._sockname[0], self._sockname[1],
                self._peername[0], self._peername[1],
                self._timeouts))

        self._sendmsg(self._query)
        self._set_timeout()

    def datagram_received(self, data, addr):
        try:
            self._logger.debug('Received data from {}"'.format(debug_data_addr(data, addr)))

            if self._peername != addr:
                self._logger.error('Unexpected source! {0}:{1} != {2}:{3}'.format(self._peername[0], self._peername[1], addr[0], addr[1]))
                return

            response = dns.message.from_wire(data)

            if not sanitize_response(self._query, response):
                # Sanitize incoming response
                self._logger.warning('Not a valid response for query\n{}'.format(response))
                response = None
            else:
                # The response is correct
                self._logger.info(
                    'Resolution succeeded {0} {1}/{2} via {3}:{4} in {num:.3f} msec'.format(
                        self._query.id,
                        self._name,
                        dns.rdatatype.to_text(self._rdtype),
                        self._peername[0],
                        self._peername[1],
                        num=self._get_runtime() * 1000))

            # Cancel timer
            self._cancel_timeout()
            # Terminate connection
            self.connection_lost(None)
            # Call callback function
            self._cb_function(self._query, self._addr, response)
        except Exception as e:
            self._logger.error('Failed to process DNS message: {}'.format(e))

    def error_received(self, exc):
        # The remote end has closed the connection - ICMP Port unreachable
        self._logger.warning('Socket failed: {0}:{1} / {2}'.format(self._peername[0], self._peername[1], exc))
        # Cancel timer
        self._cancel_timeout()
        # Terminate connection
        self.connection_lost(None)
        # Call callback function with None response
        self._cb_function(self._query, self._addr, None)

    def process_query(self, query, addr):
        q = query.question[0]
        if not self._host_rtx:
            self._logger.debug(
                'Retransmission disabled for {0} {1}/{2} from {3}{4}'.format(
                    query.id, q.name, dns.rdatatype.to_text(
                        q.rdtype), addr[0], addr[1]))
            return

        self._logger.debug(
                'Received retransmission {0} {1}/{2} from {3}{4}'.format(
                    query.id, q.name, dns.rdatatype.to_text(
                        q.rdtype), addr[0], addr[1]))

        # Forward host retransmission
        self._sendmsg(self._query)

    def timeout_expired(self, t):
        self._logger.debug('Timer expired: {num:.3f} sec'.format(num=t))
        if len(self._timeouts) > 0:
            self._sendmsg(self._query)
            self._set_timeout()
        else:
            self._logger.warning(
                'Resolution failed after {num:.3f} msec'.format(
                    num=self._get_runtime() * 1000))
            # Terminate connection
            self.connection_lost(None)
            # Call callback function with None response
            self._cb_function(self._query, self._addr, None)

    def _sendmsg(self, dnsmsg):
        self._transport.sendto(dnsmsg.to_wire())

    def _get_timeout(self):
        try:
            return self._timeouts.pop(0)
        except IndexError:
            return -1

    def _set_timeout(self):
        tout = self._get_timeout()
        if tout == 0:
            self._logger.debug('Operating in blocking mode')
        elif tout > 0:
            self._logger.debug('Setting timer value: {} sec'.format(tout))
            self._toutfuture = self._loop.call_later(
                tout, self.timeout_expired, tout)
        else:
            self._logger.debug('Timeout value is not valid: {}'.format(tout))

    def _cancel_timeout(self):
        if self._toutfuture:
            self._toutfuture.cancel()
            self._toutfuture = None

class uDNSResolver():
    '''
    # Instantiated as follows
    resolver = uDNSResolver()
    response = yield from resolver.do_resolve(query, raddr, timeouts=[1, 1, 1])
    '''

    @asyncio.coroutine
    def do_resolve(self, query, addr, timeouts=[0]):
        logger = logging.getLogger('DNSResolver #{}'.format(id(self)))
        logger.debug('Resolving to {} with timeouts {}'.format(addr, timeouts))
        loop = asyncio.get_event_loop()
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        yield from loop.sock_connect(self.sock, addr)
        # Create async socket wrapper object
        self.asock = AsyncSocketQueue(self.sock, loop)
        fqdn = format(query.question[0].name).lower()
        response = None
        i = 0
        for tout in timeouts:
            i += 1
            try:
                yield from self.asock.sendall(query.to_wire())
                dataresponse = yield from asyncio.wait_for(self.asock.recv(), timeout=tout)
                self.asock.close()
                return dns.message.from_wire(dataresponse)
            except asyncio.TimeoutError:
                logger.debug('#{} timeout expired: {:.4f} sec ({})'.format(i, tout, fqdn))
                continue
        return None

    @asyncio.coroutine
    def do_continue(self, query):
        loop = asyncio.get_event_loop()
        yield from self.asock.sendall(query.to_wire())
