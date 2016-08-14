import asyncio
import logging
import time

from customdns.dnsutils import *

LOGLEVEL = logging.INFO

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
        self._logger.setLevel(LOGLEVEL)
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
                self._query.id, self._name.to_text(), dns.rdatatype.to_text(
                    self._rdtype), self._sockname[0], self._sockname[1],
                self._peername[0], self._peername[1], self._timeouts))

        self._sendmsg(self._query)
        self._set_timeout()

    def datagram_received(self, data, addr):
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
                    self._name.to_text(),
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
                    query.id, q.name.to_text(), dns.rdatatype.to_text(
                        q.rdtype), addr[0], addr[1]))
            return

        self._logger.debug(
                'Received retransmission {0} {1}/{2} from {3}{4}'.format(
                    query.id, q.name.to_text(), dns.rdatatype.to_text(
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

'''
import threading
import asyncio
import socket
import time

import dns
from dns import *

@asyncio.coroutine
def sendrecv_tcp(host, port, message):
    # This is for TCP!
    t0 = time.time()
    reader, writer = yield from asyncio.open_connection(host, port)
    t1 = time.time()
    writer.write(message)
    yield from writer.drain()
    data = yield from reader.read()
    t2 = time.time()
    writer.close()
    print('Message received: ({} / {} ms) {}'.format((t1-t0)/1000.0, (t2-t0)/1000.0, data))

@asyncio.coroutine
def sendrecv_udp(host, port, message):
    # This is for UDP!
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    yield from loop.sock_connect(s, (host, port))
    t0 = time.time()
    yield from loop.sock_sendall(s, message)
    answer = yield from loop.sock_recv(s, 1024)
    t1 = time.time()
    print('Message received in {} ms: {}'.format((t1-t0)/1000.0, answer))
    s.close()


@asyncio.coroutine
def _make_query(fqdn, rdtype, host, port):
    dnsmsg = dns.message.make_query(fqdn, rdtype)
    sock = yield from _sock_connect(host, port)
    for tout in [0.5, 0.5, 0.5]:
        try:
            print('Sending request with timeout {}'.format(tout))
            data = yield from _sock_sendrecv(sock, dnsmsg.to_wire(), tout)
            answer = dns.message.from_wire(data)
            print(answer)
            return answer
        except asyncio.TimeoutError:
            print ('Timeout {} expired'.format(tout))
            continue

@asyncio.coroutine
def _sock_connect(host, port):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    yield from loop.sock_connect(sock, (host, port))
    return sock

@asyncio.coroutine
def _sock_sendrecv(sock, message, timeout=None, loop=None):
    """
    @param timeout: 'None' sets socket in blocking mode.
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    if timeout is None:
        sock.setblocking(True)
    else:
        sock.setblocking(False)
    yield from loop.sock_sendall(sock, message)
    data = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
    sock.close()
    return data


loop = asyncio.get_event_loop()

loop.run_until_complete(_make_query('test.abc', 1, '8.8.8.8', 53))

udpmessage = b'\x1a\xb7\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03com\x00\x00\x01\x00\x01'
tcpmessage = b'\x00\x1a\x1a\xb7\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03com\x00\x00\x01\x00\x01'

loop.run_until_complete(sendrecv_udp('8.8.8.8', 53, udpmessage))
loop.run_until_complete(sendrecv_tcp('8.8.8.8', 53, tcpmessage))

'''