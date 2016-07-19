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
        try:
            response = dns.message.from_wire(data)
        except Exception as e:
            self._logger.error('Failed to parse! {} {}"'.format(debug_data_addr(data, addr), e))
            return

        if not sanitize_response(self._query, response):
            # Sanitize incoming response and don't stop timer
            self._logger.warning('Not a valid response for query')
            return

        # The response is correct
        self._logger.warning(
            'Resolution succeeded {0} {1}/{2} via {3}:{4} in {num:.3f} msec'.format(
                self._query.id,
                self._name.to_text(),
                dns.rdatatype.to_text(self._rdtype),
                self._peername[0],
                self._peername[1],
                num=self._get_runtime() * 1000))

        #self._logger.warning('Resolution succeeded after {0} sec'.format(self._get_runtime()))
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
            # Call callback function with response = None
            self._cb_func(self._cb_args, None)

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
