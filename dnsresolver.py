import asyncio
import logging
import time

import dns
import dns.message
from mydnsutils import is_ipv4, is_ipv6, sanitize_response

LOGLEVEL = logging.DEBUG


class GenericDNSResolver(object):
    def __init__(self, loop, nameserver, *args, **kwargs):
        self._logger = logging.getLogger("GenericDNSResolver")
        self._logger.setLevel(LOGLEVEL)

        self._loop = loop
        self._nameserver = nameserver
        self._activequeries = {} # Map resolutions to resolvers
    
    def process_update(self, query, addr, cback):
        """ Generate NoError DNS response """
        self._logger.debug('process_update')
        
        try:
            rr_a = None
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A:
                    rr_a = rr
                    break
            
            if not rr_a:
                # isc-dhcp-server uses additional TXT records -> don't process
                self._logger.debug('Failed to find an A record')
                return
            
            name = rr_a.name
            ipaddr = rr_a[0].address
            
            if rr_a.ttl:
                self._logger.warning('Registering new user {} @{} {} sec'.format(name.to_text(), ipaddr, rr_a.ttl))
            else:
                self._logger.warning('Unregistering user {} @{}'.format(name.to_text(), ipaddr))
        except:
            self._logger.error('Failed to process UPDATE DNS message')
            pass
        finally:
            # Send generic DDNS Response NOERROR
            response = dns.message.make_response(query)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, response, addr)

    def process_query(self, query, addr, cback):
        """ Perform DNS resolutions of queries originated in LAN """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        if key in self._activequeries:
            # Continue ongoing resolution
            (resolver, query) = self._activequeries[key]
            resolver.process_query(query, addr)
        else:
            # Resolve DNS query as is
            self._do_resolve_query(query, addr, cback)

    def process_query_ces(self, query, addr, cback):
        """ Perform CES DNS resolutions of queries originated in LAN """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        if key in self._activequeries:
            # Continue ongoing resolution
            (resolver, query) = self._activequeries[key]
            resolver.process_query(query, addr)
        elif is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A:
            # Resolve DNS query for CES IPv4
            self._do_resolve_query_ces(query, addr, cback)
        elif is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA:
            # Resolve DNS query for CES IPv6
            self._do_resolve_query_ces(query, addr, cback, ipv6=True)
        else:
            # Resolve DNS query as is
            self._do_resolve_query(query, addr, cback)

    def _do_callback(self, metadata, response=None):
        try:
            (queryid, name, rdtype, rdclass, addr, cback) = metadata
            (resolver, query) = self._activequeries.pop(metadata)
        except KeyError:
            self._logger.warning(
                'Query has already been processed {0} {1}/{2} from {3}:{4}'.format(
                    queryid, name, dns.rdatatype.to_text(rdtype), addr[
                        0], addr[1]))
            return

        if response is None:
            self._logger.warning(
                'This seems a good place to create negative caching...')

        # Callback to send response to host
        cback(query, response, addr)

    def _do_resolve_query(self, query, addr, cback):
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        self._logger.warning(
            'Resolve normal query {0} {1}/{2} from {3}:{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        # This DNS resolution does not require any kind of mangling
        timeouts = [0.001, 0.010, 0.500]
        resolver = _ResolverWorker(self._loop, query, self._do_callback,
                                   key, timeouts)
        self._activequeries[key] = (resolver, query)
        self._loop.create_task(
            self._loop.create_datagram_endpoint(lambda: resolver,
                                                remote_addr=self._nameserver))
    
    def _do_resolve_query_ces(self, query, addr, cback, ipv6=False):
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        self._logger.warning(
            'Resolve query for CES discovery {0} {1}/{2} from {3}:{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        if not ipv6:
            resolverObj = DNSResolverCESIPv4
        else:
            resolverObj = DNSResolverCESIPv6

        resolver = resolverObj(self._loop, query, addr, self._nameserver,
                               self._do_callback, key)
        self._activequeries[key] = (resolver, query)
        resolver.begin()


class DNSResolverCESIPv4(object):
    def __init__(self, loop, query, hostaddr, nameserver, cb_func, cb_args):
        self._logger = logging.getLogger("DNSResolverCESIPv4")
        self._logger.setLevel(LOGLEVEL)

        self._loop = loop
        self._query = query
        self._hostaddr = hostaddr
        self._nameserver = nameserver
        self._cb_func = cb_func
        self._cb_args = cb_args

        # Set timeout parameters
        self._timeouts = {'NAPTR': [0.010, 0.100, 0.300],
                          'A': [0.010, 0.100, 0.300]}

    def begin(self):
        # phase = (currentPhase, NAPTR_resolved, A_resolved, CETP_started, CETP_failed)
        #assert self._phase == (0,0,0,0,0)
        self._do_NAPTR()

    def _do_NAPTR(self):
        # Make NAPTR query and instantiate _ResolverWorker
        q = self._query.question[0]
        query_naptr = dns.message.make_query(q.name, dns.rdatatype.NAPTR)

        cb_func = self.callback
        cb_args = ('NAPTR', query_naptr.id, q.name, dns.rdatatype.NAPTR,
                   self._nameserver)
        timeouts = self._timeouts['NAPTR']
        resolver = _ResolverWorker(self._loop, query_naptr, cb_func, cb_args,
                                   timeouts)
        # Instantiate resolver
        self._loop.create_task(
            self._loop.create_datagram_endpoint(lambda: resolver,
                                                remote_addr=self._nameserver))

    def _do_A(self):
        # Make A query and instantiate _ResolverWorker
        q = self._query.question[0]
        query_a = dns.message.make_query(q.name, dns.rdatatype.A)

        cb_func = self.callback
        cb_args = ('A', query_a.id, q.name, dns.rdatatype.A, self._nameserver)
        timeouts = self._timeouts['A']
        resolver = _ResolverWorker(self._loop, query_a, cb_func, cb_args,
                                   timeouts)
        # Instantiate resolver
        self._loop.create_task(
            self._loop.create_datagram_endpoint(lambda: resolver,
                                                remote_addr=self._nameserver))

    def callback(self, metadata, response=None):
        """ Received result from resolver """

        (phase, queryid, name, rdtype, addr) = metadata

        if response:
            self._logger.warning(
                'Received response for {0} {1}/{2} from {3}:{4}'.format(
                    queryid, name, dns.rdatatype.to_text(rdtype), addr[
                        0], addr[1]))
        else:
            self._logger.warning(
                'Resolution failed for {0} {1}/{2} from {3}:{4}'.format(
                    queryid, name, dns.rdatatype.to_text(rdtype), addr[
                        0], addr[1]))

        if phase == 'NAPTR':
            # Validate NAPTR response for CES requirements? Let CETP module do that
            # Check only if there is any actual NAPTR record

            if not response:
                self._logger.warning('NAPTR resolution failed!')
                # Continue to resolution of phase A
                self._do_A()
                return

            found = False
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.NAPTR:
                    found = True
                    break

            if not found:
                self._logger.warning(
                    'Response does not contain any NAPTR record!')
                # Continue to resolution of phase A
                self._do_A()
                return

            self._logger.warning('Response contains NAPTR records!')
            # Continue to CETP module
            self._do_A()

        elif phase == 'A':
            # Call callback function
            # Make response to original query
            response.id = self._query.id
            response.flags |= dns.flags.QR
            response.flags |= dns.flags.RA
            self._cb_func(self._cb_args, response)

    def process_query(self, query, addr):
        q = self._query.question[0]
        self._logger.debug(
            'Received retransmission {0} {1}/{2} from {3}{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        # TODO: Process host retransmission
        # Decide what to do!
        # self._sendmsg(self._query)



class _ResolverWorker(asyncio.DatagramProtocol):
    '''
    # Instantiated as follows
    resolver = DNSForwarderClient(loop, query, cb_func, cb_args, timeouts)
    loop.create_task(
        loop.create_datagram_endpoint( lambda: resolver, remote_addr=addr)
        )
    '''

    def __init__(self, loop, query, cb_func, cb_args, timeouts=None):
        self._logger = logging.getLogger('_ResolverWorker #{}'.format(id(
            self)))
        self._logger.setLevel(LOGLEVEL)

        self._loop = loop
        self._query = query
        self._cb_func = cb_func
        self._cb_args = cb_args

        # Set timeout parameters
        if timeouts is None:
            timeouts = [0]
        self._toutlist = timeouts
        self._toutfuture = None

        # Get query parameters
        q = query.question[0]
        self._name = q.name
        self._rdtype = q.rdtype
        self._rdclass = q.rdclass

        self._tref = time.time()

    def _get_runtime(self):
        return time.time() - self._tref

    def _log(self, s):
        print('[{0}] {1}'.format(id(self), s))

    def connection_made(self, transport):
        self._transport = transport
        self._peername = transport.get_extra_info('peername')
        self._sockname = transport.get_extra_info('sockname')

        self._logger.debug(
            'Resolve {0} {1}/{2} via {3}:{4} > {5}:{6} with timeouts {7}'.format(
                self._query.id, self._name.to_text(), dns.rdatatype.to_text(
                    self._rdtype), self._sockname[0], self._sockname[1],
                self._peername[0], self._peername[1], self._toutlist))

        self._sendmsg(self._query)
        self._set_timeout()

    def datagram_received(self, data, addr):
        self._logger.debug(
            'Received data from {0}:{1} ({2} bytes) "{3}"'.format(addr[
                0], addr[1], len(data), data))

        if self._peername != addr:
            self._logger.error(
                'Unexpected source! {0}:{1} instead of {2}:{3}'.format(
                    self._peername[0], self._peername[1], addr[0], addr[1]))

        try:
            # Build dns response message
            response = dns.message.from_wire(data)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self._logger.error(
                'Failed to create DNS message from wire: {0}:{1} ({2} bytes) "{3}"'.format(
                    addr[0], addr[1], len(data), data))
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
        self._cb_func(self._cb_args, response)

    def error_received(self, exc):
        # The remote end has closed the connection - ICMP Port unreachable
        self._logger.warning('Socket failed: {0}:{1} / {2}'.format(
            self._peername[0], self._peername[1], exc))
        # Cancel timer
        self._cancel_timeout()
        # Terminate connection
        self.connection_lost(None)
        # Call callback function with None response
        self._cb_func(self._cb_args, None)

    def process_query(self, query, addr):
        self._logger.debug(
            'Received retransmission {0} {1}/{2} from {3}{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        # TODO: Process host retransmission
        # Decide what to do!
        # self._sendmsg(self._query)

    def timeout_expired(self, t):
        self._logger.debug('Timer expired: {num:.3f} sec'.format(num=t))
        if len(self._toutlist) > 0:
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
            return self._toutlist.pop(0)
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
