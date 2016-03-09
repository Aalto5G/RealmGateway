#!/usr/bin/python3.5

import asyncio
import logging
import signal
import sys
import time
import traceback

import dns
import dns.message
import dns.zone

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

LOGLEVELDNS = logging.DEBUG

def _sanitize_query(query):
    try:
        #assert (query.opcode() == dns.opcode.QUERY)  # Standard QUERY
        assert (query.rcode() == dns.rcode.NOERROR)  # No Error
        assert ((query.flags & dns.flags.QR) != dns.flags.QR)  # Message is query
        assert (len(query.question) == 1)  # Query contains 1 question
    except Exception as e:
        print('Failed to sanitize DNS query: {}'.format(e))
        return False
    return True


def _sanitize_response(query, response):
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

def _is_ipv4(ipaddr):
    try:
        assert(dns.ipv4.inet_aton(ipaddr))
        return True
    except:
        return False
    
def _is_ipv6(ipaddr):
    try:
        assert(dns.ipv6.inet_aton(ipaddr))
        return True
    except:
        return False

def _get_dummy(zone):
    return '{}.{}'.format('__secret', zone.origin.to_text())
    
def load_zone(zone_file, origin):
    return dns.zone.from_file(zone_file, origin, relativize=False)

def add_node(zone, name, rdtype, address, ttl=60):
    print('Add node {} {}'.format(name, address))
    assert(rdtype == A)
    # Create A record with given IP address
    rdataset = zone.find_rdataset(name, rdtype, create=True)
    rdata = dns.rdtypes.IN.A.A(IN, A, address=address)
    rdataset.add(rdata, ttl=ttl)
    
    # Create CNAME record for NAPTR lookups
    target = dns.name.from_text(_get_dummy(zone))
    rdataset = zone.find_rdataset(name, CNAME, create=True)
    rdata = dns.rdtypes.ANY.CNAME.CNAME(IN, CNAME, target)
    rdataset.add(rdata, ttl=ttl)


class DNSServer(asyncio.DatagramProtocol):
    def __init__(self, zone, cb_noerror=None, cb_nxdomain=None, cb_update=None, cache=None):
        self._logger = logging.getLogger('DNSServer')
        self._logger.setLevel(LOGLEVELDNS)

        self._zone = zone
        self._cache = cache

        # Define standard functions for processing DNS queries
        self._cb_noerror  = self._do_process_query_noerror
        self._cb_nxdomain = self._do_process_query_nxdomain
        self._cb_update   = self._do_process_query_update

        # Define callback functions for connecting to other resolvers
        if cb_noerror:
            self._logger.info('Resolving internal records via {}'.format(
                cb_noerror))
            self._cb_noerror = cb_noerror

        if cb_nxdomain:
            self._logger.info('Resolving external records via {}'.format(
                cb_nxdomain))
            self._cb_nxdomain = cb_nxdomain
        
        if cb_update:
            self._logger.info('Resolving DNS update via {}'.format(
                cb_update))
            self._cb_update = cb_update

    def callback_sendto(self, query, response, addr):
        """ Send response to host """
        self._logger.debug('Callback for query {}'.format(query.id))
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
            return
        self._send_msg(response, addr)

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        self._logger.debug(
            'Received data from {0}:{1} ({2} bytes) "{3}"'.format(addr[
                0], addr[1], len(data), data))

        try:
            query = dns.message.from_wire(data)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            # self._logger.warning('{}'.format(e))
            self._logger.error(
                'Failed to parse DNS message from {0}:{1} ({2} bytes) "{3}"'.format(
                    addr[0], addr[1], len(data), data))
            return
        try:
            # Process received message
            self.process_message(query, addr)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            # self._logger.warning('{}'.format(e))
            self._logger.error(
                'Failed to process DNS message from {0}:{1} ({2} bytes) "{3}"'.format(
                    addr[0], addr[1], len(data), data))
            return

    def process_message(self, query, addr):
        """ Process a DNS message received by the DNS Server """

        # Sanitize incoming query
        if not _sanitize_query(query):
            self._send_error(query, addr, dns.rcode.FORMERR)
            return

        q = query.question[0]
        name, rdtype, rdclass = q.name, q.rdtype, q.rdclass
        opcode = query.opcode()
        key = (query.id, name, rdtype, rdclass, addr)

        self._logger.debug('Process message {}/{} {}/{} from {}{}'.format(
            dns.opcode.to_text(opcode), query.id, name.to_text(), 
            dns.rdatatype.to_text(rdtype), addr[0], addr[1]))
        
        #Process DNS Update message
        if opcode == dns.opcode.UPDATE:
            self._cb_update(query, addr, self.callback_sendto)
            return
        
        #Continue only if DNS message is Query
        elif opcode != dns.opcode.QUERY:
            self._logger.error('Received {} message. Answering NotImplemented!'.format(dns.opcode.to_text(opcode)))
            self._send_error(query, addr, dns.rcode.NOTIMP)
            return
        
        if self._name_in_cache(addr, name, rdtype, rdclass):
            self._logger.debug(
                'Domain {0}/{1} exists in DNS cache, resolve internally'.format(
                    qname.to_text(), dns.rdatatype.to_text(rdtype)))

            # TODO: Link to caching service - Negative caching / User-based
            # Caching is decided by remote resolvers
            self._do_process_query_cache()

        elif self._name_in_zone(name):
            self._logger.debug(
                'Domain {} belongs to DNS zone, resolve internally'.format(
                    name))

            if not self._get_node(name):
                self._logger.debug(
                    'Domain {} does not exist in DNS zone'.format(name.to_text(
                    )))
                self._send_error(query, addr, dns.rcode.NXDOMAIN)
                return

            # Use registered function for resolving internal records
            self._cb_noerror(query, addr, self.callback_sendto)

        else:
            self._logger.debug(
                'Domain {} not in DNS zone, resolve externally'.format(name))
            # Use registered function for resolving internal records
            self._cb_nxdomain(query, addr, self.callback_sendto)

    def _do_process_query_cache(self, query, addr, cback):
        """ Generate DNS response with the available records from the zone """
        pass

    def _do_process_query_noerror(self, query, addr, cback):
        """ Generate DNS response with the available records from the zone """

        self._logger.debug('_do_process_query_noerror')

        q = query.question[0]
        name, rdtype, rdclass = q.name, q.rdtype, q.rdclass

        response = dns.message.make_response(query, recursion_available=True)
        rrset = self._get_rrset(name, rdtype)

        # Fill the answer section
        # Contains the available records
        if rrset:
            self._logger.info('Record found for {0}/{1}'.format(
                name, dns.rdatatype.to_text(rdtype)))
            response.set_rcode(dns.rcode.NOERROR)
            response.answer.append(rrset)

        elif rdtype == dns.rdatatype.CNAME:
            self._logger.info('Record not found for {0}/{1}'.format(
                name, dns.rdatatype.to_text(rdtype)))
            response.set_rcode(dns.rcode.NOERROR)

        elif rdtype != dns.rdatatype.CNAME:
            # Resolve CNAME records if available
            response.set_rcode(dns.rcode.NOERROR)
            cname_rrset = self._resolve_cname(name, rdtype)
            response.answer = cname_rrset
            self._logger.info(
                'Found {0} related records for {1} via {2}'.format(
                    len(cname_rrset), name, dns.rdatatype.to_text(
                        dns.rdatatype.CNAME)))

        # Fill authority section
        # Contains the NS records
        ns_rrset = self._get_rrset(self._zone.origin, dns.rdatatype.NS)
        #ns_rrset = self._zone.get_rrset(self._zone.origin, dns.rdatatype.NS)
        response.authority.append(ns_rrset)

        # Fill additional section
        # Contains the A / AAAA records for the NS
        for rr in ns_rrset:
            for rr_type in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                ip_rrset = self._get_rrset(rr.target, rr_type)
                if ip_rrset:
                    response.additional.append(ip_rrset)

        response.flags |= dns.flags.AA

        # Use cback function to send ready-made response
        cback(query, response, addr)

    def _do_process_query_nxdomain(self, query, addr, cback):
        """ Generate None DNS response """
        self._logger.debug('_do_process_query_nxdomain')
        cback(query, None, addr)
    
    def _do_process_query_update(self, query, addr, cback):
        """ Generate NoError DNS response """
        self._logger.warning('_do_process_query_update')
        # Send generic DNS Response NOERROR
        response = dns.message.make_response(query)
        self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
        cback(query, response, addr)
            
    def _get_cache(self, addr, name, rdtype, rdclass):
        """ Return a cached response """
        return self._cache.get((name, rdtype, rdclass))

    def _get_node(self, name):
        """ Return a node of the DNS zone """
        return self._zone.get_node(name)

    def _get_rrset(self, name, rdtype):
        """ Return the records of the node in the DNS zone """
        return self._zone.get_rrset(name, rdtype)

    def _name_in_zone(self, name):
        """ Return True if the name belongs to the zone """
        return name.is_subdomain(self._zone.origin)

    def _name_in_cache(self, addr, name, rdtype, rdclass):
        """ Return True if the record exists in the cache """
        #Cached is not enabled
        if not self._cache:
            return False

        return (self._cache.get((name, rdtype, rdclass)) is not None)

    def _resolve_cname(self, name, rdtype):
        """ Resolve 1 level of indirection for CNAME records """
        cname_rrset = self._get_rrset(name, dns.rdatatype.CNAME)
        rrset = []
        # Resolve 1 level of indirection for CNAME
        # TODO: Make recursive and yield all records
        if not cname_rrset:
            return rrset

        # Add CNAME records to list
        rrset.append(cname_rrset)

        # Resolve CNAME records from DNS zone
        for rr in cname_rrset:
            ip_rrset = self._get_rrset(rr.target, rdtype)
            if ip_rrset:
                rrset.append(ip_rrset)

        return rrset

    def _send_msg(self, dnsmsg, addr):
        q = dnsmsg.question[0]
        self._logger.debug('Send message {0} {1}/{2} {3} to {4}{5}'.format(
            dnsmsg.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype),
            dns.rcode.to_text(dnsmsg.rcode()), addr[0], addr[1]))

        self._transport.sendto(dnsmsg.to_wire(), addr)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)


class DNSResolverCESIPv4(object):
    def __init__(self, loop, query, hostaddr, nameserver, cb_func, cb_args, host_rtx=False, timeouts=None):
        self._logger = logging.getLogger('DNSResolverCESIPv4')
        self._logger.setLevel(LOGLEVELDNS)

        self._loop = loop
        self._query = query
        self._hostaddr = hostaddr
        self._nameserver = nameserver
        self._cb_func = cb_func
        self._cb_args = cb_args
        
        # Set the host retransmission parameter
        self._host_rtx = host_rtx
        
        # Set timeout parameters
        if timeouts is None:
            self._timeouts = {'NAPTR': [0.010, 0.100, 0.300],
                              'A':     [0.010, 0.100, 0.300]}

    def begin(self):
        # phase = (currentPhase, NAPTR_resolved, A_resolved, CETP_started, CETP_failed)
        #assert self._phase == (0,0,0,0,0)
        self._do_NAPTR()

    def _do_NAPTR(self):
        # Make NAPTR query and instantiate ResolverWorker
        q = self._query.question[0]
        query_naptr = dns.message.make_query(q.name, dns.rdatatype.NAPTR)

        cb_func = self.callback
        cb_args = ('NAPTR', query_naptr.id, q.name, dns.rdatatype.NAPTR,
                   self._nameserver)
        timeouts = self._timeouts['NAPTR']
        resolver = ResolverWorker(self._loop, query_naptr, cb_func, cb_args,
                                   timeouts)
        # Store resolver for host retransmissions
        self._resolver = resolver
        # Instantiate resolver
        self._loop.create_task(
            self._loop.create_datagram_endpoint(lambda: resolver,
                                                remote_addr=self._nameserver))
        
    def _do_A(self):
        # Make A query and instantiate ResolverWorker
        q = self._query.question[0]
        query_a = dns.message.make_query(q.name, dns.rdatatype.A)

        cb_func = self.callback
        cb_args = ('A', query_a.id, q.name, dns.rdatatype.A, self._nameserver)
        timeouts = self._timeouts['A']
        resolver = ResolverWorker(self._loop, query_a, cb_func, cb_args,
                                   timeouts)
        # Store resolver for host retransmissions
        self._resolver = resolver
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
        
        self._resolver.process_query(query, addr)

class ResolverWorker(asyncio.DatagramProtocol):
    '''
    # Instantiated as follows
    resolver = DNSForwarderClient(loop, query, cb_func, cb_args, timeouts)
    loop.create_task(
        loop.create_datagram_endpoint( lambda: resolver, remote_addr=addr)
        )
    '''

    def __init__(self, loop, query, cb_func, cb_args, host_rtx=False, timeouts=None):
        self._logger = logging.getLogger('ResolverWorker #{}'.format(id(
            self)))
        self._logger.setLevel(LOGLEVELDNS)

        self._loop = loop
        self._query = query
        self._cb_func = cb_func
        self._cb_args = cb_args
        
        # Set the host retransmission parameter
        self._host_rtx = host_rtx
        
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

        if not _sanitize_response(self._query, response):
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

'''
class GenericDNSResolver(object):
    def __init__(self, loop, nameserver, *args, **kwargs):
        self._logger = logging.getLogger('GenericDNSResolver')
        self._logger.setLevel(LOGLEVELDNS)

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
        elif _is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A:
            # Resolve DNS query for CES IPv4
            self._do_resolve_query_ces(query, addr, cback)
        elif _is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA:
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
        resolver = ResolverWorker(self._loop, query, self._do_callback,
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
'''