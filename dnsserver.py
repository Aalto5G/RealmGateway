#!/usr/bin/python3.5

import asyncio
import logging
import signal
import sys
import traceback

import dns
import dns.message
import dns.zone

from dnsresolver import GenericDNSResolver
from mydnsutils import sanitize_query

LOGLEVEL = logging.DEBUG

class DNSServer(asyncio.DatagramProtocol):
    def __init__(self, zone, cb_noerror=None, cb_nxdomain=None, cb_update=None, cache=None):
        self._logger = logging.getLogger('DNSServer')
        self._logger.setLevel(LOGLEVEL)

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
        if not sanitize_query(query):
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
