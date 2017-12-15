import asyncio
import logging
import random
import pprint
from functools import partial
from operator import getitem

from aalto_helpers import utils3
from aalto_helpers import network_helper3

import customdns
from customdns import dnsutils
from customdns import edns0
from customdns.dnsresolver import DNSResolver, uDNSResolver

import dns
import dns.message
import dns.rcode

from dns.rdataclass import *
from dns.rdatatype import *

import host
from host import HostEntry

import connection
from connection import ConnectionLegacy

import pbra

DNSRR_TTL_CIRCULARPOOL = 0
DNSRR_TTL_SERVICEPOOL = 10
DNSRR_TTL_DEFAULT = 30

class DNSCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('DNSCallbacks')
        self._dns_timeout = {None:[0]} # Default single blocking query
        utils3.set_attributes(self, **kwargs)
        self.loop = asyncio.get_event_loop()
        self.state = {}
        self.soa_list = []
        self.resolver_list = []
        self.registry = {}
        self.activequeries = {}

    def get_object(self, name=None):
        if name is None:
            return self.registry.values()
        return self.registry[name]

    def register_object(self, name, value):
        self._logger.debug('Registering object {} {}'.format(name, id(value)))
        self.registry[name] = value

    def unregister_object(self, name):
        del self.registry[name]

    def dns_register_soa(self, name):
        if not name.endswith('.'):
            name += '.'
        if name not in self.soa_list:
            self.soa_list.append(name)

    def dns_get_soa(self):
        return list(self.soa_list)

    def dns_register_resolver(self, addr):
        if addr not in self.resolver_list:
            self.resolver_list.append(addr)

    def dns_get_resolver(self, any=True):
        n = 0
        if any:
            n = random.randrange(len(self.resolver_list))
        return self.resolver_list[n]

    def dns_get_timeout(self, record_type = None):
        try:
            return self._dns_timeout[record_type]
        except:
            return self._dns_timeout[None]

    def dns_register_timeout(self, timeouts, record_type = None):
        self._dns_timeout[record_type] = timeouts

    @asyncio.coroutine
    def ddns_register_user(self, fqdn, rdtype, ipaddr):
        # TODO: Move all this complexity to network module? Maybe it's more fitting...
        self._logger.info('Register new user {} @ {}'.format(fqdn, ipaddr))

        # Download user data
        user_data = yield from self.datarepository.get_policy_host(fqdn, default = None)
        if user_data is None:
            self._logger.info('Generating default subscriber data for {}'.format(fqdn))
            user_data = yield from self.datarepository.get_policy_host_default(fqdn, ipaddr)

        host_obj = HostEntry(name=fqdn, fqdn=fqdn, ipv4=ipaddr, services=user_data)
        self.hosttable.add(host_obj)

        # Create network resources
        hostname = ipaddr
        self.network.ipt_add_user(hostname, ipaddr)

        ## Add all user groups
        user_groups = host_obj.get_service('GROUP', [])
        self.network.ipt_add_user_groups(hostname, ipaddr, user_groups)

        ## Add all firewall rules
        fw_d = host_obj.get_service('FIREWALL', {})
        admin_fw = fw_d.setdefault('FIREWALL_ADMIN', [])
        user_fw  = fw_d.setdefault('FIREWALL_USER', [])
        self.network.ipt_add_user_fwrules(hostname, ipaddr, 'admin', admin_fw)
        self.network.ipt_add_user_fwrules(hostname, ipaddr, 'user', user_fw)

        ## CarrierGrade services if available
        if host_obj.has_service('CARRIERGRADE'):
            carriergrade_ipt = host_obj.get_service('CARRIERGRADE', [])
            self.network.ipt_add_user_carriergrade(hostname, carriergrade_ipt)


    @asyncio.coroutine
    def ddns_deregister_user(self, fqdn, rdtype, ipaddr):
        self._logger.info('Deregister user {} @ {}'.format(fqdn, ipaddr))
        if not self.hosttable.has((host.KEY_HOST_FQDN, fqdn)):
            self._logger.warning('Failed to deregister: user {} not found'.format(fqdn))
            return
        host_obj = self.hosttable.get((host.KEY_HOST_FQDN, fqdn))
        self.hosttable.remove(host_obj)
        # Remove network resources
        hostname = ipaddr
        ## Remove all user groups
        user_groups = host_obj.get_service('GROUP', [])
        self.network.ipt_remove_user_groups(hostname, ipaddr, user_groups)
        ## Remove all firewall rules
        self.network.ipt_remove_user(hostname, ipaddr)
        ## CarrierGrade services if available
        if host_obj.has_service('CARRIERGRADE'):
            carriergrade_ipt = host_obj.get_service('CARRIERGRADE', [])
            self.network.ipt_remove_user_fwrules(hostname, carriergrade_ipt)

    @asyncio.coroutine
    def ddns_process(self, query, addr, cback):
        """ Process DDNS query from DHCP server """
        self._logger.debug('process_update')
        try:
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A and rr.ttl != 0:
                    yield from self.ddns_register_user(format(rr.name), rr.rdtype, rr[0].address)
                elif rr.rdtype == dns.rdatatype.A and rr.ttl == 0:
                    yield from self.ddns_deregister_user(format(rr.name), rr.rdtype, rr[0].address)
        except Exception as e:
            self._logger.warning('Failed to process UPDATE DNS message {}'.format(e))
        finally:
            # Send generic DDNS Response NOERROR
            response = dnsutils.make_response_rcode(query)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)


    @asyncio.coroutine
    def _do_resolve_carriergrade(self, query, host_addr, circular_pool = False):
        """ Resolve DNS query with host_addr. Return (dns_rcode, fqdn, rrdata) """
        # Obtain FQDN from query
        fqdn = format(query.question[0].name)
        # Obtain query type to determine resolution model
        rdtype = query.question[0].rdtype
        # Obtain timeouts for given query type
        timeouts=self.dns_get_timeout(rdtype)
        self._logger.debug('Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))

        # Initiate DNS resolution
        response = None
        try:
            resolver = uDNSResolver()
            response = yield from resolver.do_resolve(query, (host_addr, 53), timeouts=timeouts)
        except ConnectionRefusedError:
            # Socket error / DNS Server unavailable
            self._logger.warning('ConnectionRefusedError: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.REFUSED, None, None, None)

        if not response:
            # Timeout expired
            self._logger.warning('TimeoutExpired: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.SERVFAIL, None, None, None)

        # Analyse DNS response based on specific rdtype (A, SRV)
        rrdata_answer = dnsutils.get_section_record(response.answer, 0)
        if not rrdata_answer:
            # Response is empty
            self._logger.warning('EmptyResponse: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.NOERROR, None, None, None)

        ## Record type A
        if rdtype == dns.rdatatype.A:
            _name, _ttl, _rdataclass, _rdatatype, _target_ipaddr = rrdata_answer.split()
            return (dns.rcode.NOERROR, fqdn, _target_ipaddr, _ttl)
        ## Record type SRV and Circular Pool resolution
        elif rdtype == dns.rdatatype.SRV and circular_pool:
            _, _, _, _, _target_prio, _target_weight, _target_port, _target_sfqdn = rrdata_answer.split()
            rrdata_additional = dnsutils.get_section_record(response.additional, 0)
            if not rrdata_additional:
                # Additional section is empty
                self._logger.warning('EmptyResponseAdditional: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
                return (dns.rcode.NOERROR, None, None, None)

            _name, _ttl, _rdataclass, _rdatatype, _target_ipaddr = rrdata_additional.split()
            if _target_sfqdn != _name:
                # Additional section record does not match SRV target domain
                self._logger.warning('WrongRecord: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
                return (dns.rcode.NOERROR, None, None, None)
            # Return A target record
            return (dns.rcode.NOERROR, _name, _target_ipaddr, _ttl)
        else:
            self._logger.warning('UnsupportedType: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.NOERROR, None, None, None)


    @asyncio.coroutine
    def dns_process_rgw_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        # Forward or continue to DNS resolver
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype

        self._logger.warning('LAN SOA: {} ({}) via {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        if self.hosttable.has((host.KEY_HOST_SERVICE, fqdn)):
            # The service exists in RGW
            host_obj = self.hosttable.get((host.KEY_HOST_SERVICE, fqdn))
            service_data = host_obj.get_service_sfqdn(fqdn)
        elif self.hosttable.has_carriergrade(fqdn):
            # There is a host with CarrierGrade service in RGW
            host_obj = self.hosttable.get_carriergrade(fqdn)
            service_data = host_obj.get_service_sfqdn(host_obj.fqdn)
        elif fqdn in self.soa_list:
            # Querying the RGW domain itself
            self._logger.debug('Use NS address for {}'.format(fqdn))
            host_obj = self.hosttable.get((host.KEY_HOST_FQDN, fqdn))
            # Create DNS Response
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, host_obj.ipv4, rdclass=1, ttl=DNSRR_TTL_DEFAULT, recursion_available=True)
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)
            return
        else:
            # FQDN not found! Answer NXDOMAIN
            self._logger.debug('Answer {} with NXDOMAIN'.format(fqdn))
            response = dnsutils.make_response_rcode(query, dns.rcode.NXDOMAIN, recursion_available=True)
            cback(query, addr, response)
            return

        # Evaluate host and service
        # TODO REDO this code from example of CGNAT resolution for SRV then A fallback?
        if service_data['carriergrade'] is True:
            # Resolve via CarrierGrade
            self._logger.debug('Process {} with CarrierGrade resolution'.format(fqdn))
            _rcode, _fqdn, _rdata, _ttl = yield from self._do_resolve_carriergrade(query, host_obj.ipv4)

            if not _rdata:
                response = dnsutils.make_response_rcode(query, _rcode, recursion_available=True)
                cback(query, addr, response)
                return

            # Get service carriergrade and verify the IP address is owned by the host
            host_cgaddrs = host_obj.get_service('CARRIERGRADE', [])
            if not any(getitem(_, 'ipv4') == _rdata for _ in host_cgaddrs):
                # Failed to verify carrier address in host pool - Drop DNS Query
                self._logger.warning('Failed to verify CarrierGrade IP address {} in {}'.format(_rdata, host_cgaddrs))
                response = dnsutils.make_response_rcode(query, dns.rcode.SERVFAIL, recursion_available=True)
                cback(query, addr, response)
                return

            self._logger.info('Completed CarrierGrade resolution: {} @ {}'.format(fqdn, _rdata))
            # Answer query with A type and answer with IPv4 address of the host
            response = dnsutils.make_response_answer_rr(query, fqdn, rdtype, _rdata, rdclass=1, ttl=_ttl, recursion_available=True)
            cback(query, addr, response)

        elif rdtype == dns.rdatatype.A:
            # Resolve A type and answer with IPv4 address of the host
            response = dnsutils.make_response_answer_rr(query, fqdn, rdtype, host_obj.ipv4, rdclass=1, ttl=DNSRR_TTL_DEFAULT, recursion_available=True)
            cback(query, addr, response)

        elif rdtype == dns.rdatatype.PTR:
            # Resolve PTR type and answer with FQDN of the host
            response = dnsutils.make_response_answer_rr(query, fqdn, rdtype, host_obj.fqdn, rdclass=1, ttl=DNSRR_TTL_DEFAULT, recursion_available=True)
            cback(query, addr, response)

        else:
            # Answer with empty records for other types
            response = dnsutils.make_response_rcode(query, dns.rcode.NOERROR, recursion_available=True)
            cback(query, addr, response)


    @asyncio.coroutine
    def dns_process_rgw_lan_nosoa(self, query, addr, cback):
        """ Process DNS query from private network of a name not in a SOA zone """
        # Forward or continue to DNS resolver
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, addr)
        fqdn = q.name
        rdtype = q.rdtype

        self._logger.warning('LAN !SOA: {} ({}) via {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        if key in self.activequeries:
            # Continue ongoing resolution
            resolver = self.activequeries[key]
            resolver.do_continue(query)
            return

        # Create factory for new resolution
        raddr = self.dns_get_resolver()
        resolver = uDNSResolver()
        self.activequeries[key] = resolver
        try:
            response = yield from resolver.do_resolve(query, raddr, timeouts=self.dns_get_timeout(1))
        except ConnectionRefusedError:
            # Failed to resolve DNS query - Drop DNS Query
            self._logger.warning('ConnectionRefusedError: Resolving {} via {}:{}'.format(fqdn, raddr[0], raddr[1]))
            response = dnsutils.make_response_rcode(query, dns.rcode.REFUSED)
        if not response:
            # Failed to resolve DNS query - Drop DNS Query
            self._logger.warning('ResolutionFailure: Failed to resolve address for {} via {}:{}'.format(fqdn, raddr[0], raddr[1]))
            response = dnsutils.make_response_rcode(query, dns.rcode.SERVFAIL)
        # Resolution ended, send generated response
        del self.activequeries[key]
        cback(query, addr, response)


    @asyncio.coroutine
    def dns_process_rgw_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype

        # Initialize to None to prevent AttributeError
        query.reputation_resolver = None
        query.reputation_requestor = None

        self._logger.debug('WAN SOA: {} ({}) via {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        # The service exists in RGW
        if self.hosttable.has((host.KEY_HOST_SERVICE, fqdn)):
            host_obj = self.hosttable.get((host.KEY_HOST_SERVICE, fqdn))
            service_data = host_obj.get_service_sfqdn(fqdn)
        elif self.hosttable.has_carriergrade(fqdn):
            host_obj = self.hosttable.get_carriergrade(fqdn)
            service_data = host_obj.get_service_sfqdn(host_obj.fqdn)
        elif fqdn in self.soa_list:
            self._logger.debug('Use NS address for {}'.format(fqdn))
            host_obj = self.hosttable.get((host.KEY_HOST_FQDN, fqdn))
            # Create DNS Response
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, host_obj.ipv4, rdclass=1, ttl=DNSRR_TTL_DEFAULT)
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)
            return
        else:
            # FQDN not found! Answer NXDOMAIN
            self._logger.debug('Answer {} with NXDOMAIN'.format(fqdn))
            response = dnsutils.make_response_rcode(query, dns.rcode.NXDOMAIN)
            cback(query, addr, response)
            return

        #TODO: At this point we have the host object and the service_data.
        # Maybe it's possible to centralize the PBRA from here instead?
        # Load reputation metadata in DNS query?
        response = self.pbra.dns_preprocess_rgw_wan_soa(query, addr, host_obj, service_data)
        if response is not None:
            self._logger.debug('Preprocessing DNS response\n{}'.format(response))
            cback(query, addr, response)
            return

        # Evaluate host data service
        if service_data['proxy_required'] is True:
            # Resolve via Service Pool
            self._logger.debug('Process {} with ServicePool ({})'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            yield from self._dns_process_rgw_wan_soa_servicepool(query, addr, cback, host_obj, service_data)
        else:
            # Resolve via Circular Pool
            self._logger.debug('Process {} with CircularPool ({})'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            yield from self._dns_process_rgw_wan_soa_circularpool(query, addr, cback, host_obj, service_data)


    @asyncio.coroutine
    def _dns_process_rgw_wan_soa_servicepool(self, query, addr, cback, host_obj, service_data):
        """
        Process DNS query from public network of a name in a SOA zone with "proxy_required" service.
        This function processes only type A DNS query
        """
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype
        allocated_ipv4 = None

        self._logger.warning('WAN SOA ServicePool: {} ({}) via {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        # Sanity check
        assert(service_data['proxy_required'] is True)

        # Process only type A queries for servicepool domains
        if rdtype != dns.rdatatype.A:
            self._logger.info('Answer with empty records for ServicePool domain {} type {}'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            response = dnsutils.make_response_rcode(query, rcode=dns.rcode.NOERROR, recursion_available=False)
            cback(query, addr, response)
            return

        ap_spool = self.pooltable.get('servicepool')
        allocated_ipv4 = ap_spool.allocate()
        ap_spool.release(allocated_ipv4)

        self._logger.debug('Use servicepool address {} pool for {}'.format(allocated_ipv4, fqdn))

        # Create DNS Response type A
        response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, allocated_ipv4, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
        self._logger.debug('Send NORMAL DNS response to {}:{}'.format(addr[0],addr[1]))

        # Send crafted response
        cback(query, addr, response)


    @asyncio.coroutine
    def _dns_process_rgw_wan_soa_circularpool(self, query, addr, cback, host_obj, service_data):
        """
        Process DNS query from public network of a name in a SOA zone.
        This function processes query types A and SRV (nested environments)
        """
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype
        allocated_ipv4 = None

        self._logger.warning('WAN SOA CircularPool: {} ({}) via {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        # Sanity check
        assert(service_data['proxy_required'] is False)

        # Process only type A/SRV queries for circularpool domains
        if rdtype not in (dns.rdatatype.A, dns.rdatatype.SRV):
            self._logger.info('Answer with empty records for CircularPool domain {} type {}'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            response = dnsutils.make_response_rcode(query, rcode=dns.rcode.NOERROR, recursion_available=False)
            cback(query, addr, response)
            return

        # NOTES:
        ## Here we could first apply a pre-policy check, in case we are already in 100% and preserve CG-NAT addresses.
        ## However, the assumption is that real public IP addresses are more limited than CG-NAT addresses, therefore a best-effort
        ## approach is to try to allocate the CG-NAT, and only then, try to allocate on the public side.

        # If the service is carriergrade, resolve it first before allocating our own address
        try:
            if service_data['carriergrade'] is True:
                ## TODO: requestor_addr should be changed to best match from metadata, now using DNS resolver address
                host_ipv4, _service_data = yield from self._dns_resolve_circularpool_carriergrade(host_obj, fqdn, addr, service_data)
            else:
                host_ipv4, _service_data = host_obj.ipv4, service_data
        except:
            # TODO: CarrierGrade resolution failed - Host is not answering -> Return empty records?
            response = dnsutils.make_response_rcode(query, rcode=dns.rcode.NOERROR, recursion_available=False)
            cback(query, addr, response)
            return

        self._logger.debug('WAN SOA CircularPool: {} via {} for {}'.format(fqdn, host_ipv4, _service_data))

        # Decision making based on load level(s) and reputation
        allocated_ipv4 = self.pbra.api_dns_circularpool(query, addr, host_obj, _service_data, host_ipv4)
        if not allocated_ipv4:
            # Failed to allocate an address - Drop DNS Query to trigger reattempt
            self._logger.warning('Failed to allocate an address for {}'.format(fqdn))
            return

        if rdtype == dns.rdatatype.A:
            # Create DNS Response type A
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, allocated_ipv4, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)
        elif rdtype == dns.rdatatype.SRV:
            # Create DNS Response type SRV
            # Check service data and build SFQDN for SRV response, then add SFQDN A record to additional records
            sfqdn = '_{}._{}.{}'.format(_service_data['port'], _service_data['protocol'], fqdn)
            # Build SRV data response - SRV answer with encoded SFQDN and additional with A record for encoded SFQDN
            priority, weight, port, target = 10, 100, _service_data['port'], sfqdn
            srv_rrset = '{} {} {} {}'.format(priority, weight, port, target)
            response = dnsutils.make_response_answer_rr(query, fqdn, 33, srv_rrset, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            _foo = dnsutils.make_response_answer_rr(query, sfqdn, dns.rdatatype.A, allocated_ipv4, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            response.additional = _foo.answer
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)


    @asyncio.coroutine
    def _dns_resolve_circularpool_carriergrade(self, host_obj, fqdn, requestor_addr, service_data):
        """ Resolve FQDN via CarrierGrade host. Return obtained IPv4 address if successful or None """
        host_ipaddr = host_obj.ipv4
        host_cpool_ipv4 = None
        self._logger.warning('WAN SOA CarrierGrade: {} via {}'.format(fqdn, host_ipaddr))

        # Initiate SRV resolution towards CarrierGrade host
        ## Add EDNS0 ECS option to query
        edns0_ecs = edns0.EDNS0_ECSOption(requestor_addr[0], 32, 0)
        edns0_eci = edns0.EDNS0_EClientInfoOption(requestor_addr[0], 17, requestor_addr[1]) #UDP

        # Create SRV query
        query_srv = dnsutils.make_query(fqdn, dns.rdatatype.SRV, options=[edns0_ecs, edns0_eci])
        _rcode, _fqdn, _rdata, _ttl =  yield from self._do_resolve_carriergrade(query_srv, host_ipaddr, circular_pool=True)
        if not _rdata:
            ## TODO: Add fallback to A query type when SRV response is (dns.rcode.NOERROR, None, None)
            query_a = dnsutils.make_query(fqdn, dns.rdatatype.A, options=[edns0_ecs, edns0_eci])
            _rcode, _fqdn, _rdata, _ttl =  yield from self._do_resolve_carriergrade(query_a, host_ipaddr, circular_pool=True)

        if not _rdata:
            self._logger.warning('Failed CarrierGrade resolution: {} via {}'.format(fqdn, host_ipaddr))
            return None

        # Get service carriergrade and verify the IP address is owned by the host
        host_cgaddrs = host_obj.get_service('CARRIERGRADE', [])
        host_cpool_ipv4 = _rdata
        if not any(getitem(_, 'ipv4') == host_cpool_ipv4 for _ in host_cgaddrs):
            # Failed to verify carrier address in host pool - Drop DNS Query
            self._logger.warning('Failed to verify CarrierGrade IP address {} in {}'.format(host_cpool_ipv4, host_cgaddrs))
            return None

        self._logger.info('Completed CarrierGrade resolution: {} @ {} via {}'.format(fqdn, host_cpool_ipv4, host_ipaddr))

        # Analyze fqdn with _fqdn to updated a copy of service_data if needed
        srv_metadata = _fqdn.replace(fqdn, '')
        if srv_metadata:
            # This should contain 2 labels similar to SRV metadata '_portNumber._protoNumber.'
            _port  = int(srv_metadata.split('.')[0].split('_')[1])
            _proto = int(srv_metadata.split('.')[1].split('_')[1])
            _service_data = dict(service_data)
            _service_data['port'] = _port
            _service_data['protocol'] = _proto
        else:
            _service_data = service_data

        # Return allocated IPv4 and best service_data available
        return (host_cpool_ipv4, _service_data)

    @asyncio.coroutine
    def dns_process_rgw_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype
        self._logger.warning('Drop DNS query for non-SOA domain: {} ({}) via {}'.format(fqdn, dns.rdatatype.to_text(rdtype), query.transport))
        # Drop DNS Query
        return

        '''
    def dns_process_ces_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        pass

    def dns_process_ces_lan_nosoa(self, query, addr, cback):
        """ Process DNS query from private network of a name not in a SOA zone """
        pass

    def dns_process_ces_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        self._logger.warning('dns_process_ces_wan_soa')
        # Drop DNS Query
        return

    def dns_process_ces_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        self._logger.warning('dns_process_ces_wan_nosoa')
        # Drop DNS Query
        return
        '''





class PacketCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('PacketCallbacks')
        utils3.set_attributes(self, **kwargs)

    def _format_5tuple(self, packet_fields):
        if packet_fields['proto'] == 6:
            return '{}:{} {}:{} [{}] (TTL {}) flags/{:08b}'.format(packet_fields['src'], packet_fields['sport'],
                                                                  packet_fields['dst'], packet_fields['dport'],
                                                                  packet_fields['proto'], packet_fields['ttl'],
                                                                  packet_fields['tcp_flags'])
        elif packet_fields['proto'] == 132:
            return '{}:{} {}:{} [{}] (TTL {}) tag/{:x}'.format(packet_fields['src'], packet_fields['sport'],
                                                                packet_fields['dst'], packet_fields['dport'],
                                                                packet_fields['proto'], packet_fields['ttl'],
                                                                packet_fields['sctp_tag'])
        else:
            return '{}:{} {}:{} [{}] (TTL {})'.format(packet_fields['src'], packet_fields['sport'],
                                                      packet_fields['dst'], packet_fields['dport'],
                                                      packet_fields['proto'], packet_fields['ttl'])

    def packet_in_circularpool(self, packet):
        # TODO: Improve lookup processing to also consider dns_bind flag of a waiting connection
        #       > Match sending client with connection.query.reputation_resolver before claim
        # TODO: We have modified in connection.py the way of creating the 3-tuple and 5-tuple match
        #       > This would require up to 3 keys for the 5-tuple match, to include wildcards for remote_port and protocol
        #       > However, we do not have any use for 5-tuple at this point, so it's probably best to remove it, as it won't be tested

        # Get IP data
        data = self.network.ipt_nfpacket_payload(packet)
        # Parse packet
        packet_fields = network_helper3.parse_packet_custom(data)
        # Select appropriate values for building the keys
        src, dst = packet_fields['src'], packet_fields['dst']
        proto, ttl = packet_fields['proto'], packet_fields['ttl']
        sport = packet_fields.setdefault('sport', 0)
        dport = packet_fields.setdefault('dport', 0)
        sender = '{}:{}'.format(src, sport)
        self._logger.debug('Received PacketIn: {}'.format(packet_fields))

        # Build connection lookup keys
        # key1: Basic IP destination for early drop
        key1 = (connection.KEY_RGW, dst)
        # key2: Full fledged 5-tuple (not in use by the system, yet)
        #key2 = (connection.KEY_RGW, dst, dport, src, sport, proto)
        # key3: Semi-full fledged 3-tuple  (SFQDN+)
        key3 = (connection.KEY_RGW, dst, dport, proto)
        # key4: Basic 3-tuple with wildcards (SFQDN-)
        key4 = (connection.KEY_RGW, dst, dport, 0)
        # key5: Basic 3-tuple with wildcards (SFQDN-)
        key5 = (connection.KEY_RGW, dst, 0, proto)
        # key6: Basic 3-tuple with wildcards (FQDN)
        key6 = (connection.KEY_RGW, dst, 0, 0)

        # Lookup connection in table with basic key for for early drop
        if not self.connectiontable.has(key1):
            self._logger.info('No connection reserved for IP {}: [{}]'.format(dst,self._format_5tuple(packet_fields)))
            self.network.ipt_nfpacket_drop(packet)
            return

        # Lookup connection in table with rest of the keys
        conn = None
        for key in [key3, key4, key5, key6]:
            if self.connectiontable.has(key):
                self._logger.debug('Connection found for n-tuple* {}: [{}]'.format(key,self._format_5tuple(packet_fields)))
                conn = self.connectiontable.get(key)
                break

        if conn is None:
            self._logger.warning('No connection found for packet: [{}]'.format(self._format_5tuple(packet_fields)))
            self.network.ipt_nfpacket_drop(packet)
            return

        # The connection belongs to an SLA marked DNS server
        if conn.dns_bind and conn.dns_host.contains(src):
            self._logger.info('Connection reserved found for remote host {}: {}'.format(src, conn.dns_host))
        elif conn.dns_bind:
            self._logger.info('Connection not reserved for remote host {}: {}'.format(src, conn.dns_host))
            return

        # DNAT to private host
        self._logger.info('DNAT of {} to {} via {}: [{}]'.format(conn.fqdn, conn.private_ip, dst, self._format_5tuple(packet_fields)))
        self.network.ipt_nfpacket_dnat(packet, conn.private_ip)

        if conn.post_processing(self.connectiontable, src, sport):
            # Delete connection and trigger IP address release
            self.connectiontable.remove(conn)
