import asyncio
import logging
import random
import pprint
from functools import partial
from operator import getitem

from helpers_n_wrappers import utils3
from helpers_n_wrappers import network_helper3

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
        if not timeouts:
            # Do not register empty timeout schemes
            return
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
        """ Resolve DNS query with host_addr. Return (dns_rcode, ipv4, service_data) """
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
            self._logger.debug('ConnectionRefusedError: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.REFUSED, None, None)

        if not response:
            # Timeout expired
            self._logger.debug('TimeoutExpired: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.SERVFAIL, None, None)

        # Analyse DNS response based on specific rdtype (A, SRV)
        rrdata_answer = dnsutils.get_section_record(response.answer, 0)
        if not rrdata_answer:
            # Response is empty
            self._logger.debug('EmptyResponse: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.NOERROR, None, None)

        ## Record type A
        if rdtype == dns.rdatatype.A:
            _service_data = {'port':0, 'protocol':0, 'proxy_required': False}
            _name, _ttl, _rdataclass, _rdatatype, _target_ipaddr = rrdata_answer.split()
            return (dns.rcode.NOERROR, _target_ipaddr, _service_data)

        ## Record type SRV and Circular Pool resolution
        elif rdtype == dns.rdatatype.SRV and circular_pool:
            # Build service_data dictionary
            _, _, _, _, _target_prio, _target_weight, _target_port, _target_sfqdn = rrdata_answer.split()
            srv_metadata = _target_sfqdn.replace(fqdn, '')
            # This should contain 2 labels similar to SRV metadata '_portNumber._protoNumber.'
            _port  = int(srv_metadata.split('.')[0].split('_')[1])
            _proto = int(srv_metadata.split('.')[1].split('_')[1])
            _service_data = {'port':_port, 'protocol':_proto, 'proxy_required': False}
            # Find IPv4 address
            rrdata_additional = dnsutils.get_section_record(response.additional, 0)
            _name, _ttl, _rdataclass, _rdatatype, _target_ipaddr = rrdata_additional.split()
            # Return A target record
            return (dns.rcode.NOERROR, _target_ipaddr, _service_data)

        ## Record type TXT and Circular Pool resolution
        elif rdtype == dns.rdatatype.TXT and circular_pool:
            # Build service_data dictionary
            _service_data = {}
            ## For some reason, TXT data (_target_txt) is enclosed in quotes '"' so we have to remove them
            #['test103.nest0.gwa.cesproto.re2ee.org.', '0', 'IN', 'TXT', '"proxy_False.port_0.protocol_0.test103.nest0.gwa.cesproto.re2ee.org."']
            _name, _ttl, _rdataclass, _rdatatype, _target_txt = rrdata_answer.split()
            txt_metadata = _target_txt.replace('"', '').replace(fqdn, '')
            for label in txt_metadata.split('.'):
                if label == '':
                    continue
                k, v = label.split('_')
                if k == 'proxy':
                    str2bool = lambda x: x.lower() in ("yes", "true", "t", "1")
                    _service_data['proxy_required'] = str2bool(v)
                elif k == 'port':
                    _service_data['port'] = int(v)
                elif k == 'protocol':
                    _service_data['protocol'] = int(v)
            # Find IPv4 address
            rrdata_additional = dnsutils.get_section_record(response.additional, 0)
            _name, _ttl, _rdataclass, _rdatatype, _target_ipaddr = rrdata_additional.split()
            # Return IPv4 address and service_data
            return (dns.rcode.NOERROR, _target_ipaddr, _service_data)
        else:
            self._logger.warning('UnsupportedType: Resolve CarrierGrade domain: [{}] {} via {}'.format(dns.rdatatype.to_text(rdtype), fqdn, host_addr))
            return (dns.rcode.NOERROR, None, None)


    @asyncio.coroutine
    def dns_process_rgw_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        # Forward or continue to DNS resolver
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype

        self._logger.debug('LAN SOA: {} ({}) from {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        if self.hosttable.has((host.KEY_HOST_SERVICE, fqdn)):
            # The service exists in RGW
            host_obj = self.hosttable.get((host.KEY_HOST_SERVICE, fqdn))
            service_data = host_obj.get_service_sfqdn(fqdn)
            self._logger.debug('Found service: {} / {}'.format(fqdn, service_data))
        elif self.hosttable.has_carriergrade(fqdn):
            # There is a host with CarrierGrade service in RGW
            host_obj, service_data = self.hosttable.get_carriergrade(fqdn)
            self._logger.debug('Found CarrierGrade service: {} / {}'.format(fqdn, service_data))
        elif fqdn in self.soa_list:
            # Querying the RGW domain itself
            self._logger.debug('Use NS address: {}'.format(fqdn))
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

        # TODO: Modify this to propagate original queries if carriergrade, and only override certain types, e.g. dns.rdatatype.A,

        # Evaluate host and service
        if service_data['carriergrade'] is True:
            # Resolve via CarrierGrade
            self._logger.debug('Process {} with CarrierGrade resolution'.format(fqdn))
            _rcode, _ipv4, _service_data = yield from self._dns_resolve_circularpool_carriergrade(host_obj, fqdn, addr, service_data)
            if not _ipv4:
                # Propagate rcode value
                response = dnsutils.make_response_rcode(query, rcode=_rcode, recursion_available=True)
                cback(query, addr, response)
                return

            self._logger.debug('Completed LAN CarrierGrade resolution: {} @ {}'.format(fqdn, _ipv4))
            # Answer query with A type and answer with IPv4 address of the host
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, _ipv4, rdclass=1, ttl=DNSRR_TTL_DEFAULT, recursion_available=True)
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

        self._logger.info('LAN !SOA: {} ({}) from {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

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
            response = yield from resolver.do_resolve(query, raddr, timeouts=self.dns_get_timeout(rdtype))
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

        self._logger.debug('WAN SOA: {} ({}) from {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

        if self.hosttable.has((host.KEY_HOST_SERVICE, fqdn)):
            # The service exists in RGW
            host_obj = self.hosttable.get((host.KEY_HOST_SERVICE, fqdn))
            service_data = host_obj.get_service_sfqdn(fqdn)
            self._logger.debug('Found service: {} / {}'.format(fqdn, service_data))
        elif self.hosttable.has_carriergrade(fqdn):
            # There is a host with CarrierGrade service in RGW
            host_obj, service_data = self.hosttable.get_carriergrade(fqdn)
            self._logger.debug('Found CarrierGrade service: {} / {}'.format(fqdn, service_data))
        elif fqdn in self.soa_list:
            # Querying the RGW domain itself
            self._logger.debug('Use NS address: {}'.format(fqdn))
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
        response = self.pbra.pbra_dns_preprocess_rgw_wan_soa(query, addr, host_obj, service_data)
        if response is not None:
            self._logger.debug('Preprocessing DNS response\n{}'.format(response))
            cback(query, addr, response)
            return

        self._logger.debug('Continue after pre-processing query / {}'.format(service_data))

        # Process only type A/SRV/TXT queries for servicepool domains
        if rdtype not in (dns.rdatatype.A, dns.rdatatype.SRV, dns.rdatatype.TXT):
            self._logger.debug('Answer with empty records for public domain {} type {}'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            response = dnsutils.make_response_rcode(query, rcode=dns.rcode.NOERROR, recursion_available=False)
            cback(query, addr, response)
            return

        # If the service is carriergrade, resolve it first before allocating our own address
        _ipv4, _service_data = host_obj.ipv4, service_data
        if service_data['carriergrade'] is True:
            _carriergrade_fqdn = fqdn
            if service_data['alias'] is True:
                # Use original FQDN in carriergrade resolutions, instead of the alias CNAMEd FQDN
                _carriergrade_fqdn = service_data['_fqdn']
                self._logger.debug('CarrierGrade resolution using original fqdn={} instead of alias fqdn={}'.format(_carriergrade_fqdn, fqdn))
            _rcode, _ipv4, _service_data = yield from self._dns_resolve_circularpool_carriergrade(host_obj, _carriergrade_fqdn, addr, service_data)

        if _ipv4 is None:
            # Propagate rcode value
            response = dnsutils.make_response_rcode(query, rcode=_rcode, recursion_available=False)
            cback(query, addr, response)
            return

        # Use PBRA to allocate an address according to policy
        allocated_ipv4 = self.pbra.pbra_dns_process_rgw_wan_soa(query, addr, host_obj, _service_data, _ipv4)

        # Evaluate allocated address
        if not allocated_ipv4:
            # Failed to allocate an address - Drop DNS Query to trigger reattempt
            self._logger.warning('Failed to allocate an address for {}'.format(fqdn))
            return

        # Create DNS response based on received query type
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
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.SRV, srv_rrset, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            _foo = dnsutils.make_response_answer_rr(query, sfqdn, dns.rdatatype.A, allocated_ipv4, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            response.additional = _foo.answer
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)

        elif rdtype == dns.rdatatype.TXT:
            # Create DNS Response type TXT
            # Build TXT data response - TXT answer with encoded data service and additional with A record for IP address
            txt_rrset = 'proxy_{}.port_{}.protocol_{}.{}'.format(_service_data['proxy_required'], _service_data['port'], _service_data['protocol'], fqdn)
            response = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.TXT, txt_rrset, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            _foo = dnsutils.make_response_answer_rr(query, fqdn, dns.rdatatype.A, allocated_ipv4, rdclass=1, ttl=DNSRR_TTL_CIRCULARPOOL)
            response.additional = _foo.answer
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)

        #self._logger.debug('/WAN SOA: {} ({}) from {}/{}\n\n'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))

    @asyncio.coroutine
    def _dns_resolve_circularpool_carriergrade(self, host_obj, fqdn, requestor_addr, service_data):
        """ Resolve FQDN via CarrierGrade host. Return a tuple of (rcode, IPv4 address, service_data) if successful or (None, None) """
        host_ipaddr = host_obj.ipv4
        self._logger.debug('SOA CarrierGrade: {} via {}'.format(fqdn, host_ipaddr))

        # Initiate SRV resolution towards CarrierGrade host
        ## Add EDNS0 ECS option to query
        edns0_ecs = edns0.EDNS0_ECSOption(requestor_addr[0], 32, 0)
        edns0_eci = edns0.EDNS0_EClientInfoOption(requestor_addr[0], 17, requestor_addr[1]) #UDP

        # Create resolution loop
        _ipv4 = None
        _rcode = dns.rcode.SERVFAIL
        for rdtype in [dns.rdatatype.TXT, dns.rdatatype.SRV, dns.rdatatype.A]:
            try:
                query_rdtype = dnsutils.make_query(fqdn, rdtype, options=[edns0_ecs, edns0_eci])
                _rcode, _ipv4, _service_data =  yield from self._do_resolve_carriergrade(query_rdtype, host_ipaddr, circular_pool=True)
                if _ipv4:
                    # Resolution succeeded
                    break
            except Exception as e:
                self._logger.warning('Exception while performing CarrierGrade resolution: {} ({}) via {}'.format(fqdn, dns.rdatatype.to_text(rdtype), host_ipaddr))

        if not _ipv4:
            self._logger.warning('Failed CarrierGrade resolution: {} via {}'.format(fqdn, host_ipaddr))
            return (_rcode, None, None)

        # Get service carriergrade and verify the IP address is owned by the host
        host_cgaddrs = host_obj.get_service('CARRIERGRADE', [])
        host_cpool_ipv4 = _ipv4
        if not any(getitem(_, 'ipv4') == _ipv4 for _ in host_cgaddrs):
            # Failed to verify carrier address in host pool - Drop DNS Query
            self._logger.warning('Failed to verify CarrierGrade IP address {} in {}'.format(_ipv4, host_cgaddrs))
            return (_rcode, None, None)

        self._logger.info('Completed CarrierGrade resolution: {} @ {} via {} / {}'.format(fqdn, _ipv4, host_ipaddr, _service_data))
        # Return allocated IPv4 and best service_data available
        return (_rcode, _ipv4, _service_data)

    @asyncio.coroutine
    def dns_process_rgw_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = format(query.question[0].name)
        rdtype = query.question[0].rdtype
        self._logger.warning('Drop DNS query for non-SOA domain: {} ({}) from {}/{}'.format(fqdn, dns.rdatatype.to_text(rdtype), addr[0], query.transport))
        # TODO: Feed this to the algorithm as untrusted events? What about misconfigured DNS servers?
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

    @asyncio.coroutine
    def dns_error_response(self, query, addr, cback, rcode=dns.rcode.REFUSED):
        # Create error response
        response = dnsutils.make_response_rcode(query, rcode=rcode, recursion_available=True)
        cback(query, addr, response)


class PacketCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('PacketCallbacks')
        utils3.set_attributes(self, **kwargs)

    def _format_5tuple(self, packet_fields):
        if packet_fields['proto'] == 6:
            return '{}:{} {}:{} [{}] (TTL {}) flags/{:08b} seq/{} ack{}'.format(packet_fields['src'], packet_fields['sport'],
                                                                                packet_fields['dst'], packet_fields['dport'],
                                                                                packet_fields['proto'], packet_fields['ttl'],
                                                                                packet_fields['tcp_flags'],packet_fields['tcp_seq'],
                                                                                packet_fields['tcp_ack'])
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

        # Pre-emptive check with PBRA if the packet is blacklister
        response = self.pbra.pbra_data_preaccept_circularpool(data, packet_fields)
        if response is False:
            self._logger.info('Reject / CircularPool pre-emptive check failed: [{}]'.format(dst,self._format_5tuple(packet_fields)))
            self.network.ipt_nfpacket_reject(packet)
            self.pbra.pbra_data_track_circularpool(data, packet_fields)
            return

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
            self._logger.debug('Reject / No connection reserved for IP {}: [{}]'.format(dst,self._format_5tuple(packet_fields)))
            self.network.ipt_nfpacket_reject(packet)
            self.pbra.pbra_data_track_circularpool(data, packet_fields)
            return

        # Lookup connection in table with rest of the keys
        conn = None
        for key in [key3, key4, key5, key6]:
            if self.connectiontable.has(key):
                self._logger.debug('Connection found for n-tuple* {}: [{}]'.format(key,self._format_5tuple(packet_fields)))
                conn = self.connectiontable.get(key)
                break

        if conn is None:
            self._logger.warning('Reject / No connection found for packet: [{}]'.format(self._format_5tuple(packet_fields)))
            self.network.ipt_nfpacket_reject(packet)
            self.pbra.pbra_data_track_circularpool(data, packet_fields)
            return

        # The connection belongs to an SLA marked DNS server
        if conn.dns_bind and conn.dns_host.contains(src):
            self._logger.info('Connection reserved found for remote host {}: {}'.format(src, conn.dns_host))
        elif conn.dns_bind:
            self._logger.info('Reject / Connection not reserved for remote host {}: {}'.format(src, conn.dns_host))
            self.network.ipt_nfpacket_reject(packet)
            self.pbra.pbra_data_track_circularpool(data, packet_fields)
            return

        # DNAT to private host
        self._logger.info('DNAT of [{}] to {} via {}'.format(self._format_5tuple(packet_fields), conn.private_ip, conn.fqdn))
        self.network.ipt_nfpacket_dnat(packet, conn.private_ip)

        if conn.post_processing(self.connectiontable, src, sport):
            # Delete connection and trigger IP address release
            self.connectiontable.remove(conn)
