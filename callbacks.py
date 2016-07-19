import asyncio
import utils
import logging
import random
import pprint

import customdns
from customdns import dnsutils
from customdns.dnsresolver import DNSResolver

import dns
import dns.message
import dns.zone
import dns.rcode

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

import host
from host import HostEntry

import connection
from connection import ConnectionLegacy

from functools import partial


LOGLEVELCALLBACK = logging.INFO

class DNSCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('DNSCallbacks')
        self._logger.setLevel(LOGLEVELCALLBACK)
        utils.set_attributes(self, **kwargs)
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
            n = random.randint(0, len(self.resolver_list) - 1)
        return self.resolver_list[n]

    def ddns_register_user(self, name, rdtype, ipaddr):
        self._logger.info('Register new user {} @ {}'.format(name, ipaddr))
        # Download user data
        user_services = self.datarepository.get_subscriber_service(name, None)
        #DEBUG
        #print(user_services)
        user_data = {'ipv4':ipaddr, 'fqdn': name, 'services': user_services}
        host_obj = HostEntry(name=name, **user_data)
        self.hosttable.add(host_obj)
        # Create network resources
        self.network.ipt_add_user(ipaddr)
        ## Add all firewall rules
        admin_fw  = host_obj.get_service('FIREWALL_ADMIN', [])
        parental_fw  = host_obj.get_service('FIREWALL_PARENTAL', [])
        legacy_fw = host_obj.get_service('FIREWALL_LEGACY', [])
        self.network.ipt_add_user_fwrules(ipaddr, 'admin', admin_fw)
        self.network.ipt_add_user_fwrules(ipaddr, 'parental', parental_fw)
        self.network.ipt_add_user_fwrules(ipaddr, 'legacy', legacy_fw)

    def ddns_deregister_user(self, name, rdtype, ipaddr):
        self._logger.info('Deregister user {} @ {}'.format(name, ipaddr))
        if not self.hosttable.has((host.KEY_HOST_FQDN, name)):
            self._logger.warning('Failed to deregister: user {} not found'.format(name))
            return
        host_obj = self.hosttable.get((host.KEY_HOST_FQDN, name))
        self.hosttable.remove(host_obj)
        # Remove network resources
        self.network.ipt_remove_user(ipaddr)

    def ddns_process(self, query, addr, cback):
        """ Process DDNS query from DHCP server """
        self._logger.debug('process_update')
        try:
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A and rr.ttl != 0:
                    self.ddns_register_user(rr.name.to_text(), rr.rdtype, rr[0].address)
                elif rr.rdtype == dns.rdatatype.A and rr.ttl == 0:
                    self.ddns_deregister_user(rr.name.to_text(), rr.rdtype, rr[0].address)

            # Send generic DDNS Response NOERROR
            response = dnsutils.make_response_rcode(query)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)
        except Exception as e:
            self._logger.error('Failed to process UPDATE DNS message {}'.format(e))

    def dns_process_rgw_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        # This function is not performed by BIND and its local zone
        pass

    def dns_process_rgw_lan_nosoa(self, query, addr, cback):
        # This function is not performed by BIND and its forwarder configuration
        pass
        """ Process DNS query from private network of a name not in a SOA zone """
        '''
        # Forward or continue to DNS resolver
        self._logger.warning('dns_process_rgw_lan_nosoa')
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, addr)

        if key not in self.activequeries:
            # Create new resolution
            self._logger.warning(
                'Resolve normal query {0} {1}/{2} from {3}:{4}'.format(
                    query.id, q.name.to_text(), dns.rdatatype.to_text(
                        q.rdtype), addr[0], addr[1]))
            # Create factory
            cb_f = self._do_callback
            resolver = DNSResolver(query, addr, cb_f, timeouts=None) #Passive resolution
            self.activequeries[key] = (resolver, cback)
            raddr = self.dns_get_resolver()
            self.loop.create_task(self.loop.create_datagram_endpoint(lambda: resolver, remote_addr=raddr))
        else:
            # Continue ongoing resolution
            self._logger.warning(
                'Continue query resolution {0} {1}/{2} from {3}:{4}'.format(
                    query.id, q.name.to_text(), dns.rdatatype.to_text(
                        q.rdtype), addr[0], addr[1]))
            (resolver, cback) = self.activequeries[key]
            resolver.process_query(query, addr)
        '''

    def dns_process_ces_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

    def dns_process_ces_lan_nosoa(self, query, addr, cback):
        """ Process DNS query from private network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

    def dns_process_rgw_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        self._logger.debug('dns_process_rgw_wan_soa')
        fqdn = query.question[0].name.to_text()
        rdtype = query.question[0].rdtype
        if not self.hosttable.has((host.KEY_HOST_SERVICE, fqdn)):
            # FQDN not found! Answer NXDOMAIN
            response = dnsutils.make_response_rcode(query, dns.rcode.NXDOMAIN)
            self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)
        elif rdtype == 1:
            # Resolve A type via Circular Pool
            self._dns_process_rgw_wan_soa_a(query, addr, cback)
        else:
            # Answer with empty records for other types
            response = dnsutils.make_response_rcode(query)
            self._logger.warning('Send empty DNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, addr, response)


    def _dns_process_rgw_wan_soa_a(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        # TODO: Check allocation policy is not exceeded for neither CES and HOST
        self._logger.debug('_dns_process_rgw_wan_soa_a')

        # Get host object
        fqdn = query.question[0].name.to_text()
        host_obj = self.hosttable.lookup((host.KEY_HOST_SERVICE, fqdn))
        # Get Circular Pool address pool
        ap_cpool = self.pooltable.get('circularpool')
        # Check for expired connections
        self.connectiontable.update_all_rgw()
        # Get host usage stats of the pool
        host_conns = self.connectiontable.lookup((connection.KEY_RGW, host_obj.ipv4), check_expire=False)
        #print('host_conns {}'.format(host_conns))
        # Get global usage stats of the pool
        pool_size, pool_allocated, pool_available = ap_cpool.get_stats()
        #print('pool_size, pool_allocated, pool_available {}'.format((pool_size, pool_allocated, pool_available)))
        # Get data service from FQDN
        service_data = host_obj.get_service_sfqdn(fqdn)

        if service_data['proxy_required']:
            self._logger.debug('Use servicepool address pool for {}'.format(fqdn))
            ap_spool = self.pooltable.get('servicepool')
            allocated_ipv4 = ap_spool.allocate()
            ap_spool.release(allocated_ipv4)
        else:
            self._logger.debug('Use circularpool address pool for {}'.format(fqdn))
            allocated_ipv4 = self._create_connectionentryrgw(query, addr, cback)

        if not allocated_ipv4:
            # Failed to allocate an address - Drop DNS Query
            self._logger.info('Failed to allocate an address for {}'.format(fqdn))
            return

        # Create DNS Response
        response = dnsutils.make_response_answer_rr(query, fqdn, 1, allocated_ipv4, rdclass=1, ttl=0)
        self._logger.debug('Send DNS response to {}:{}'.format(addr[0],addr[1]))
        cback(query, addr, response)

    def dns_process_rgw_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        self._logger.warning('dns_process_rgw_wan_nosoa')
        # For testing purposes
        # Answer with empty records for other types
        #response = dnsutils.make_response_rcode(query)
        #self._logger.warning('Send empty DNS response to {}:{}'.format(addr[0],addr[1]))
        #cback(query, addr, response)
        # Drop DNS Query
        return

    def dns_process_ces_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

    def dns_process_ces_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

    def _create_connectionentryrgw(self, query, addr, cback):
        """ Return the allocated IPv4 address """
        allocated_ipv4 = None
        # Get host object
        fqdn = query.question[0].name.to_text()
        host_obj = self.hosttable.lookup((host.KEY_HOST_SERVICE, fqdn))
        # Get data service from FQDN
        service_data = host_obj.get_service_sfqdn(fqdn)
        # Get Circular Pool address pool
        ap_cpool = self.pooltable.get('circularpool')
        # Iterate all RealmGateway connections and try to reuse existing allocated IP addresses
        for ipv4 in ap_cpool.get_allocated():
            addrinuse = False
            conns = self.connectiontable.get((connection.KEY_RGW, ipv4))
            for conn in conns:
                c_port, c_proto = conn.outbound_port, conn.protocol
                d_port, d_proto = service_data['port'], service_data['protocol']
                self._logger.debug('Comparing {} vs {} @{}'.format((c_port, c_proto),(d_port, d_proto), ipv4))
                # The following statements match when IP overloading cannot be performed
                if (c_port == 0 and c_proto == 0) or (d_port == 0 and d_proto == 0):
                    self._logger.debug('0. Port & Protocol blocked')
                    addrinuse = True
                    break
                elif (c_port == d_port) and (c_proto == d_proto or c_proto == 0 or d_proto == 0):
                    self._logger.debug('1. Port blocked')
                    addrinuse = True
                    break
                elif (c_proto == d_proto) and (c_port == 0 or d_port == 0):
                    self._logger.debug('2. Port blocked')
                    addrinuse = True
                    break

            if not addrinuse:
                allocated_ipv4 = ipv4
                self._logger.warning('Overloading {} for {}!!'.format(ipv4, fqdn))
                break

        if allocated_ipv4 is None:
            self._logger.debug('Impossible to overload existing connections for {}. Allocate new address from CircularPool'.format(fqdn))
            allocated_ipv4 = ap_cpool.allocate()
        if allocated_ipv4 is None:
            return None
        
        self._logger.info('Allocated IP address from Circular Pool: {}'.format(allocated_ipv4))
        
        # Create RealmGateway connection
        conn_param = {'private_ip': host_obj.ipv4, 'private_port': service_data['port'],
                      'outbound_ip': allocated_ipv4, 'outbound_port': service_data['port'],
                      'protocol': service_data['protocol'], 'fqdn': fqdn, 'dns_server': addr[0] }
        new_conn = ConnectionLegacy(**conn_param)
        # Monkey patch delete function
        new_conn.delete = partial(self._delete_connectionentryrgw, new_conn)
        # Add connection to table
        self.connectiontable.add(new_conn)
        return allocated_ipv4

    def _delete_connectionentryrgw(self, conn):
        # Get Circular Pool address pool
        ap_cpool = self.pooltable.get('circularpool')
        ipaddr = conn.outbound_ip
        # Get RealmGateway connections
        if self.connectiontable.has((connection.KEY_RGW, ipaddr)):
            self._logger.warning('Cannot release IP address to Circular Pool: {} still in use'.format(ipaddr))
            return
        ap_cpool.release(ipaddr)
        self._logger.info('Released IP address to Circular Pool: {}'.format(ipaddr))

    def _do_callback(self, query, addr, response=None):
        try:
            q = query.question[0]
            key = (query.id, q.name, q.rdtype, addr)
            (resolver, cback) = self.activequeries.pop(key)
        except KeyError:
            self._logger.warning(
                'Query has already been processed {0} {1}/{2} from {3}:{4}'.format(
                    query.id, q.name, dns.rdatatype.to_text(q.rdtype),
                    addr[0], addr[1]))
            return

        if response is None:
            self._logger.warning('??? This seems a good place to create negative caching ???')

        # Callback to send response to host
        cback(query, addr, response)

class PacketCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('PacketCallbacks')
        self._logger.setLevel(LOGLEVELCALLBACK)
        utils.set_attributes(self, **kwargs)

    def packet_in_circularpool(self, packet):
        # Get IP data
        data = self.network.ipt_nfpacket_payload(packet)
        # Parse packet
        packet_fields = utils.parse_packet_custom(data)
        # Select appropriate values for building the keys
        src, dst, proto = packet_fields['src'], packet_fields['dst'], packet_fields['proto']
        sport, dport =  (0,0)
        if 'dport' in packet_fields:
            sport, dport = (packet_fields['sport'],packet_fields['dport'])

        # Build connection lookup keys
        # key1: Basic IP destination for early drop
        key1 = (connection.KEY_RGW, dst)
        # key2: Full fledged 5-tuple
        key2 = (connection.KEY_RGW, dst, dport, src, sport, proto)
        # key3: Semi-full fledged 3-tuple
        key3 = (connection.KEY_RGW, dst, dport, proto)
        # key4: Basic 3-tuple with wildcards
        key4 = (connection.KEY_RGW, dst, 0, 0)
        # key5: Basic 3-tuple with wildcards
        key5 = (connection.KEY_RGW, dst, dport, 0)
        # key6: Basic 3-tuple with wildcards
        key6 = (connection.KEY_RGW, dst, 0, proto)

        # Lookup connection in table with basic key for for early drop
        if not self.connectiontable.has(key1):
            self._logger.info('No connection found for IP: {}'.format(dst))
            return

        # Lookup connection in table with rest of the keys
        conn = None
        for key in [key2, key3, key4, key5, key6]:
            if self.connectiontable.has(key):
                self._logger.info('Connection found for n-tuple*: {}'.format(key))
                conn = self.connectiontable.get(key)
                break

        if conn is None:
            self._logger.warning('No connection found for packet: {}'.format(packet_fields))
            return

        # DNAT to private host
        self.network.ipt_nfpacket_dnat(packet, conn.private_ip)
        # Delete connection and trigger IP address release
        self.connectiontable.remove(conn)

