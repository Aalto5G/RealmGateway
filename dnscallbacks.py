import asyncio
import utils
import logging
import random

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

from host import HostEntry

from connection import ConnectionEntryRGW

class DNSCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('DNSCallbacks')
        self._logger.setLevel(logging.WARNING)
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
        self._logger.warning('Register new user {} @ {}'.format(name, ipaddr))
        # Download user data
        user_services = self.datarepository.get_subscriber_service(name, None)
        user_data = {'ipv4':ipaddr, 'fqdn': name, 'services': user_services[name]}
        host = HostEntry(name=name, **user_data)
        self.hosttable.add(host)

    def ddns_deregister_user(self, name, rdtype, ipaddr):
        self._logger.warning('Deregister user {} @ {}'.format(name, ipaddr))
        host = self.hosttable.lookup(name)
        self.hosttable.remove(host)

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
        self._logger.warning('dns_process_rgw_wan_soa')
        fqdn = query.question[0].name.to_text()
        rdtype = query.question[0].rdtype
        print('Received query for {}'.format(fqdn))
        host = self.hosttable.lookup(fqdn)
        if host is None:
            # Host not found! Answer NXDOMAIN
            response = dnsutils.make_response_rcode(query, dns.rcode.NXDOMAIN)

        # Resolve locally
        elif rdtype == 1:
            # Resolve A type - Circular Pool
            (port, protocol) = host.get_service_fqdn_mapping(fqdn)
            #d1 = {'public_ipv4':'1.2.3.4','dns_ipv4':'8.8.8.8','host_ipv4':'192.168.0.100','host_fqdn':'host100.rgw','timeout':2.0}
            conn = ConnectionEntryRGW(public_ipv4='1.2.3.4', public_port=port, public_protocol=protocol,
                                      dns_ipv4=addr[0], host_fqdn=fqdn, host_ipv4=host.ipv4, timeout=2.0)
            print('Creating new connection')
            print(conn)
            #self.hosttable.add(conn)
            response = dnsutils.make_response_answer_rr(query, fqdn, 1, '1.2.3.4', rdclass=1, ttl=0)
        else:
            # Answer with empty records for other types
            response = dnsutils.make_response_rcode(query)

        self._logger.debug('Sent DNS response to {}:{}'.format(addr[0],addr[1]))
        cback(query, addr, response)


    def dns_process_rgw_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        self._logger.warning('dns_process_rgw_wan_nosoa')
        print(addr)
        print(query)
        fqdn = query.question[0].name.to_text()
        # Discard
        pass

    def dns_process_ces_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

    def dns_process_ces_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass

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