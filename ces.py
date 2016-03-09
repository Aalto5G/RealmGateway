#!/usr/bin/python3.5

import asyncio
import addresspool
import configparser
import dns
import mydns
import logging
import signal
import sys
import traceback
import yaml

from utils import is_ipv4, is_ipv6

LOGLEVELCES = logging.WARNING

class CustomerEdgeSwitch(object):
    def __init__(self, name='CustomerEdgeSwitch'):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELCES)
        
        # Get event loop
        self._loop = asyncio.get_event_loop()
        
        # Enable debugging
        #self._set_verbose()
        
        # Capture signals
        self._capture_signal()
        
        # Read configuration
        self._config = self._load_configuration('ces.yaml')
        print(self._config)
        
        # Initialize Address Pools
        self._init_address_pools()
        
        # Initialize DNS
        self._init_dns()
    
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)
    
    def _load_configuration(self, filename):
        config = yaml.load(open(filename,'r'))
        return config
    
    def _init_address_pools(self):
        # Create container of Address Pools
        self._addresspoolcontainer = addresspool.AddressPoolContainer()
        # Create specific Address Pools
        for k,v in self._config['ADDRESSPOOL'].items():
            if k == 'circularpool':
                ap = addresspool.AddressPoolShared(k)
            elif k == 'proxypool':
                ap = addresspool.AddressPoolUser(k)
            else:
                self._logger.warning('AddressPool {} not supported'.format(k))
            
            self._logger.warning('Created Address Pool - {}'.format(k))
            for net in v:
                self._logger.warning('Adding resources to pool {}: {}'.format(k, net))
                ap.add_to_pool(net)
    
    def _init_dns(self):
        # Store all DNS related parameters in a dictionary
        self._dns = {}
        self._dns['addr'] = {}
        self._dns['node'] = {}
        self._dns['activequeries'] = {}
        self._dns['soa'] = self._config['DNS']['soa']
        self._dns['timeouts'] = self._config['DNS']['timeouts']
        
        # Create DNS Zone file to be populated
        self._dns['zone'] = mydns.load_zone(self._config['DNS']['zonefile'],self._config['DNS']['soa'])
        
        self._logger.warning('DNS rtx-timeout for CES NAPTR: {}'.format(self._dns['timeouts']['naptr']))
        self._logger.warning('DNS rtx-timeout for CES A:     {}'.format(self._dns['timeouts']['a']))
        self._logger.warning('DNS rtx-timeout for other:     {}'.format(self._dns['timeouts']['any']))
        
        # Get address tuple configuration of DNS servers
        for k, v in self._config['DNS']['server'].items():
            self._dns['addr'][k] = (v['ip'], v['port'])
        
        # Initiate specific DNS servers
        self._init_dns_lan()
        self._init_dns_wan()
        self._init_dns_loopback()
        
    def _init_dns_lan(self):
        # Initiate DNS Server in LAN
        zone = self._dns['zone']
        addr = self._dns['addr']['lan']
        self._logger.warning('Creating DNS Server {} @{}:{}'.format('lan', addr[0],addr[1]))
        
        # Define callbacks for different DNS queries
        cb_noerror = self.process_dns_query_lan_noerror
        cb_nxdomain = self.process_dns_query_lan_nxdomain
        cb_udpate = None
        
        factory = mydns.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        self._dns['node']['lan'] = factory
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: factory, local_addr=addr))
        
    def _init_dns_wan(self):
        # Initiate DNS Server in WAN
        zone = self._dns['zone']
        addr = self._dns['addr']['wan']
        self._logger.warning('Creating DNS Server {} @{}:{}'.format('wan', addr[0],addr[1]))
        
        # Define callbacks for different DNS queries
        cb_noerror = self.process_dns_query_wan_noerror
        cb_nxdomain = self.process_dns_query_wan_nxdomain 
        cb_udpate = None
        
        factory = mydns.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        self._dns['node']['wan'] = factory
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: factory, local_addr=addr))
        
    def _init_dns_loopback(self):
        # Initiate DNS Server in Loopback
        zone = self._dns['zone']
        addr = self._dns['addr']['loopback']
        self._logger.warning('Creating DNS Server {} @{}:{}'.format('loopback', addr[0],addr[1]))
        
        # Define callbacks for different DNS queries
        cb_noerror = None
        cb_nxdomain = self.process_dns_query
        cb_udpate = self.process_dns_update
        
        factory = mydns.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        self._dns['node']['loopback'] = factory
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: factory, local_addr=addr))
    
    def _set_verbose(self):
        self._logger.warning('Enabling logging.DEBUG')
        logging.basicConfig(level=logging.DEBUG)
        self._loop.set_debug(True)
        
    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        try:
            #TODO: Close all sockets?
            for k,v in self._dns['node'].items():
                addr = self._dns['addr'][k]
                self._logger.warning('Terminating DNS Server {} @{}:{}'.format(k, addr[0],addr[1]))
                v.connection_lost(None)
        except:
            print('Exception in user code:')
            print('-' * 60)
            traceback.print_exc(file=sys.stdout)
            print('-' * 60)
        finally:
            self._loop.stop()
    
    def begin(self):
        print('CESv2 is starting...')
        self._loop.run_forever()
    
    ############################################################################
    ########################  DNS PROCESSING FUNCTIONS  ########################
    
    def process_dns_query(self, query, addr, cback):
        """ Perform public DNS resolutions of a query """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        self._logger.warning('Resolve query {0} {1}/{2} from {3}:{4}'.format(query.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype), addr[0], addr[1]))
        
        if key in self._dns['activequeries']:
            # Continue ongoing resolution
            (resolver, query) = self._dns['activequeries'][key]
            resolver.process_query(query, addr)
        else:
            # Resolve DNS query as is
            self._do_resolve_dns_query(query, addr, cback)

    def process_dns_query_lan_noerror(self, query, addr, cback):
        """ Process DNS query from private network of an existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        if is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A:
            # Resolve local CES policy
            #self._do_resolve_dns_query_ces(query, addr, cback)
            print('Resolve local policy of hosts')
            cback(query, None, addr)
            
        elif is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA:
            # Resolve local CES policy
            #self._do_resolve_dns_query_ces(query, addr, cback, ipv6=True)
            print('Resolve local policy of hosts')
            cback(query, None, addr)
            
        else:
            # Answer with REFUSED any other query not in cache
            cback(query, None, addr)
    
    def process_dns_query_lan_nxdomain(self, query, addr, cback):
        """ Process DNS query from private network of a non existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        self._logger.warning('Resolve query for CES discovery {0} {1}/{2} from {3}:{4}'.format(query.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype), addr[0], addr[1]))
        
        if key in self._dns['activequeries']:
            # Continue ongoing resolution
            (resolver, query) = self._dns['activequeries'][key]
            resolver.process_query(query, addr)
        elif is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A:
            # Resolve DNS query for CES IPv4
            timeouts = dict(self._dns['timeouts'])
            resolver = mydns.DNSResolverCESIPv4(self._loop, query, addr, self._dns['addr']['resolver'],self._do_resolver_callback, key, timeouts=timeouts)
            self._dns['activequeries'][key] = (resolver, query)
            resolver.begin()
        elif is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA:
            # Resolve DNS query for CES IPv6
            timeouts = dict(self._dns['timeouts'])
            resolver = mydns.DNSResolverCESIPv6(self._loop, query, addr, self._dns['addr']['resolver'],self._do_resolver_callback, key, timeouts=timeouts)
            self._dns['activequeries'][key] = (resolver, query)
            resolver.begin()
        else:
            # Resolve DNS query as is
            self._do_resolve_dns_query(query, addr, cback)
            
    def process_dns_query_wan_noerror(self, query, addr, cback):
        """ Process DNS query from public Internet of an existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        # Serve public records...
        
        ## Filter NAPTR and A records
        cback(query, None, addr)
    
    def process_dns_query_wan_nxdomain(self, query, addr, cback):
        """ Process DNS query from public Internet of a non existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        # We have received a query for a domain that should exist in our zone but it doesn't
        cback(query, None, addr)
    
    def process_dns_update(self, query, addr, cback):
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
            
    def _do_resolver_callback(self, metadata, response=None):
        try:
            (queryid, name, rdtype, rdclass, addr, cback) = metadata
            (resolver, query) = self._dns['activequeries'].pop(metadata)
        except KeyError:
            self._logger.warning('Query has already been processed {0} {1}/{2} from {3}:{4}'.format(queryid, name, dns.rdatatype.to_text(rdtype), addr[0], addr[1]))
            return

        if response is None:
            self._logger.warning(
                'This seems a good place to create negative caching...')

        # Callback to send response to host
        cback(query, response, addr)

    def _do_resolve_dns_query(self, query, addr, cback):
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        self._logger.warning(
            'Resolve normal query {0} {1}/{2} from {3}:{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        # This DNS resolution does not require any kind of mangling
        timeouts = list(self._dns['timeouts']['any'])
        resolver = mydns.ResolverWorker(self._loop, query, self._do_resolver_callback,
                                   key, timeouts)
        self._dns['activequeries'][key] = (resolver, query)
        raddr = self._dns['addr']['resolver']
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: resolver, remote_addr=raddr))
        
if __name__ == '__main__':
    try:
        ces = CustomerEdgeSwitch()
        ces.begin()
    except Exception:
        print('Exception in user code:')
        print('-' * 60)
        traceback.print_exc(file=sys.stdout)
        print('-' * 60)
    finally:
        loop = asyncio.get_event_loop()
        loop.close()
    print('Bye!')
