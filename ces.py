#!/usr/bin/python3.5

import asyncio
import addresspool
import configparser
import dnsserver
import dnsresolver
import logging
import signal
import sys
import traceback
import yaml


LOGLEVELCES = logging.WARNING

class CustomerEdgeSwitch(object):
    def __init__(self, name='CustomerEdgeSwitch'):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELCES)
        
        # Get event loop
        self._loop = asyncio.get_event_loop()
        
        # Enable debugging
        self._set_verbose()
        
        # Capture signals
        self._capture_signal()
        
        # Read configuration
        #self._config = self._load_configuration('ces.cfg')
        self._config = self._load_configuration('ces.yaml')
        
        # Initialize Address Pools
        self._init_address_pools()
        
        # Initialize DNS
        self._init_dns()
        
    
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)
    
    def _load_configuration(self, filename):
        #config = configparser.ConfigParser()
        #config.read_file(open(filename,'r'))
        #print(config.__dict__)
        config = yaml.load(open(filename,'r'))
        print(config)
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
        # Create DNS Zone file to be populated
        
        import dns
        import dns.zone
        
        loop = self._loop
        
        soa = self._config['DNS']['soa']
        zone = dns.zone.Zone(origin=soa, relativize=False)
        
        # Create specific DNS servers
        for k, v in self._config['DNS']['server'].items():
            self._logger.warning('Creating DNS Server {}@{}:{}'.format(k,v['ip'],v['port']))
        
        '''
        # Create DNS Server in LAN
        ipaddr = self._config['DNS']['server']['lan']['ip']
        port = self._config['DNS']['server']['lan']['port']
        cb_noerror = cb_nxdomain = cb_udpate = None
        lan_addr = (ipaddr, port)
        
        factory = dnsserver.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        loop.create_task(loop.create_datagram_endpoint(lambda: factory, local_addr=lan_addr))
        
        # Create DNS Server in WAN
        ipaddr = self._config['DNS']['server']['wan']['ip']
        port = self._config['DNS']['server']['wan']['port']
        cb_noerror = cb_nxdomain = cb_udpate = None
        wan_addr = (ipaddr, port)
        
        factory = dnsserver.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        loop.create_task(loop.create_datagram_endpoint(lambda: factory, local_addr=wan_addr))
        
        '''
        
        # Create DNS Server in Loopback
        ipaddr = self._config['DNS']['server']['loopback']['ip']
        port = self._config['DNS']['server']['loopback']['port']
        cb_noerror = cb_nxdomain = cb_udpate = None
        wan_addr = (ipaddr, port)
        
        factory = dnsserver.DNSServer(zone, cb_noerror, cb_nxdomain, cb_udpate)
        loop.create_task(loop.create_datagram_endpoint(lambda: factory, local_addr=wan_addr))
        
    
    def _set_verbose(self):
        self._logger.warning('Enabling logging.DEBUG')
        logging.basicConfig(level=logging.DEBUG)
        self._loop.set_debug(True)
        
    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        self._loop.stop()
    
    def begin(self):
        print('CESv2 is starting...')
        self._loop.run_forever()


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
