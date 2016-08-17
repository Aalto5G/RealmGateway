#!/usr/bin/env python3

# TODO: Read DNS timeouts from file and use them in DNSCallbacks

import asyncio
import pool
import configparser
import dns
import network
import mydns
import logging
import logging.handlers
import signal
import sys
import traceback
import yaml
import pprint

from datarepository import DataRepository
from pool import PoolContainer, NamePool, AddressPoolShared, AddressPoolUser
from host import HostTable, HostEntry
from connection import ConnectionTable
from callbacks import DNSCallbacks, PacketCallbacks

import customdns
from customdns.ddns import DDNSServer
from customdns.dnsproxy import DNSProxy

from utils import is_ipv4, is_ipv6, trace

LOGLEVELMAIN = logging.WARNING

class RetCodes(object):
    POLICY_OK  = 0
    POLICY_NOK = 1

    APOOL_AVAILABLE = 0
    APOOL_DEPLETED = 1

    DNS_NOERROR  = 0    # DNS Query completed successfully
    DNS_FORMERR  = 1    # DNS Query Format Error
    DNS_SERVFAIL = 2    # Server failed to complete the DNS request
    DNS_NXDOMAIN = 3    # Domain name does not exist.  For help resolving this error, read here.
    DNS_NOTIMP   = 4    # Function not implemented
    DNS_REFUSED  = 5    # The server refused to answer for the query
    DNS_YXDOMAIN = 6    # Name that should not exist, does exist
    DNS_XRRSET   = 7    # RRset that should not exist, does exist
    DNS_NOTAUTH  = 8    # Server not authoritative for the zone
    DNS_NOTZONE  = 9    # Name not in zone


class RealmGateway(object):
    def __init__(self, name='RealmGateway'):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELMAIN)

        # Get event loop
        self._loop = asyncio.get_event_loop()

        # Enable debugging
        self._set_verbose()

        # Capture signals
        self._capture_signal()

        # Read configuration
        self._config = self._load_configuration('gwa.demo.config.yaml')

        # Initialize Data Repository
        self._init_datarepository()

        # Initialize Host table
        self._init_hosttable()

        # Initialize Connection table
        self._init_connectiontable()

        # Initialize Network
        self._init_network()

        # Initialize Address Pools
        self._init_pools()

        # Initialize DNS
        self._init_dns()

        # Initialize configured subscriber data
        self._init_subscriberdata()

        # Do debugging
        '''
        print('\nHostTable')
        print(self._hosttable)
        print('\nPoolTable')
        print(self._pooltable)
        print('\nConnectionTable')
        print(self._connectiontable)
        '''

    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)

    def _load_configuration(self, filename):
        return yaml.load(open(filename,'r'))

    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.warning('Initializing data repository')
        subscriberdata = self._config['DATAREPOSITORY']['subscriberdata']
        servicedata = self._config['DATAREPOSITORY']['servicedata']
        policydata = self._config['DATAREPOSITORY']['policydata']
        self._datarepository = DataRepository(subscriberdata=subscriberdata,servicedata=servicedata,policydata=policydata)

    def _init_hosttable(self):
        # Create container of Hosts
        self._hosttable = HostTable()

    def _init_connectiontable(self):
        # Create container of Connections
        self._connectiontable = ConnectionTable()

    def _init_pools(self):
        # Create container of Address Pools
        self._pooltable = PoolContainer()

        '''
        This is not required anymore for RealmGateway as the flow
        is configured to proxy_required=True/False
        # Create specific Name Pools
        for k,v in self._config['NETWORK']['namepool'].items():
            ap = NamePool(k)
            self._logger.warning('Created Name Pool - "{}"'.format(k))
            self._pooltable.add(ap)
        '''
        # Create specific Address Pools
        for k,v in self._config['NETWORK']['addresspool'].items():
            if k == 'circularpool':
                ap = AddressPoolShared(k)
            elif k == 'servicepool':
                ap = AddressPoolShared(k)
            elif k == 'proxypool':
                ap = AddressPoolUser(k)
            else:
                self._logger.warning('AddressPool {} not supported'.format(k))
                continue

            self._logger.warning('Created Address Pool - "{}"'.format(k))
            for net in v:
                self._logger.warning('Adding resource(s) to pool "{}": {}'.format(k, net))
                ap.add_to_pool(net)
            self._pooltable.add(ap)

    def _init_dns(self):
        # Create object for storing all DNS-related information
        self.dnscb = DNSCallbacks(cachetable = None,
                                  datarepository = self._datarepository,
                                  network = self._network,
                                  hosttable = self._hosttable,
                                  pooltable = self._pooltable,
                                  connectiontable = self._connectiontable)

        # Register defined SOA zones
        for name in self._config['DNS']['soa']:
            self._logger.warning('Registering DNS SOA {}'.format(name))
            self.dnscb.dns_register_soa(name)
        soa_list = self.dnscb.dns_get_soa()

        # Register DNS resolvers
        addr = self._config['DNS']['resolver']['ip'], self._config['DNS']['resolver']['port']
        self.dnscb.dns_register_resolver(addr)

        # Initiate specific DNS servers

        ## DDNS Server for DHCP Server with forwarding to BIND9 server
        '''
        addr = self._config['DNS']['ddnsproxy']['ip'], self._config['DNS']['ddnsproxy']['port']
        ddnsserver_addr = self._config['DNS']['ddnsserver']['ip'], self._config['DNS']['ddnsserver']['port']
        self._logger.warning('Creating DDNS Server Local @{}:{}'.format(addr[0],addr[1]))
        obj_ddns = DDNSProxy(dns_addr = ddnsserver_addr, cb_default = self.dnscb.ddns_process)
        self.dnscb.register_object('DDNS_Server_Local', obj_ddns)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: obj_ddns, local_addr=addr))
        '''
        ## DDNS Server for DHCP Server
        addr = self._config['DNS']['ddnsserver']['ip'], self._config['DNS']['ddnsserver']['port']
        self._logger.warning('Creating DDNS Server Local @{}:{}'.format(addr[0],addr[1]))
        obj_ddns = DDNSServer(cb_default = self.dnscb.ddns_process)
        self.dnscb.register_object('DDNS_Server_Local', obj_ddns)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: obj_ddns, local_addr=addr))

        ## DNS Server for WAN
        addr = self._config['DNS']['server']['ip'], self._config['DNS']['server']['port']
        self._logger.warning('Creating DNS Server WAN @{}:{}'.format(addr[0],addr[1]))
        obj_serverwan = DNSProxy(soa_list = soa_list, cb_soa = self.dnscb.dns_process_rgw_wan_soa, cb_nosoa = self.dnscb.dns_process_rgw_wan_nosoa)
        self.dnscb.register_object('DNS_Server_WAN', obj_serverwan)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: obj_serverwan, local_addr=addr))


        '''# This is only required for CES - RGW does not perform DNS QUERY MANGLING!'''
        # Create DNS Proxy as forwarders to local resolver for LAN and Local
        ## DNS Proxy for LAN
        addr = self._config['DNS']['proxylan']['ip'], self._config['DNS']['proxylan']['port']
        self._logger.warning('Creating DNS Proxy LAN @{}:{}'.format(addr[0],addr[1]))
        cb_nosoa = cb = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
        obj_proxylan = DNSProxy(soa_list = soa_list, cb_soa = self.dnscb.dns_process_rgw_lan_soa, cb_nosoa = cb_nosoa)
        self.dnscb.register_object('DNS_Proxy_LAN', obj_proxylan)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: obj_proxylan, local_addr=addr))

        ## DNS Proxy for Local
        addr = self._config['DNS']['proxylocal']['ip'], self._config['DNS']['proxylocal']['port']
        self._logger.warning('Creating DNS Proxy Local @{}:{}'.format(addr[0],addr[1]))
        obj_proxylocal = DNSProxy(soa_list = soa_list, cb_soa = self.dnscb.dns_process_rgw_lan_soa, cb_nosoa = self.dnscb.dns_process_rgw_lan_nosoa)
        self.dnscb.register_object('DNS_Proxy_Local', obj_proxylocal)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: obj_proxylocal, local_addr=addr))

    def _init_subscriberdata(self):
        self._logger.warning('Initializing subscriber data')
        for subscriber_id, subscriber_data in self._datarepository.get_subscriber_data(None).items():
            ipaddr = subscriber_data['ipv4']
            fqdn = subscriber_data['fqdn']
            self._logger.info('Registering subscriber {} / {}@{}'.format(subscriber_id, fqdn, ipaddr))
            self.dnscb.ddns_register_user(fqdn, 1, ipaddr)

    def _init_network(self):
        kwargs = self._config['NETWORK']
        self._network = network.Network(**kwargs)
        # Create object for storing all PacketIn-related information
        self.packetcb = PacketCallbacks(network=self._network, connectiontable=self._connectiontable)
        # Register NFQUEUE callback
        queue = self._config['NETWORK']['iptables']['circularpool']['nfqueue']
        self._network.ipt_register_nfqueue(queue, self.packetcb.packet_in_circularpool)


    def _set_verbose(self, loglevel = logging.INFO):
        self._logger.warning('Setting loglevel {}'.format(logging.getLevelName(loglevel)))
        logging.basicConfig(level=loglevel)
        if loglevel <= logging.DEBUG:
            self._loop.set_debug(True)

    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        try:
            #TODO: Close all sockets?
            for obj in self.dnscb.get_object(None):
                obj.connection_lost(None)
            # Close NFQUEUE
            self._network.ipt_deregister_nfqueue()
        except:
            trace()
        finally:
            self._loop.stop()

    def begin(self):
        self._logger.info('RealmGateway_v2 is starting...')
        self._loop.run_forever()

if __name__ == '__main__':
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    format = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)
    fh = logging.handlers.RotatingFileHandler('rgw.log', maxBytes=(1048576*5), backupCount=7)
    fh.setFormatter(format)
    log.addHandler(fh)
    try:
        loop = asyncio.get_event_loop()
        rgw = RealmGateway()
        rgw.begin()
    except Exception as e:
        print(format(e))
        trace()
    finally:
        loop.close()
    print('Bye!')

