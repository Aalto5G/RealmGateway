#!/usr/bin/env python3

import asyncio
import pool
import configparser
import dns
import network

import logging
import logging.config
import logging.handlers
import yaml
import os

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

from aalto_helpers import utils3
from loglevel import LOGLEVEL_MAIN

def setup_logging_yaml(default_path='logging.yaml',
                       default_level=logging.INFO,
                       env_key='LOG_CFG'):
    """Setup logging configuration"""
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)

class RealmGateway(object):
    def __init__(self, configfile, name='RealmGateway'):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_MAIN)

        # Get event loop
        self._loop = asyncio.get_event_loop()
        # Enable debugging
        self._set_verbose()
        # Capture signals
        self._capture_signal()
        # Read configuration
        self._config = self._load_configuration(configfile)
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
        # Initialize configured subscriber data wrapped as a corutine
        self._loop.create_task(self._init_subscriberdata())

    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)

    def _load_configuration(self, filename):
        return yaml.load(open(filename,'r'))

    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.info('Initializing data repository')
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

            self._logger.info('Created Address Pool <{}>'.format(k))
            for net in v:
                self._logger.debug('Adding resource(s) to pool {}@<{}>'.format(net, k))
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
            self._logger.info('Registering DNS SOA {}'.format(name))
            self.dnscb.dns_register_soa(name)
        soa_list = self.dnscb.dns_get_soa()

        # Register DNS resolvers
        for addr in self._config['DNS']['resolver']:
            self._logger.info('Creating DNS Resolver endpoint @{}:{}'.format(addr[0],addr[1]))
            self.dnscb.dns_register_resolver(addr)

        # Dynamic DNS Server for DNS update messages
        for addr in self._config['DNS']['ddnsserver']:
            cb_function = lambda x,y,z: asyncio.ensure_future(self.dnscb.ddns_process(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DDNSServer(cb_default = cb_function), local_addr=tuple(addr))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS DDNS endpoint @{}:{} <{}>'.format(addr[0],addr[1], id(protocol)))
            self.dnscb.register_object('DDNS@{}:{}'.format(addr[0],addr[1]), protocol)

        # DNS Server for WAN
        for addr in self._config['DNS']['server']:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=tuple(addr))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Server endpoint @{}:{} <{}>'.format(addr[0],addr[1], id(protocol)))
            self.dnscb.register_object('DNSServer@{}:{}'.format(addr[0],addr[1]), protocol)

        # DNS Proxy for LAN
        for addr in self._config['DNS']['proxylan']:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=tuple(addr))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{} <{}>'.format(addr[0],addr[1], id(protocol)))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(addr[0],addr[1]), protocol)

        ## DNS Proxy for Local
        for addr in self._config['DNS']['proxylocal']:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=tuple(addr))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{} <{}>'.format(addr[0],addr[1], id(protocol)))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(addr[0],addr[1]), protocol)


    @asyncio.coroutine
    def _init_subscriberdata(self):
        self._logger.info('Initializing subscriber data')
        for subscriber_id, subscriber_data in self._datarepository.get_subscriber_data(None).items():
            ipaddr = subscriber_data['ipv4']
            fqdn = subscriber_data['fqdn']
            self._logger.info('Registering subscriber {} / {}@{}'.format(subscriber_id, fqdn, ipaddr))
            yield from self.dnscb.ddns_register_user(fqdn, 1, ipaddr)

    def _init_network(self):
        kwargs = self._config['NETWORK']
        self._network = network.Network(**kwargs)
        # Create object for storing all PacketIn-related information
        self.packetcb = PacketCallbacks(network=self._network, connectiontable=self._connectiontable)
        # Register NFQUEUE callback
        queue = self._config['NETWORK']['iptables']['circularpool']['nfqueue']
        self._network.ipt_register_nfqueue(queue, self.packetcb.packet_in_circularpool)

    def _set_verbose(self, loglevel = LOGLEVEL_MAIN):
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
            self._logger.exception()
        finally:
            self._loop.stop()

    def begin(self):
        self._logger.info('RealmGateway_v2 is starting...')
        self._loop.run_forever()

if __name__ == '__main__':
    # Use function to configure logging from file
    setup_logging_yaml()

    # Change logging dynamically
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        loop = asyncio.get_event_loop()
        rgw = RealmGateway(sys.argv[1])
        rgw.begin()
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.exception("Exception!")
    finally:
        loop.close()

'''
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

'''