#!/usr/bin/env python3

#TODO: Overwrite method getattr from argument object Namespace to return None if non existing or default value
#TODO: Add logic to register several DNS resolvers and round robin or avoid using unreachable one

'''
Run as:
./rgw.py  --name gwa.demo                                                    \
          --dns-soa gwa.demo. 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \
          --dns-server-local 127.0.0.1 53 --dns-server-local 127.0.0.1 1053  \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.1.130 53                                 \
          --dns-resolver     8.8.8.8 53                                      \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.1 53                                    \
          --dns-timeout      0.010 0.100 0.200                               \
          --pool-serviceip   100.64.1.130/32                                 \
          --pool-cpoolip     100.64.1.133/32 100.64.1.134/32 100.64.1.135/32 \
          --ipt-cpool-queue  1 2 3                                           \
          --ipt-cpool-chain  NAT_PRE_CPOOL                                   \
          --ipt-host-chain   FILTER_HOST_POLICY                              \
          --ipt-host-accept  FILTER_HOST_POLICY_ACCEPT                       \
          --repository-subscriber-file   gwa.subscriber.yaml                 \
          --repository-subscriber-folder gwa.subscriber.d/
'''

import argparse
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

def parse_arguments():
    parser = argparse.ArgumentParser(description='Realm Gateway')
    parser.add_argument('--name', type=str, required=True,
                        help='Name of the Realm Gateway instance i.e. gwa.demo')

    # DNS parameters
    parser.add_argument('--dns-soa', nargs='*', required=True,
                        help='Available SOA zones (FQDN and PTR)')
    parser.add_argument('--dns-server-local', nargs=2, action='append',
                        metavar=('IPADDR', 'PORT'),
                        help='DNS serving own host')
    parser.add_argument('--dns-server-lan', nargs=2, action='append',
                        metavar=('IPADDR', 'PORT'),
                        help='DNS serving LAN hosts')
    parser.add_argument('--dns-server-wan', nargs=2, action='append',
                        metavar=('IPADDR', 'PORT'),
                         help='DNS serving WAN hosts')
    parser.add_argument('--dns-resolver', nargs=2, action='append',
                        metavar=('IPADDR', 'PORT'),
                        help='DNS resolver server')
    parser.add_argument('--ddns-server', nargs=2, action='append',
                        metavar=('IPADDR', 'PORT'),
                        help='DDNS serving own DHCP server')

    # DNS timeout parameters
    parser.add_argument('--dns-timeout', nargs='+', type=float, default=[0.100, 0.200, 0.200],
                        help='Default timeouts for DNS resolution (sec)')
    parser.add_argument('--dns-timeout-a', nargs='+', type=float, default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS A resolution (sec)')
    parser.add_argument('--dns-timeout-aaaa', nargs='+', type=float, default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS AAAA resolution (sec)')
    parser.add_argument('--dns-timeout-naptr', nargs='+', type=float, default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS NAPTR resolution (sec)')

    # Address pool parameters
    parser.add_argument('--pool-serviceip', nargs='*',
                        metavar=('IPADDR'),
                        help='IP address of public proxy frontend')
    parser.add_argument('--pool-cpoolip',nargs='*',
                        metavar=('IPADDR'),
                        help='IP address of public Circular Pool')

    # Iptables parameters
    parser.add_argument('--ipt-cpool-queue', nargs='*', type=int,
                        metavar=('QUEUENUM'),
                        help='NFQUEUE number')
    parser.add_argument('--ipt-cpool-chain', type=str,
                        metavar=('IPT_CPOOL_CHAIN'),
                        help='Iptables CircularPool nat chain')
    parser.add_argument('--ipt-host-chain', type=str,
                        metavar=('IPT_HOST_CHAIN'),
                        help='Iptables Host filter chain')
    parser.add_argument('--ipt-host-accept', type=str,
                        metavar=('IPT_HOST_ACCEPT'),
                        help='Iptables Host accept target chain')

    # Data repository parameters
    ## Subscriber information
    parser.add_argument('--repository-subscriber-file', type=str,
                        metavar=('FILENAME'),
                        help='Configuration file with subscriber information')
    parser.add_argument('--repository-subscriber-folder', type=str,
                        metavar=('FOLDERNAME'),
                        help='Configuration folder with subscriber information')
    ### Policy information
    #parser.add_argument('--repository-policy-file', nargs=1,
    #                    metavar=('FILENAME'),
    #                    help='Configuration file with policy information')
    #parser.add_argument('--repository-policy-folder', nargs=1,
    #                    metavar=('FOLDERNAME'),
    #                    help='Configuration folder with policy information')

    return parser.parse_args()

class RealmGateway(object):
    def __init__(self, args):
        self._config = args
        self._logger = logging.getLogger(self._config.name)
        self._logger.setLevel(LOGLEVEL_MAIN)

        # Get event loop
        self._loop = asyncio.get_event_loop()
        # Enable debugging
        self._set_verbose()
        # Capture signals
        self._capture_signal()
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

    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.info('Initializing data repository')
        self._datarepository = DataRepository(configfile = self._config.repository_subscriber_file,
                                              configfolder = self._config.repository_subscriber_folder)

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
        ## Service IP Pool
        ap = AddressPoolShared('servicepool')
        self._pooltable.add(ap)
        for ipaddr in self._config.pool_serviceip:
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)

        ## Circular IP Pool
        ap = AddressPoolShared('circularpool')
        self._pooltable.add(ap)
        for ipaddr in self._config.pool_cpoolip:
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)
        '''
        # For future use
        ## CES Proxy IP Pool
        ap = AddressPoolUser('proxypool')
        self._pooltable.add(ap)
        for ipaddr in self._config.pool_cespoolip:
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)
        '''

    def _init_dns(self):
        # Create object for storing all DNS-related information
        self.dnscb = DNSCallbacks(cachetable      = None,
                                  datarepository  = self._datarepository,
                                  network         = self._network,
                                  hosttable       = self._hosttable,
                                  pooltable       = self._pooltable,
                                  connectiontable = self._connectiontable)

        # Register defined DNS timeouts
        self.dnscb.dns_register_timeouts(self._config.dns_timeout, None)
        ## TODO: Add rest of DNS recort type timeouts

        # Register defined SOA zones
        for soa_name in self._config.dns_soa:
            self._logger.info('Registering DNS SOA {}'.format(soa_name))
            self.dnscb.dns_register_soa(soa_name)
        soa_list = self.dnscb.dns_get_soa()

        # Register DNS resolvers
        for ipaddr, port in self._config.dns_resolver:
            self._logger.info('Creating DNS Resolver endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.dns_register_resolver((ipaddr, port))

        # Dynamic DNS Server for DNS update messages
        for ipaddr, port in self._config.ddns_server:
            cb_function = lambda x,y,z: asyncio.ensure_future(self.dnscb.ddns_process(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DDNSServer(cb_default = cb_function), local_addr=(ipaddr, port))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS DDNS endpoint @{}:{} <{}>'.format(ipaddr, port, id(protocol)))
            self.dnscb.register_object('DDNS@{}:{}'.format(ipaddr, port), protocol)

        # DNS Server for WAN
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Server endpoint @{}:{} <{}>'.format(ipaddr, port, id(protocol)))
            self.dnscb.register_object('DNSServer@{}:{}'.format(ipaddr, port), protocol)

        # DNS Proxy for LAN
        for ipaddr, port in self._config.dns_server_lan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{} <{}>'.format(ipaddr, port, id(protocol)))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

        ## DNS Proxy for Local
        for ipaddr, port in self._config.dns_server_local:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            transport, protocol = self._loop.run_until_complete(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{} <{}>'.format(ipaddr, port, id(protocol)))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

    @asyncio.coroutine
    def _init_subscriberdata(self):
        self._logger.info('Initializing subscriber data')
        for subs_id, subs_data in self._datarepository.getall_subscriber(default = {}).items():
            ipaddr = subs_data['ID']['IPV4'][0]
            fqdn = subs_data['ID']['FQDN'][0]
            self._logger.debug('Registering subscriber {} / {}@{}'.format(subs_id, fqdn, ipaddr))
            yield from self.dnscb.ddns_register_user(fqdn, 1, ipaddr)

    def _init_network(self):
        self._network = network.Network(ipt_cpool_queue  = self._config.ipt_cpool_queue,
                                        ipt_cpool_chain  = self._config.ipt_cpool_chain,
                                        ipt_host_chain   = self._config.ipt_host_chain ,
                                        ipt_host_accept  = self._config.ipt_host_accept)
        # Create object for storing all PacketIn-related information
        self.packetcb = PacketCallbacks(network=self._network, connectiontable=self._connectiontable)
        # Register NFQUEUE(s) callback
        self._network.ipt_register_nfqueues(self.packetcb.packet_in_circularpool)

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
            # Close bound NFQUEUEs
            self._network.ipt_deregister_nfqueues()
        except:
            self._logger.exception()
        finally:
            self._loop.stop()

    def begin(self):
        self._logger.info('RealmGateway_v2 is starting...')
        self._loop.run_forever()

if __name__ == '__main__':
    # Parse arguments
    args = parse_arguments()
    print(args)

    # Use function to configure logging from file
    setup_logging_yaml()

    # Change logging dynamically
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        loop = asyncio.get_event_loop()
        rgw = RealmGateway(args)
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