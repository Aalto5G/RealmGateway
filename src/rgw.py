#!/usr/bin/env python3

#TODO: Add logic to register several DNS resolvers and round robin or avoid using unreachable one
#TODO: Define better transition from CUSTOMER_POLICY towards ADMIN_POLICY in filter.FORWARD - Use ipt-host-unknown ?
'''
Run as:
./rgw.py  --name gwa.demo                                                    \
          --dns-soa gwa.demo. 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.1.130 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.010 0.100 0.200                               \
          --pool-serviceip   100.64.1.130/32                                 \
          --pool-cpoolip     100.64.1.133/32 100.64.1.134/32 100.64.1.135/32 \
          --ipt-cpool-queue  1                                               \
          --ipt-cpool-chain  CIRCULAR_POOL                                   \
          --ipt-host-chain   CUSTOMER_POLICY                                 \
          --ipt-host-unknown CUSTOMER_POLICY_ACCEPT                          \
          --ipt-policy-order PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE     \
                             GROUP_POLICY CUSTOMER_POLICY                    \
                             ADMIN_POLICY ADMIN_POLICY_DHCP                  \
                             ADMIN_POLICY_HTTP ADMIN_POLICY_DNS              \
                             GUEST_SERVICES                                  \
          --ips-hosts        IPS_SUBSCRIBERS                                 \
          --ipt-markdnat                                                     \
          --ipt-flush                                                        \
          --repository-subscriber-folder gwa.subscriber.d/                   \
          --repository-policy-folder     gwa.policy.d/
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
import time
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
    parser.add_argument('--ipt-host-unknown', type=str,
                        metavar=('IPT_HOST_UNKNOWN'),
                        default='CONTINUE',
                        help='Default iptables target for unknown LAN host (CUSTOMER_POLICY_ACCEPT/DROP)')
    parser.add_argument('--ipt-policy-order', nargs='*', type=str,
                        metavar=('IPT_POLICY_ORDER'),
                        help='Iptables install policy order')
    parser.add_argument('--ipt-markdnat', dest='ipt_markdnat', action='store_true',
                        help='Use iptables MARKDNAT target')
    parser.add_argument('--ipt-flush', dest='ipt_flush', action='store_true',
                        help='Flush iptables & ipset previous parameters')
    parser.add_argument('--ips-hosts', type=str,
                        metavar=('IPS_HOSTS'),
                        default='IPS_HOSTS',
                        help='ipset type hash:ip that stores the registered hosts')

    # Data repository parameters
    ## API URL information
    parser.add_argument('--repository-api-url', type=str,
                        metavar=('URL'),
                        help='URL of the data repository')
    ## Subscriber information
    parser.add_argument('--repository-subscriber-file', type=str,
                        metavar=('FILENAME'),
                        help='Configuration file with subscriber information')
    parser.add_argument('--repository-subscriber-folder', type=str,
                        metavar=('FOLDERNAME'),
                        help='Configuration folder with subscriber information')
    ## Policy information
    parser.add_argument('--repository-policy-file', type=str,
                        metavar=('FILENAME'),
                        help='Configuration file with local policy information')
    parser.add_argument('--repository-policy-folder', type=str,
                        metavar=('FOLDERNAME'),
                        help='Configuration folder with local policy information')

    # Loglevel and verbosity
    parser.add_argument('--verbose', dest='verbose', action='store_true')

    return parser.parse_args()

class RealmGateway(object):
    def __init__(self, args):
        self._config = args

        # Get event loop
        self._loop = asyncio.get_event_loop()
        # Set logging
        self._set_logging()
        # Capture signals
        self._capture_signal()
        # Continue initialization in coroutine
        self._loop.create_task(self.__init__continue())

    @asyncio.coroutine
    def __init__continue(self):
        # Initialize Data Repository
        yield from self._init_datarepository()
        # Initialize Address Pools
        yield from self._init_pools()
        # Initialize Host table
        yield from self._init_hosttable()
        # Initialize Connection table
        yield from self._init_connectiontable()
        # Initialize Network
        yield from self._init_network()
        # Initialize DNS
        yield from self._init_dns()
        # Initialize configured subscriber data wrapped as a corutine
        self._loop.create_task(self._init_subscriberdata())
        # Initialize configured subscriber data wrapped as a corutine
        self._loop.create_task(self._init_cleanup_cpool(0.1))

    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)

    @asyncio.coroutine
    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.info('Initializing data repository')
        configfile   = self._config.getdefault('repository_subscriber_file', None)
        configfolder = self._config.getdefault('repository_subscriber_folder', None)
        policyfile   = self._config.getdefault('repository_policy_file', None)
        policyfolder = self._config.getdefault('repository_policy_folder', None)
        api_url      = self._config.getdefault('repository_api_url', None)
        self._datarepository = DataRepository(configfile = configfile, configfolder = configfolder,
                                              policyfile = policyfile, policyfolder = policyfolder,
                                              api_url = api_url)

    @asyncio.coroutine
    def _init_pools(self):
        # Create container of Address Pools
        self._pooltable = PoolContainer()

        # Create specific Address Pools
        ## Service IP Pool
        ap = AddressPoolShared('servicepool', name='Service Pool')
        self._pooltable.add(ap)
        for ipaddr in self._config.getdefault('pool_serviceip', ()):
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)

        ## Circular IP Pool
        ap = AddressPoolShared('circularpool', name='Circular Pool')
        self._pooltable.add(ap)
        for ipaddr in self._config.getdefault('pool_cpoolip', ()):
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)

        # For future use
        ## CES Proxy IP Pool
        ap = AddressPoolUser('proxypool', name='CES Proxy Pool')
        self._pooltable.add(ap)
        for ipaddr in self._config.getdefault('pool_cespoolip', ()):
            self._logger.info('Adding resource(s) to pool {} @ <{}>'.format(ipaddr, ap))
            ap.add_to_pool(ipaddr)

    @asyncio.coroutine
    def _init_hosttable(self):
        # Create container of Hosts
        self._hosttable = HostTable()

    @asyncio.coroutine
    def _init_connectiontable(self):
        # Create container of Connections
        self._connectiontable = ConnectionTable()

    @asyncio.coroutine
    def _init_network(self):
        self._network = network.Network(ipt_cpool_queue  = self._config.ipt_cpool_queue,
                                        ipt_cpool_chain  = self._config.ipt_cpool_chain,
                                        ipt_host_chain   = self._config.ipt_host_chain ,
                                        ipt_host_unknown = self._config.ipt_host_unknown,
                                        ipt_policy_order = self._config.ipt_policy_order,
                                        ipt_markdnat     = self._config.ipt_markdnat,
                                        ipt_flush        = self._config.ipt_flush,
                                        ips_hosts        = self._config.ips_hosts,
                                        datarepository   = self._datarepository)
        # Create object for storing all PacketIn-related information
        self.packetcb = PacketCallbacks(network=self._network, connectiontable=self._connectiontable)
        # Register NFQUEUE(s) callback
        self._network.ipt_register_nfqueues(self.packetcb.packet_in_circularpool)

    @asyncio.coroutine
    def _init_dns(self):
        # Create object for storing all DNS-related information
        self.dnscb = DNSCallbacks(cachetable      = None,
                                  datarepository  = self._datarepository,
                                  network         = self._network,
                                  hosttable       = self._hosttable,
                                  pooltable       = self._pooltable,
                                  connectiontable = self._connectiontable)

        # Register defined DNS timeouts
        self.dnscb.dns_register_timeout(self._config.dns_timeout, None)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_a, 1)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_aaaa, 28)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_naptr, 35)

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
            #transport, protocol = self._loop.run_until_complete(listen_obj)
            transport, protocol = yield from self._loop.create_task(listen_obj)
            self._logger.info('Creating DNS DDNS endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DDNS@{}:{}'.format(ipaddr, port), protocol)

        # DNS Server for WAN
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            #transport, protocol = self._loop.run_until_complete(listen_obj)
            transport, protocol = yield from self._loop.create_task(listen_obj)
            self._logger.info('Creating DNS Server endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSServer@{}:{}'.format(ipaddr, port), protocol)

        # DNS Proxy for LAN
        for ipaddr, port in self._config.dns_server_lan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            #transport, protocol = self._loop.run_until_complete(listen_obj)
            transport, protocol = yield from self._loop.create_task(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

        ## DNS Proxy for Local
        for ipaddr, port in self._config.dns_server_local:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            listen_obj = self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            #transport, protocol = self._loop.run_until_complete(listen_obj)
            transport, protocol = yield from self._loop.create_task(listen_obj)
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

    @asyncio.coroutine
    def _init_subscriberdata(self):
        self._logger.info('Initializing subscriber data')
        tzero = time.time()
        for subs_id, subs_data in self._datarepository.getall_subscriber(default = {}).items():
            ipaddr = subs_data['ID']['ipv4'][0]
            fqdn = subs_data['ID']['fqdn'][0]
            self._logger.debug('Registering subscriber {} / {}@{}'.format(subs_id, fqdn, ipaddr))
            yield from self.dnscb.ddns_register_user(fqdn, 1, ipaddr)
        self._logger.info('Completed initializacion of subscriber data in {:.3f} sec'.format(time.time()-tzero))

    @asyncio.coroutine
    def _init_cleanup_cpool(self, delay):
        self._logger.info('Initiating cleanup of the Circular Pool every {} seconds'.format(delay))
        while True:
            yield from asyncio.sleep(delay)
            self._logger.debug('do cleanup circularpool')
            # Update table and remove for expired connections
            self._connectiontable.update_all_rgw()

    def _set_logging(self, loglevel = LOGLEVEL_MAIN):
        if self._config.verbose:
            loglevel = logging.DEBUG
            self._loop.set_debug(True)

        self._logger = logging.getLogger(self._config.name)
        self._logger.setLevel(loglevel)
        self._logger.warning('Setting loglevel {}'.format(logging.getLevelName(loglevel)))
        logging.basicConfig(level=loglevel)

    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        try:
            #TODO: Close all sockets?
            for obj in self.dnscb.get_object(None):
                obj.connection_lost(None)
            # Close bound NFQUEUEs
            self._network.ipt_deregister_nfqueues()
            # Close open aiohttp_client objects
            self._network.rest_api_close()
            self._datarepository.rest_api_close()
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
    # Overload Namespace object with getdefault function
    args.getdefault = lambda name, default: getattr(args, name, default)

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
