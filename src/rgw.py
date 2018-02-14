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
          --dns-resolver     8.8.8.8 53                                      \
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
          --network-api-url  http://127.0.0.1:8081/                          \
          --repository-subscriber-folder ../config.d/gwa.demo.subscriber.d/  \
          --repository-policy-folder     ../config.d/gwa.demo.policy.d/      \
          --repository-api-url  http://127.0.0.1:8082/                       \
          --mode rgw
'''

import argparse
import asyncio
import pool
import configparser


import logging
import logging.config
import yaml
import os

import time
from contextlib import suppress

from datarepository import DataRepository
from pool import PoolContainer, NamePool, AddressPoolShared, AddressPoolUser
from host import HostTable, HostEntry
from connection import ConnectionTable
from network import Network
from callbacks import DNSCallbacks, PacketCallbacks

import customdns
from customdns.ddns import DDNSServer
from customdns.dnsproxy import DNSProxy, DNSTCPProxy

from helpers_n_wrappers import utils3
from global_variables import RUNNING_TASKS

import pbra
from pbra import PolicyBasedResourceAllocation

import dns
import dns.rcode

def setup_logging_yaml(default_path='logging.yaml',
                       default_level=logging.INFO,
                       env_path='LOG_CFG',
                       env_level='LOG_LEVEL'):
    """Setup logging configuration"""
    path = os.getenv(env_path, default_path)
    level = os.getenv(env_level, default_level)
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=level)

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
    parser.add_argument('--dns-timeout', nargs='+', type=float, default=[0.100, 0.250, 0.250],
                        help='Default timeouts for DNS resolution (sec)')
    parser.add_argument('--dns-timeout-a', nargs='+', type=float, #default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS A resolution (sec)')
    parser.add_argument('--dns-timeout-aaaa', nargs='+', type=float, #default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS AAAA resolution (sec)')
    parser.add_argument('--dns-timeout-srv', nargs='+', type=float, #default=[0.010, 0.200, 0.200],
                        help='Default timeouts for DNS SRV resolution (sec)')
    parser.add_argument('--dns-timeout-naptr', nargs='+', type=float, #default=[0.010, 0.200, 0.200],
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
    parser.add_argument('--network-api-url', type=str,
                        metavar=('URL'),
                        help='URL of the network API')

    # Data repository parameters
    ## API URL information
    parser.add_argument('--repository-api-url', type=str,
                        metavar=('URL'),
                        help='URL of the repository API')
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

    ## SYNPROXY information
    parser.add_argument('--synproxy', nargs=2, default=('127.0.0.1', 12345),
                        metavar=('IPADDR', 'PORT'),
                        help='SYNPROXY control endpoint')
    # Operation mode
    parser.add_argument('--mode', dest='mode', default='rgw', choices=['rgw', 'ces'])

    return parser.parse_args()

class RealmGateway(object):
    def __init__(self, args):
        self._config = args
        # Get event loop
        self._loop = asyncio.get_event_loop()
        # Get logger
        self._logger = logging.getLogger(self._config.name)

    @asyncio.coroutine
    def run(self):
        self._logger.warning('RealmGateway_v2 is starting...')
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
        # Initialize Policy Based Resource Allocation
        yield from self._init_pbra()
        # Initialize PacketCallbacks
        yield from self._init_packet_callbacks()
        # Initialize DNS
        yield from self._init_dns()
        # Create task: CircularPool cleanup
        _t = asyncio.ensure_future(self._init_cleanup_cpool(0.1))
        RUNNING_TASKS.append((_t, 'cleanup_cpool'))
        # Create task: Timer cleanup
        _t = asyncio.ensure_future(self._init_cleanup_pbra_timers(10.0))
        RUNNING_TASKS.append((_t, 'cleanup_pbra_timers'))
        # Create task: Show DNS groups
        _t = asyncio.ensure_future(self._init_show_dnsgroups(60.0))
        RUNNING_TASKS.append((_t, 'show_dnsgroups'))
        # Initialize Subscriber information
        yield from self._init_subscriberdata()
        # Ready!
        self._logger.warning('RealmGateway_v2 is ready!')


    @asyncio.coroutine
    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.warning('Initializing Data Repository')
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
        self._logger.warning('Initializing Address Pools')
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
        self._logger.warning('Initializing Network')
        self._network = Network(ipt_cpool_queue  = self._config.ipt_cpool_queue,
                                ipt_cpool_chain  = self._config.ipt_cpool_chain,
                                ipt_host_chain   = self._config.ipt_host_chain ,
                                ipt_host_unknown = self._config.ipt_host_unknown,
                                ipt_policy_order = self._config.ipt_policy_order,
                                ipt_markdnat     = self._config.ipt_markdnat,
                                ipt_flush        = self._config.ipt_flush,
                                ips_hosts        = self._config.ips_hosts,
                                api_url          = self._config.network_api_url,
                                datarepository   = self._datarepository,
                                synproxy         = self._config.synproxy,
                                pooltable        = self._pooltable)

    @asyncio.coroutine
    def _init_pbra(self):
        # Create container of Reputation objects
        self._logger.warning('Initializing Policy Based Resource Allocation')
        self._pbra = PolicyBasedResourceAllocation(pooltable       = self._pooltable,
                                                   hosttable       = self._hosttable,
                                                   connectiontable = self._connectiontable,
                                                   datarepository  = self._datarepository,
                                                   network         = self._network)

    @asyncio.coroutine
    def _init_packet_callbacks(self):
        # Create object for storing all PacketIn-related information
        self.packetcb = PacketCallbacks(network         = self._network,
                                        connectiontable = self._connectiontable,
                                        pbra            = self._pbra)
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
                                  connectiontable = self._connectiontable,
                                  pbra            = self._pbra)

        # Register defined DNS timeouts
        self.dnscb.dns_register_timeout(self._config.dns_timeout, None)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_a, 1)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_aaaa, 28)
        self.dnscb.dns_register_timeout(self._config.dns_timeout_srv, 33)
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
            transport, protocol = yield from self._loop.create_datagram_endpoint(lambda: DDNSServer(cb_default = cb_function), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS DDNS endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DDNS@{}:{}'.format(ipaddr, port), protocol)

        # DNS Server for WAN via UDP
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            transport, protocol = yield from self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Server endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSServer@{}:{}'.format(ipaddr, port), protocol)

        # DNS Proxy for LAN
        for ipaddr, port in self._config.dns_server_lan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            transport, protocol = yield from self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

        ## DNS Proxy for Local
        for ipaddr, port in self._config.dns_server_local:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_lan_soa(x,y,z))
            # Disable resolutions of non SOA domains for self generated DNS queries (i.e. HTTP proxy) - Answer with REFUSED
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_error_response(x,y,z,rcode=dns.rcode.REFUSED))
            transport, protocol = yield from self._loop.create_datagram_endpoint(lambda: DNSProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

        # BUG: If we move this part upwards, there is misrouting of messages to dns_process_rgw_lan_soa/dns_process_rgw_lan_nosoa
        # DNS Server for WAN via TCP
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self.dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            server = yield from self._loop.create_server(lambda: DNSTCPProxy(soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), host=ipaddr, port=port, reuse_address=True)
            server.connection_lost = lambda x: server.close()
            self._logger.info('Creating DNS TCP Server endpoint @{}:{}'.format(ipaddr, port))
            self.dnscb.register_object('DNSTCPServer@{}:{}'.format(ipaddr, port), server)

    @asyncio.coroutine
    def _init_subscriberdata(self):
        self._logger.warning('Initializing subscriber data')
        tzero = time.time()
        for subs_id, subs_data in self._datarepository.get_policy_host_all({}).items():
            ipaddr = subs_data['ID']['ipv4'][0]
            fqdn = subs_data['ID']['fqdn'][0]
            self._logger.debug('Registering subscriber {} / {}@{}'.format(subs_id, fqdn, ipaddr))
            yield from self.dnscb.ddns_register_user(fqdn, 1, ipaddr)
        self._logger.info('Completed initializacion of subscriber data in {:.3f} sec'.format(time.time()-tzero))

    @asyncio.coroutine
    def _init_cleanup_cpool(self, delay):
        self._logger.warning('Initiating cleanup of the Circular Pool every {} seconds'.format(delay))
        while True:
            yield from asyncio.sleep(delay)
            # Update table and remove expired elements
            self._connectiontable.update_all_rgw()

    @asyncio.coroutine
    def _init_cleanup_pbra_timers(self, delay):
        self._logger.warning('Initiating cleanup of PBRA timers every {} seconds'.format(delay))
        while True:
            yield from asyncio.sleep(delay)
            # Update table and remove expired elements
            self._pbra.cleanup_timers()

    @asyncio.coroutine
    def _init_show_dnsgroups(self, delay):
        self._logger.warning('Initiating display of DNSGroup information every {} seconds'.format(delay))
        while True:
            yield from asyncio.sleep(delay)
            # Update table and remove expired elements
            self._pbra.debug_dnsgroups()

    @asyncio.coroutine
    def shutdown(self):
        self._logger.warning('RealmGateway_v2 is shutting down...')
        # Close registered sockets in callback module
        for obj in self.dnscb.get_object(None):
            obj.connection_lost(None)
        # Close bound NFQUEUEs
        self._network.ipt_deregister_nfqueues()
        # Close open aiohttp_client objects
        self._network.rest_api_close()
        self._datarepository.rest_api_close()

        for task_obj, task_name in RUNNING_TASKS:
            with suppress(asyncio.CancelledError):
                self._logger.info('Cancelling {} task'.format(task_name))
                task_obj.cancel()
                yield from asyncio.sleep(1)
                yield from task_obj
                self._logger.warning('>> Cancelled {} task'.format(task_name))


if __name__ == '__main__':
    # Parse arguments
    args = parse_arguments()
    # Overload Namespace object with getdefault function
    args.getdefault = lambda name, default: getattr(args, name, default)
    # Use function to configure logging from file
    setup_logging_yaml()
    logger = logging.getLogger(__name__)
    # Get event loop
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    try:
        # Create object instance
        obj = RealmGateway(args)
        loop.run_until_complete(obj.run())
        loop.run_forever()
    except KeyboardInterrupt:
        logger.warning('Keyboard interrupt')
    except Exception as e:
        logger.exception('Exception happened', exc_info=True)
    finally:
        loop.run_until_complete(obj.shutdown())

    #This is not ideal, the obj.shutdown should cleanup the tasks
    # Let's also cancel all running tasks:
    all_tasks = asyncio.Task.all_tasks()
    logger.warning('Removing remaining tasks ({})'.format(len(all_tasks)))
    for i, task in enumerate(all_tasks):
        logger.warning('#{} {}'.format(i+1, task))
        with suppress(Exception):
            task.cancel()
            time.sleep(1)
        # Now we should await task to execute it's cancellation.
        # Cancelled task raises asyncio.CancelledError that we can suppress:
        #with suppress(asyncio.CancelledError):
        #with suppress(Exception):
        #    loop.run_until_complete(task)

    loop.stop()
    loop.close()