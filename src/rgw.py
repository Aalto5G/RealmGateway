#!/usr/bin/env python3

"""
BSD 3-Clause License

Copyright (c) 2018, Jesus Llorente Santos, Aalto University, Finland
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

#TODO: Add logic to register several DNS resolvers and round robin or avoid using unreachable one
#TODO: Define better transition from CUSTOMER_POLICY towards ADMIN_POLICY in filter.FORWARD - Use ipt-host-unknown ?
'''
Run as:
./rgw.py  --name             gwa.demo                                        \
          --dns-soa          gwa.demo. cname-gwa.demo.                       \
                             0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa.  \
          --dns-cname-soa    cname-gwa.demo.                                 \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.1.130 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.25 0.25 0.25                                  \
          --pool-serviceip   100.64.1.130/32                                 \
          --pool-cpoolip     100.64.1.131/32 100.64.1.132/32 100.64.1.133/32 \
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
          --repository-subscriber-folder /customer_edge_switching_v2/config.d/gwa.demo.subscriber.d/ \
          --repository-policy-folder     /customer_edge_switching_v2/config.d/gwa.demo.policy.d/     \
          --repository-api-url  http://127.0.0.1:8082/                       \
          --network-api-url     http://127.0.0.1:8081/                       \
          --synproxy         172.31.255.14 12345

'''

import argparse
import asyncio
import dns
import dns.rcode
import functools
import logging
import logging.config
import os
import time
import yaml
from contextlib import suppress
import json

from callbacks import DNSCallbacks, PacketCallbacks
from connection import ConnectionTable
from customdns.ddns import DDNSServer
from customdns.dnsproxy import DNSProxy, DNSTCPProxy
from datarepository import DataRepository
from host import HostTable, HostEntry
from network import Network
from pbra import PolicyBasedResourceAllocation
from pool import PoolContainer, NamePool, AddressPoolShared, AddressPoolUser
from suricata import SuricataAlert
from helpers_n_wrappers import utils3
from helpers_n_wrappers.aiohttp_client import HTTPRestClient
from global_variables import RUNNING_TASKS



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
    parser.add_argument('--dns-cname-soa', nargs='*', required=True,
                        help='Available SOA zones for CNAME alias generation')
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
    parser.add_argument('--synproxy', nargs=2, default=None, #('127.0.0.1', 12345),
                        metavar=('IPADDR', 'PORT'),
                        help='SYNPROXY control endpoint')

    return parser.parse_args()

class RealmGateway(object):
    def __init__(self, args):
        self._config = args

        self._oldmap = {}
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
        _t = asyncio.ensure_future(self._init_show_dnsgroups(20.0))
        RUNNING_TASKS.append((_t, 'show_dnsgroups'))
        # Initialize Subscriber information
        yield from self._init_subscriberdata()

        # Initialize Subscriber information
        yield from self._init_suricata('0.0.0.0', 12346)


        # Ready!
        self._logger.warning('RealmGateway_v2 is ready!')

    @asyncio.coroutine
    def update_policy(self):
        while True:

            yield from asyncio.sleep(10)
            # Initialize Data Repository
            self._logger.warning('Reinitializing Data Repository')
            configfile = self._config.getdefault('repository_subscriber_file', None)
            configfolder = self._config.getdefault('repository_subscriber_folder', None)
            policyfile = self._config.getdefault('repository_policy_file', None)
            policyfolder = self._config.getdefault('repository_policy_folder', None)
            api_url = self._config.getdefault('repository_api_url', None)
            yield from self._datarepository.replace()
            yield from self._init_subscriberdata()


    @asyncio.coroutine
    def _init_datarepository(self):
        # Initialize Data Repository
        self._logger.warning('Initializing Data Repository')
        configfile   = self._config.getdefault('repository_subscriber_file', None)
        configfolder = self._config.getdefault('repository_subscriber_folder', None)
        policyfile   = self._config.getdefault('repository_policy_file', None)
        policyfolder = self._config.getdefault('repository_policy_folder', None)
        api_url      = self._config.getdefault('repository_api_url', None)
        self._datarepository = yield from DataRepository.create(configfile = configfile, configfolder = configfolder,
                                              policyfile = policyfile, policyfolder = policyfolder,
                                              api_url = api_url)

        self._loop.create_task(self.update_policy())


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
                                                   network         = self._network,
                                                   cname_soa       = self._config.dns_cname_soa)

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
        self._dnscb = DNSCallbacks(cachetable      = None,
                                  datarepository  = self._datarepository,
                                  network         = self._network,
                                  hosttable       = self._hosttable,
                                  pooltable       = self._pooltable,
                                  connectiontable = self._connectiontable,
                                  pbra            = self._pbra)

        # Register defined DNS timeouts
        self._dnscb.dns_register_timeout(self._config.dns_timeout, None)
        self._dnscb.dns_register_timeout(self._config.dns_timeout_a, 1)
        self._dnscb.dns_register_timeout(self._config.dns_timeout_aaaa, 28)
        self._dnscb.dns_register_timeout(self._config.dns_timeout_srv, 33)
        self._dnscb.dns_register_timeout(self._config.dns_timeout_naptr, 35)

        # Register defined SOA zones
        for soa_name in self._config.dns_soa:
            self._logger.info('Registering DNS SOA {}'.format(soa_name))
            self._dnscb.dns_register_soa(soa_name)
        soa_list = self._dnscb.dns_get_soa()

        # Register DNS resolvers
        for ipaddr, port in self._config.dns_resolver:
            self._logger.info('Creating DNS Resolver endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.dns_register_resolver((ipaddr, port))

        # Dynamic DNS Server for DNS update messages
        for ipaddr, port in self._config.ddns_server:
            cb_function = lambda x,y,z: asyncio.ensure_future(self._dnscb.ddns_process(x,y,z))
            transport, protocol = yield from self._loop.create_datagram_endpoint(functools.partial(DDNSServer, cb_default = cb_function), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS DDNS endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.register_object('DDNS@{}:{}'.format(ipaddr, port), protocol)

        # DNS Server for WAN via UDP
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            transport, protocol = yield from self._loop.create_datagram_endpoint(functools.partial(DNSProxy, soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Server endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.register_object('DNSServer@{}:{}'.format(ipaddr, port), protocol)

        # DNS Server for WAN via TCP
        for ipaddr, port in self._config.dns_server_wan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_wan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_wan_nosoa(x,y,z))
            server = yield from self._loop.create_server(functools.partial(DNSTCPProxy, soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), host=ipaddr, port=port, reuse_address=True)
            server.connection_lost = lambda x: server.close()
            self._logger.info('Creating DNS TCP Server endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.register_object('DNSTCPServer@{}:{}'.format(ipaddr, port), server)

        # DNS Proxy for LAN
        for ipaddr, port in self._config.dns_server_lan:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_lan_soa(x,y,z))
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_lan_nosoa(x,y,z))
            transport, protocol = yield from self._loop.create_datagram_endpoint(functools.partial(DNSProxy, soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)

        ## DNS Proxy for Local
        for ipaddr, port in self._config.dns_server_local:
            cb_soa   = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_process_rgw_lan_soa(x,y,z))
            # Disable resolutions of non SOA domains for self generated DNS queries (i.e. HTTP proxy) - Answer with REFUSED
            cb_nosoa = lambda x,y,z: asyncio.ensure_future(self._dnscb.dns_error_response(x,y,z,rcode=dns.rcode.REFUSED))
            transport, protocol = yield from self._loop.create_datagram_endpoint(functools.partial(DNSProxy, soa_list = soa_list, cb_soa = cb_soa, cb_nosoa = cb_nosoa), local_addr=(ipaddr, port))
            self._logger.info('Creating DNS Proxy endpoint @{}:{}'.format(ipaddr, port))
            self._dnscb.register_object('DNSProxy@{}:{}'.format(ipaddr, port), protocol)


    @asyncio.coroutine
    def _init_subscriberdata(self):
        self._logger.warning('Initializing subscriber data')
        tzero = self._loop.time()
        self._map= {}

        for subs_id, subs_data in self._datarepository.get_policy_host_all({}).items():
            try:
                ipaddr = subs_data['ID']['ipv4'][0]
                fqdn = subs_data['ID']['fqdn'][0]
                self._map[fqdn]= ipaddr
                self._logger.debug('Registering subscriber {} / {}@{}'.format(subs_id, fqdn, ipaddr))
                yield from self._dnscb.ddns_register_user(fqdn, 1, ipaddr)

            except:
                pass
        removed_users= self._oldmap.keys() - self._map.keys()
        for fqdn in removed_users:
            ipaddr = self._oldmap[fqdn]
            self._logger.debug('Degistering subscriber / {}@{}'.format( fqdn, ipaddr))
            yield from self._dnscb.ddns_deregister_user(fqdn, 1, ipaddr)

        self._oldmap = self._map

        self._logger.info('Completed initializacion of subscriber data in {:.3f} sec'.format(self._loop.time()-tzero))

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
        self._pbra.debug_dnsgroups(transition = False)
        while True:
            yield from asyncio.sleep(delay)
            # Update table and remove expired elements
            self._pbra.debug_dnsgroups(transition = True)

    @asyncio.coroutine
    def shutdown(self):
        self._logger.warning('RealmGateway_v2 is shutting down...')
        self._dnscb.shutdown()
        self._network.shutdown()
        self._datarepository.shutdown()

        for task_obj, task_name in RUNNING_TASKS:
            with suppress(asyncio.CancelledError):
                self._logger.info('Cancelling {} task'.format(task_name))
                task_obj.cancel()
                yield from asyncio.sleep(1)
                yield from task_obj
                self._logger.warning('>> Cancelled {} task'.format(task_name))

    @asyncio.coroutine
    def _init_suricata(self, ipaddr, port):
        ## Added for Suricata testing
        transport, protocol = yield from self._loop.create_datagram_endpoint(SuricataAlert, local_addr=(ipaddr, port))
        self._logger.warning('Creating SuricataAlert endpoint @{}:{}'.format(ipaddr, port))


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
