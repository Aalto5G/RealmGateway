#!/usr/bin/env python3

"""
Copyright <2018> <Jesus Llorente Santos, Aalto University>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

# Run as:
# ./synproxy_dataplane.py --nic-wan test_wan0 --nic-wanp test_wan0p --ipaddr 127.0.0.1 --port 12345
# Run standalone with supporting network configured
# ./synproxy_dataplane.py --nic-wan test_wan0 --nic-wanp test_wan0p --ipaddr 127.0.0.1 --port 12345 --default-tcpmss 1460 --default-tcpsack 1 --default-tcpwscale 7 --standalone
# Run standalone modifying networking from the process
# ./synproxy_dataplane.py --nic-wan test_wan0 --nic-wanp test_wan0p --ipaddr 127.0.0.1 --port 12345 --default-tcpmss 1460 --default-tcpsack 1 --default-tcpwscale 7 --standalone --secure-net 195.148.124.0/24 195.148.125.201/32 --default-gw


import asyncio
import argparse
import ipaddress
import logging
import os
import socket
import struct
import subprocess
import sys
from contextlib import suppress

from helpers_n_wrappers import iptc_helper3, container3


def synproxy_build_message(mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale):
    """
    Build and return synchronization message

    Message structure:
      - 32 bits: IPv4 address
      - 16 bits: Port number
      - 8  bits: Protocol
      - 8  bits: Flags
      - 16 bits: TCP MSS value
      - 8  bits: TCP SACK value [0,1]
      - 8  bits: TCP window scaling value [0-14]
    """
    # Build flags
    flags = 0
    if mode == 'flush':
        flags |= 0b0000001
        tcpmss = 0
        tcpsack = 0
        tcpwscale = 0
        port = 0
        proto = 0
    elif mode == 'add':
        flags |= 0b0000010
    elif mode == 'mod':
        flags |= 0b0000100
    elif mode == 'del':
        flags |= 0b0001000
        tcpmss = 0
        tcpsack = 0
        tcpwscale = 0
    # Pack message
    msg = socket.inet_pton(socket.AF_INET, ipaddr) + struct.pack('!HBBHBB', port, proto, flags, tcpmss, tcpsack, tcpwscale)
    # Return built message
    return msg


def synproxy_parse_message(data):
    """ Return tuple (mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale) """
    if len(data) != 12:
        raise Exception('wrong message')

    # Unpack IP address
    ipaddr = socket.inet_ntop(socket.AF_INET, data[0:4])
    # Unpack fields
    port, proto, flags, tcpmss, tcpsack, tcpwscale = struct.unpack('!HBBHBB', data[4:12])
    # Parse flags
    ## flush
    if (flags & 0b0000001) == 0b0000001:
        mode = 'flush'
        # Assert zeroed values? (port, proto, tcpmss, tcpsack, tcpwscale)
        port, proto, tcpmss, tcpsack, tcpwscale = 0, 0, 0, 0, 0
    ## add
    elif (flags & 0b0000010) == 0b0000010:
        mode = 'add'
    ## mod
    elif (flags & 0b0000100) == 0b0000100:
        mode = 'mod'
    ## del
    elif (flags & 0b0001000) == 0b0001000:
        mode = 'del'
    else:
        raise Exception('wrong message')

    # Do not process port and proto flags
    return (mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)


class SYNProxyConnectionTCP(container3.ContainerNode):
    def __init__(self, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale, ipt_rule):
        self.ipaddr = ipaddr
        self.port = port
        self.proto = proto
        self.tcpmss = tcpmss
        self.tcpsack = tcpsack
        self.tcpwscale = tcpwscale
        # Add rule object to minimize Netlink load
        self.ipt_rule = ipt_rule

    def lookupkeys(self):
        """ Return the lookup keys of the node. """
        # Create 3-tuple and 1-tuple (IP-based) matches
        return (((self.ipaddr, self.port, self.proto), True), (self.ipaddr, False))

    def dump(self):
        """ Return a string representation of the node. """
        return '[{}] {}:{} / mss={} sack={} wscale={}'.format(self.proto, self.ipaddr, self.port, self.tcpmss, self.tcpsack, self.tcpwscale)

    def __repr__(self):
        return self.dump()


class SYNProxyDataplane():
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('SYNProxyDataplane')
        # Store local parameters
        self.nic_wan  = kwargs['nic_wan']
        self.nic_wanp = kwargs['nic_wanp']
        self.default_gw = kwargs['default_gw']
        self.secure_net = kwargs['secure_net']
        # Create a connection table to store the rules
        self.connectiontable = container3.Container(name='ConnectionTable')
        # Continue with bootstrapping actions
        self.ovs_create()
        self.ovs_init_flows()
        self.ipt_init_flows()

        # Start monitor task
        self.tasks = []
        _t = asyncio.ensure_future(self.monitor(10))
        self.tasks.append(_t)

        # Run in standalone mode with default flow
        if kwargs['standalone']:
            self._logger.info('Standalone more active, insert default rule')
            self._do_mod('0.0.0.0', 0, 6, kwargs['tcpmss'], kwargs['tcpsack'], kwargs['tcpwscale'])

    @asyncio.coroutine
    def shutdown(self):
        self._logger.warning('Removing OpenvSwitch instance')

        ## Delete OVS bridge
        to_exec = ['ovs-vsctl --if-exists del-br br-synproxy']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = False, silent = False)

        ## Restart OpenvSwitch service
        to_exec = ['systemctl restart openvswitch-switch']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Cancel running tasks
        for _task in self.tasks:
            with suppress(asyncio.CancelledError):
                del _task
                yield from asyncio.sleep(1)


    def ovs_create(self):
        self._logger.info('Create OpenvSwitch instance')

        ## Enable IP forwarding
        to_exec = ['sysctl -w  net.ipv4.ip_forward=1']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = True)

        # Setting up TCP SYNPROXY ipt_SYNPROXY
        # https://r00t-services.net/knowledgebase/14/Homemade-DDoS-Protection-Using-IPTables-SYNPROXY.html
        to_exec = ['sysctl -w net.ipv4.tcp_syncookies=1',
                   'sysctl -w net.ipv4.tcp_timestamps=1',
                   'sysctl -w net.netfilter.nf_conntrack_tcp_loose=0']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = False, silent = True)


        ## Restart OpenvSwitch service
        to_exec = ['systemctl restart openvswitch-switch']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Create OVS bridge
        to_exec = ['ovs-vsctl --if-exists del-br br-synproxy',
                   'ovs-vsctl             add-br br-synproxy']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Add ports
        to_exec = ['ovs-vsctl add-port br-synproxy {0}  -- set interface {0}  ofport_request=1'.format(self.nic_wan),
                   'ovs-vsctl add-port br-synproxy mitm0 -- set interface mitm0 ofport_request=2 -- set interface mitm0 type=internal # Connected to *WAN*',
                   'ovs-vsctl add-port br-synproxy mitm1 -- set interface mitm1 ofport_request=3 -- set interface mitm1 type=internal # Connected to *WAN_proxied*',
                   'ovs-vsctl add-port br-synproxy {0} -- set interface {0} ofport_request=4'.format(self.nic_wanp)]
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Configure ports
        to_exec = ['ip link set dev mitm0 arp off',
                   'ip link set dev mitm0 address 00:00:00:aa:bb:cc',
                   'ip link set dev mitm0 up',
                   'ip link set dev mitm1 arp off',
                   'ip link set dev mitm1 address 00:00:00:dd:ee:ff',
                   'ip link set dev mitm1 up',
                   'ip link set dev {0} up'.format(self.nic_wan),
                   'ip link set dev {0} up'.format(self.nic_wanp)]

        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Configure default gateway
        if self.default_gw:
            self._logger.info('Adding route to default gateway via mimt0')
            _ = 'ip route add default dev mitm0 metric 100'
            self._do_subprocess_call(_, raise_exc = False, silent = True)

        ## Configure secure networks
        for net in self.secure_net:
            self._logger.info('Adding route to secure network {} via mitm1'.format(net))
            _ = 'ip route add {} dev mitm1'.format(net)
            self._do_subprocess_call(_, raise_exc = False, silent = True)


    def ovs_init_flows(self):
        self._logger.info('Initialize OpenvSwitch flows')

        ## Create basic table architecture
        to_exec = ['ovs-ofctl del-flows -O OpenFlow13 br-synproxy',
                   ### Go to ARP MAC Learning table
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=100,dl_type=0x0806,           actions=goto_table:1"',
                   ### Go to TCP Forwading table
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=100,dl_type=0x0800,nw_proto=6 actions=goto_table:2"',
                   ### Default flow
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=0,priority=1                             actions=NORMAL"',
                   ### ARP MAC Learning Learning table 1
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=1,priority=1                             actions=NORMAL"',
                   ### TCP Forwading table 2
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=2,priority=1                             actions=goto_table:3"']

        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)

        ## Create TCP learning flows
        #### Learn new flows coming from WAN
        to_exec = ['ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=3,priority=1,in_port=1,dl_type=0x0800 actions=load:0x0001->NXM_NX_REG0[0..15],load:0x0002->NXM_NX_REG1[0..15],load:0x0003->NXM_NX_REG2[0..15],load:0x0004->NXM_NX_REG3[0..15],                                                                                                           \
                learn(table=2,hard_timeout=30,priority=200,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
                learn(table=2,                priority=200,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG0[0..15]), \
                learn(table=2,                priority=200,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_DST[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG3[0..15]), \
                learn(table=2,hard_timeout=30,priority=200,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_SRC[]=NXM_OF_IP_DST[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15]), \
                resubmit(,2)"',
                    #### Learn new flows coming from WAN_proxied
                   'ovs-ofctl add-flow -O OpenFlow13 br-synproxy "table=3,priority=1,in_port=4,dl_type=0x0800 actions=load:0x0001->NXM_NX_REG0[0..15],load:0x0002->NXM_NX_REG1[0..15],load:0x0003->NXM_NX_REG2[0..15],load:0x0004->NXM_NX_REG3[0..15],                                                                                                           \
                learn(table=2,hard_timeout=30,priority=100,in_port=1,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_DST[],NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:0x000000aabbcc->NXM_OF_ETH_DST[], output:NXM_NX_REG1[0..15]), \
                learn(table=2,                priority=100,in_port=2,dl_type=0x0800,NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_SRC[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_DST[],                           output:NXM_NX_REG0[0..15]), \
                learn(table=2,                priority=100,in_port=3,dl_type=0x0800,NXM_OF_IP_DST[]=NXM_OF_IP_SRC[] load:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],load:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],                           output:NXM_NX_REG3[0..15]), \
                learn(table=2,hard_timeout=30,priority=100,in_port=4,dl_type=0x0800,NXM_OF_ETH_SRC[]=NXM_OF_ETH_SRC[],NXM_OF_ETH_DST[]=NXM_OF_ETH_DST[],NXM_OF_IP_SRC[]=NXM_OF_IP_SRC[] load:0x000000ddeeff->NXM_OF_ETH_DST[], output:NXM_NX_REG2[0..15]), \
                resubmit(,2)"']
        for _ in to_exec:
            self._do_subprocess_call(_, raise_exc = True, silent = False)


    def ipt_init_flows(self):
        # Specific TCP flows are inserted/appended to filter.synproxy_chain """
        self._logger.info('Initialize iptables chains and rules')

        # Add custom chains
        iptc_helper3.add_chain('raw', 'synproxy_chain', ipv6=False, silent=True)
        iptc_helper3.add_chain('filter', 'synproxy_chain', ipv6=False, silent=True)

        # Flush chains
        iptc_helper3.flush_chain('raw', 'PREROUTING', ipv6=False, silent=False)
        iptc_helper3.flush_chain('filter', 'FORWARD', ipv6=False, silent=False)
        iptc_helper3.flush_chain('raw', 'synproxy_chain', ipv6=False, silent=False)
        iptc_helper3.flush_chain('filter', 'synproxy_chain', ipv6=False, silent=False)

        # Populate chains with basic rules
        ## raw.PREROUTING
        rule_d = {'in-interface': 'mitm0', 'protocol': 'tcp', 'target': 'synproxy_chain'}
        iptc_helper3.add_rule('raw', 'PREROUTING', rule_d, position=0, ipv6=False)
        rule_d = {'in-interface': 'mitm1', 'protocol': 'tcp', 'target': 'synproxy_chain'}
        iptc_helper3.add_rule('raw', 'PREROUTING', rule_d, position=0, ipv6=False)
        ## raw.synproxy_chain
        rule_d = {'in-interface': 'mitm0', 'protocol': 'tcp', 'tcp': {'tcp-flags': ['FIN,SYN,RST,ACK', 'SYN']}, 'target': {'CT': {'notrack': ''}}, }
        iptc_helper3.add_rule('raw', 'synproxy_chain', rule_d, position=0, ipv6=False)
        rule_d = {'target': 'ACCEPT'}
        iptc_helper3.add_rule('raw', 'synproxy_chain', rule_d, position=0, ipv6=False)
        ## filter.FORWARD
        rule_d = {'in-interface': 'mitm0', 'protocol': 'tcp', 'target': 'synproxy_chain'}
        iptc_helper3.add_rule('filter', 'FORWARD', rule_d, position=0, ipv6=False)
        rule_d = {'in-interface': 'mitm1', 'protocol': 'tcp', 'target': 'synproxy_chain'}
        iptc_helper3.add_rule('filter', 'FORWARD', rule_d, position=0, ipv6=False)
        ## filter.synproxy_chain
        rule_d = {'protocol': 'tcp', 'conntrack': {'ctstate': ['INVALID']}, 'target': 'DROP'}
        iptc_helper3.add_rule('filter', 'synproxy_chain', rule_d, position=0, ipv6=False)


    def process_message(self, data, addr):
        # Parse received message
        mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale = synproxy_parse_message(data)
        self._logger.debug('Data received from {}: {}'.format(addr, (mode, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)))
        # Evaluate mode
        if mode == 'flush':
            ret = self._do_flush(ipaddr)
        elif mode == 'add':
            ret = self._do_add(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)
        elif mode == 'mod':
            ret = self._do_mod(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)
        elif mode == 'del':
            ret = self._do_del(ipaddr, port, proto)
        # Return result
        if ret:
            return b'1\n'
        else:
            return b'0\n'

    @asyncio.coroutine
    def monitor(self, interval):
        """ Monitoring service to display periodic information """
        self._logger.info('Monitoring connection table state every {} sec'.format(interval))
        while True:
            connections = self.connectiontable.getall()
            nof_connections = len(connections)
            self._logger.info('There are currently {} connection(s)'.format(nof_connections))
            if nof_connections:
                self._logger.info('\n'.join('\t#{}. {}'.format(_i+1, _c) for _i, _c in enumerate(connections)))
            yield from asyncio.sleep(interval)

    def _do_subprocess_call(self, command, raise_exc = True, silent = False):
        try:
            self._logger.debug('System call: {}'.format(command))
            if silent:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f, stderr=f)
            else:
                subprocess.check_call(command, shell=True)
            return True
        except Exception as e:
            if not silent:
                self._logger.info(e)
            if raise_exc:
                raise e
            return False


    def _build_ipt_synproxy_rule(self, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale):
        # Adjust parameters
        if ipaddr == '0.0.0.0':
            ipaddr = '0.0.0.0/0'

        # Basic rule
        rule_d = {'conntrack': {'ctstate': ['INVALID,UNTRACKED']},
                  'in-interface': 'mitm0', 'out-interface': 'mitm1',
                  'protocol': 'tcp',
                  'tcp':{},
                  'target': {'SYNPROXY': {}}}
        # Set specifics
        rule_d['dst'] = ipaddr
        if port != 0:
            rule_d['tcp']['dport'] = str(port)
        rule_d['target']['SYNPROXY']['mss'] = str(tcpmss)
        rule_d['target']['SYNPROXY']['wscale'] = str(tcpwscale)
        if tcpsack:
            rule_d['target']['SYNPROXY']['sack-perm'] = ''
        # Return rule
        return rule_d


    def _do_flush(self, ipaddr):
        # Flush connections based on IP address
        if ipaddr == '0.0.0.0':
            connections = self.connectiontable.getall()
        elif self.connectiontable.has(ipaddr):
            connections = self.connectiontable.get(ipaddr)
        else:
            # Nothing to do here
            self._logger.debug('[flush] No connection(s) found for ipaddr={}'.format(ipaddr))
            return False

        # We need a new iterable not to modify on the fly the set/list of connections
        _connections = list(connections)

        # Optimize for batch mode?
        BATCH = True
        if BATCH:
            for connection in _connections:
                self._logger.info('Flush connection: {}'.format(connection))
                self.connectiontable.remove(connection, callback=False)

            batch_rules = [('synproxy_chain', _c.ipt_rule) for _c in _connections]
            iptc_helper3.batch_begin(table='filter', ipv6=False)
            iptc_helper3.batch_delete_rules('filter', batch_rules, ipv6=False, silent=True)
            iptc_helper3.batch_end(table='filter', ipv6=False)

        else:
            for connection in _connections:
                self._logger.info('Flush connection: {}'.format(connection))
                self.connectiontable.remove(connection, callback=False)
                iptc_helper3.delete_rule('filter', 'synproxy_chain', connection.ipt_rule, ipv6=False, silent=True)

        return True

    def _do_add(self, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale):
        # Add a connection based on given parameters
        # Define inserting position based on n-tuple match
        if ipaddr != '0.0.0.0' and port != 0:
            # 3-tuple connection, higher priority
            pos = 1
        elif ipaddr != '0.0.0.0' and port == 0:
            # 3-tuple connection with wildcard port, higher priority than default
            pos = -3
        elif ipaddr == '0.0.0.0':
            # Default connection, lowest priority
            pos = -2
        else:
            raise Exception('Unsupported! {}'.format(ipaddr, proto, port, tcpmss, tcpsack, tcpwscale))

        if self.connectiontable.has((ipaddr, port, proto)):
            connection = self.connectiontable.get((ipaddr, port, proto))
            self._logger.debug('[add] Conflict exists for {} / {}'.format((ipaddr, port, proto, tcpmss, tcpsack, tcpwscale), connection))
            return False

        # Create iptables rule and connection object
        ipt_rule = self._build_ipt_synproxy_rule(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)
        connection = SYNProxyConnectionTCP(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale, ipt_rule)
        self.connectiontable.add(connection)
        # Insert rule at precise position
        self._logger.info('Add connection: {}'.format(connection))
        iptc_helper3.add_rule('filter', 'synproxy_chain', ipt_rule, position=pos, ipv6=False)
        return True

    def _do_mod(self, ipaddr, port, proto, tcpmss, tcpsack, tcpwscale):
        # Modify a connection based on given parameters
        # Define inserting position based on n-tuple match
        if ipaddr != '0.0.0.0' and port != 0:
            # 3-tuple connection, higher priority
            pos = 1
        elif ipaddr != '0.0.0.0' and port == 0:
            # 3-tuple connection with wildcard port, higher priority than default
            pos = -3
        elif ipaddr == '0.0.0.0':
            # Default connection, lowest priority
            pos = -2
        else:
            raise Exception('Unsupported! {}'.format(ipaddr, proto, port, tcpmss, tcpsack, tcpwscale))

        if self.connectiontable.has((ipaddr, port, proto)):
            connection = self.connectiontable.get((ipaddr, port, proto))
            # Check if the existing parameters are the same
            if connection.tcpmss == tcpmss and connection.tcpsack == tcpsack and connection.tcpwscale == tcpwscale:
                self._logger.debug('[mod] Modify not required : {} / {}'.format(connection, (tcpmss, tcpsack, tcpwscale)))
                return True
            # Create iptables rule and update connection object
            old_ipt_rule = connection.ipt_rule
            new_ipt_rule = self._build_ipt_synproxy_rule(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)
            self._logger.info('Modify connection: {} / {}'.format(connection, (tcpmss, tcpsack, tcpwscale)))
            connection.ipt_rule = new_ipt_rule
            # Replace rule
            iptc_helper3.replace_rule('filter', 'synproxy_chain', old_ipt_rule, new_ipt_rule, ipv6=False)
        else:
            # Create iptables rule and connection object
            ipt_rule = self._build_ipt_synproxy_rule(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale)
            connection = SYNProxyConnectionTCP(ipaddr, port, proto, tcpmss, tcpsack, tcpwscale, ipt_rule)
            self.connectiontable.add(connection)
            # Insert rule at precise position
            self._logger.info('Add connection: {}'.format(connection))
            iptc_helper3.add_rule('filter', 'synproxy_chain', ipt_rule, position=pos, ipv6=False)

        return True

    def _do_del(self, ipaddr, port, proto):
        # Delete a connection based on given parameters
        if not self.connectiontable.has((ipaddr, port, proto)):
            # Nothing to do here
            self._logger.debug('[del] No connection found for key={}'.format((ipaddr, port, proto)))
            return False

        connection = self.connectiontable.get((ipaddr, port, proto))
        self._logger.info('Delete connection: {}'.format(connection))
        self.connectiontable.remove(connection, callback=False)
        iptc_helper3.delete_rule('filter', 'synproxy_chain', connection.ipt_rule, ipv6=False, silent=True)
        return True


class SYNProxyDataplaneEndpoint(asyncio.Protocol):
    # start -> connection_made() [-> data_received() *] [-> eof_received() ?] -> connection_lost() -> end
    def __init__(self, cb):
        self._logger = logging.getLogger('SYNProxyDataplaneEndpoint')
        self.cb = cb
        self._buffer = b''

    def connection_made(self, transport):
        self._transport = transport
        # Get local and remote addresses from transport
        self.laddr = transport.get_extra_info('sockname')
        self.raddr = transport.get_extra_info('peername')
        # Set TCP_NODELAY
        sock = transport.get_extra_info('socket')
        try:
            sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        except (OSError, NameError):
            pass
        self._logger.info('Connected endpoint @{0}:{1}'.format(self.raddr[0], self.raddr[1]))

    def connection_lost(self, exc):
        self._logger.info('Connection lost @{0}:{1} {2}'.format(self.raddr[0], self.raddr[1], exc))
        self._transport = None

    def _read_from_buffer(self, data, n=12):
        # Add data to buffer and read n bytes if possible
        self._buffer += data
        if len(self._buffer) >= 12:
            _data = self._buffer[:12]
            self._buffer = self._buffer[12:]
            return _data
        else:
            return ''

    def data_received(self, data):
        # Add data to buffer and extract up to one message
        _data = self._read_from_buffer(data)
        # Process messages in a loop while there is data in the buffer
        while _data:
            response = self.cb(_data, self.raddr)
            self._transport.write(response)
            _data = self._read_from_buffer(b'')


def validate_arguments(args):
    # Validate IPv4 address
    try:
        socket.inet_pton(socket.AF_INET, args.ipaddr)
    except:
        logger.error('IPv4 address not valid <{}>'.format(args.ipaddr))
        sys.exit(1)

    # Validate port number
    if args.port <= 0 or args.port > 65535:
        logger.error('Port number not valid <{}>'.format(args.port))
        sys.exit(1)

    # Validate TCP MSS value
    ## Set MAX MTU size at 9000
    if args.default_tcpmss <= 0 or args.default_tcpmss > 8960:
        logger.error('TCP MSS value not valid <{}> (1-8960)'.format(args.default_tcpmss))
        sys.exit(1)

    # Validate TCP window scaling value
    if args.default_tcpwscale < 0 or args.default_tcpwscale > 14:
        logger.error('TCP window scale value not valid <{}> (0-14)'.format(args.default_tcpwscale))
        sys.exit(1)

    # Validate secure networks value
    for net in args.secure_net:
        try:
            ipaddress.IPv4Network(net)
        except:
            logger.error('Network not valid <{}>'.format(net))
            sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description='TCP SYN Proxy ControlPlane v0.1')
    # Socket address
    parser.add_argument('--ipaddr', type=str, default='127.0.0.1',
                        help='Dataplane IP address')
    parser.add_argument('--port', type=int, default=12345,
                        help='Dataplane IP address')
    # Network information
    parser.add_argument('--nic-wan', type=str, required=True,
                        help='NIC connected to wild WAN')
    parser.add_argument('--nic-wanp', type=str, required=True,
                        help='NIC connected to proxied WAN')

    parser.add_argument('--standalone', action='store_true',
                        help='Run in standalone with default TCP options')
    parser.add_argument('--default-tcpmss', type=int, default=1460,
                        metavar=('TCPMSS'),
                        help='Default TCP MSS value')
    parser.add_argument('--default-tcpsack',  type=int, default=1,
                        choices=[0, 1],
                        metavar=('TCPSACK'),
                        help='Default TCP SACK [True, False]')
    parser.add_argument('--default-tcpwscale', type=int, default=7,
                        choices=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
                        metavar=('TCPWSCALE'),
                        help='Default TCP window scaling value [0-14]')

    parser.add_argument('--secure-net', nargs='*', type=str,
                        help='Networks behind SYNPROXY in CIDR format e.g. 195.148.124.0/24 195.148.125.0/24')
    parser.add_argument('--default-gw', action='store_true',
                        help='Add default gateway route')

    args = parser.parse_args()
    validate_arguments(args)
    return args


# Get event loop
loop = asyncio.get_event_loop()
# Get logger instance
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('')

if __name__ == '__main__':
    # Parse arguments
    args = parse_arguments()
    logger.info('Starting server @{}:{}'.format(args.ipaddr, args.port))
    synproxy_obj = SYNProxyDataplane(nic_wan = args.nic_wan,
                                     nic_wanp = args.nic_wanp,
                                     standalone = args.standalone,
                                     tcpmss = args.default_tcpmss,
                                     tcpsack = args.default_tcpsack,
                                     tcpwscale = args.default_tcpwscale,
                                     secure_net = args.secure_net,
                                     default_gw = args.default_gw
                                     )
    cb = synproxy_obj.process_message
    coro = loop.create_server(lambda: SYNProxyDataplaneEndpoint(cb = cb),
                              host=args.ipaddr,
                              port=args.port,
                              reuse_address=True)

    try:
        server = loop.run_until_complete(coro)
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(synproxy_obj.shutdown())

    server.close()
    loop.close()
    logger.warning('Bye!')
    sys.exit(0)


'''
How to create test flows from sibling synproxy_controlplane.py script

TESTS

#1 - Flush all - OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0

#2 - Flush all twice - OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0

#3 - Flush all then flush IP address - OK/NOK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 1.1.1.1

#4 - Flush all then add default connection - OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 0.0.0.0 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#5 - Flush all then add default connection twice - OK/OK/NOK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 0.0.0.0 --conn-proto 6 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 0.0.0.0 --conn-proto 6 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#6 - Flush all then add default connection then modify - OK/OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 0.0.0.0 --conn-proto 6 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode mod   --conn-dstaddr 0.0.0.0 --conn-proto 6 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#7 - Flush all then add default connection then modify - OK/OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode mod   --conn-dstaddr 0.0.0.0 --conn-proto 6 --conn-dstport 0  --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#8 - Flush all then add default connection then delete - OK/OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode del   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#9 - Flush all then add default connection then delete NOK - OK/OK/NOK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode del   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 0  --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7

#10 - Flush all then add default connection then delete NOK - OK/OK/OK/OK/OK
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 22 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 23 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 24 --conn-tcpmss 1460 --conn-tcpsack 1 --conn-tcpwscale 7
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 1.1.1.1

# 11 - Add in benchmark mode
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 1 --conn-tcpmss  536 --conn-tcpsack 1 --conn-tcpwscale 1 --benchmark --benchmark-seq 1 --benchmark-iter 5000 #4000 ops
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 1 --conn-tcpmss  536 --conn-tcpsack 1 --conn-tcpwscale 1 --benchmark --benchmark-seq 1 --benchmark-iter 500  #330  ops
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode add   --conn-dstaddr 1.1.1.1 --conn-proto 6 --conn-dstport 1 --conn-tcpmss  536 --conn-tcpsack 1 --conn-tcpwscale 1 --benchmark --benchmark-seq 1 --benchmark-iter 5000 #115  ops
./synproxy_controlplane.py --ipaddr 127.0.0.1 --port 12345 --mode flush --conn-dstaddr 0.0.0.0                                                                                        --benchmark --benchmark-seq 1 --benchmark-iter 1

'''

