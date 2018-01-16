#!/usr/bin/env python3

'''
NOTE: If run into the problem of too many files open, add to the file /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535

In this test suite we attempt to generate a deterministic amount of Internet traffic to model our algorithms deployed in Realm Gateway.

We consider the following types of traffic:
1. Legitimate DNS+data clients (desired users)
2. Legitimate DNS clients      (produce address expiration)
3. Legitimate data clients     (scanner/spiders/attack via TCP)
4. Spoofed DNS clients         (produce address expiration)
5. Spoofed data clients        (SYN spoofing attacks)


####################################################################################################

#1. Legitimate DNS+data clients
We distinguish 2 phases:
a. DNS resolution: Resolve an FQDN issuing an A query request to a DNS server.
b. Data transfer: Begin an echo client instance (TCP/UDP) to the given IP address and port.


#2. Legitimate DNS clients
a. DNS resolution: Resolve an FQDN issuing an A query request to a DNS server.


#3. Legitimate data clients
b. Data transfer: Begin an echo client instance (TCP/UDP) to the given IP address and port.


#4. Spoofed DNS clients
c. Spoofed DNS resolution: Resolve an FQDN issuing an A query request to a DNS server impersonating another host/server.
This is a special case because impersonating a DNS resolver we could try to fake DNS options to also affect reputation of a host.

#5. Spoofed data clients
d. Spoofed data transfer: Send TCP SYN or UDP messages as an echo client instance to the given IP address and port.



How do we mix all of this in the same program?
We define the requirements for actions {a,b,c,d} separately.

#a. DNS resolution
 - FQDN
 - Query type fixed to A and recursive enabled
 - Source socket address
 - Remote socket address
 - Retransmission scheme

#b. Data transfer
 - Source socket address
 - Remote socket address
 - Protocol
 - Retransmission scheme

#c. Spoofed DNS resolution
 - FQDN
 - Query type fixed to A and recursive enabled
 - EDNS0 options?
 - Source socket address
 - Remote socket address
 - Retransmission scheme
 - Implementation details:
    + Use the same code as "a. DNS resolution" from a *fake* IP source
    + Measure success/failure based on A record type found in response

#d. Spoofed data transfer
 - Source socket address
 - Remote socket address
 - Protocol
 - Implementation details:
    + Use the same code as "b. Data transfer" from a *fake* IP source
    + TCP: Measure success/failure based on TCP SYN.ACK TCP opt parameters (or TCP RST) (scapy?)
    + UDP: Measure success/failure based on any response



There seems to be a rather common amount of data required for all phases.

Modelling FQDN:
 - A tuple consisting on ((s)fqdn, port, protocol)
 - Read from a file and build pool?

Modelling DNS resolvers for #1 and #2:
 - A tuple consisting on (ip, port, protocol)
 - Read from a file and build pool?

Modelling spoofed sources for DNS/data:
 - A tuple consisting on (ip, port, protocol)
 - Read from a file and build pool?

Modelling spoofed destinations for DNS:
 - A tuple consisting on (ip, port, protocol)
 - Read from a file and build pool?

Modelling spoofed destinations for data:
 - A tuple consisting on (ip, port, protocol)
 - Read from a file and build pool?


# Modelling configuration file
{'duration': 300,
 # Globals for traffic tests ?
 'service_dns': [('tcp2000.host.demo', 2000, 6), ('udp2001.host.demo', 2001, 17)],
 'service_data': [('195.148.125.202', 2000, 6), ('195.148.125.203', 2001, 17)],
 # This models all the test traffic
 'traffic': [
            # dnsdata: TCP based data & UDP based resolution
             {'type': 'dnsdata',  'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('tcp2000.host.demo', 2000, 6)]},
            # dnsdata: UDP based data & UDP based resolution
             {'type': 'dnsdata',  'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('udp2001.host.demo', 2001, 17)]},

            # dns: UDP based resolution
             {'type': 'dns',      'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('udp2002.host.demo', 2002, 17)]},

            # data: TCP based data
             {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('195.148.125.202', 3000, 6)]},
            # data: UDP based data
             {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('195.148.125.202', 3001, 17)]},



             {'type': 'spoofdns', 'load': 1, 'service_dns': [('tcp5000.host.demo', 0, 6), ('udp5000.host.demo', 0, 17)], 'local_addrs':[('2.3.4.5', 0, 17)], 'remote_addrs':[('195.148.125.201', 53, 17)]},
             {'type': 'spoofdata','load': 1, 'service_data': [('195.148.125.202', 5000, 6), ('195.148.125.203', 5000, 17)], 'local_addrs':[('2.3.4.5', 0, 17), ('2.3.4.5', 0, 6)]},
             {},
             {},
             {},
             ]
 }

Run as:   ./async_echoclient_v4.py --duration 3 --load 300 --distribution const --dnstimeout 1 1 1 --datatimeout 1 --fqdn localhost.demo:12345 --dnsaddr 127.0.0.1 --dnsport 54
Requires: ./async_echoserver_v3.py -b 127.0.0.1:12345

Run as: ./async_echoclient_v4.py --duration 3 --load 300 --distribution const --dnstimeout 1 1 1 --datatimeout 1 --dnsaddr 127.0.0.1 --dnsport 54 --fqdn localhost.demo:2000 --sfqdn udp2000.localhost.demo:2000 udp2001.localhost.demo:2001 udp2002.localhost.demo:2002 udp2003.localhost.demo:2003 udp2004.localhost.demo:2004 udp2005.localhost.demo:2005 udp2006.localhost.demo:2006 udp2007.localhost.demo:2007 udp2008.localhost.demo:2008 udp2009.localhost.demo:2009 --trafficshape 0
Requires: ./async_echoserver_v3.py -b 127.0.0.1:2000 127.0.0.1:2001 127.0.0.1:2002 127.0.0.1:2003 127.0.0.1:2004 127.0.0.1:2005 127.0.0.1:2006 127.0.0.1:2007 127.0.0.1:2008 127.0.0.1:2009
'''

import asyncio
import argparse
import json
import logging
import os
import random
import socket
import statistics
import struct
import sys
import time
import uuid


import math
import struct

import dns
import dns.message
import dns.edns
import dns.rdatatype


from helpers_n_wrappers import utils3

WATCHDOG = 1.0 #Sleep 1 second before displaying loop stats

loop = asyncio.get_event_loop()
def _now(ref = 0):
    """ Return current time based on event loop """
    return loop.time() - ref

@asyncio.coroutine
def _timeit(coro, scale = 1):
    """ Execute a coroutine and return the time consumed in second scale """
    t0 = _now()
    r = yield from coro
    return (_now(t0)*scale, r)


"""
TODOS

Define function to real_gethostbyname()
Define function to real_sendrecv()
"""

@asyncio.coroutine
def _socket_connect(raddr, laddr, family=socket.AF_INET, type=socket.SOCK_DGRAM, reuseaddr=True, timeout=1):
    sock = socket.socket(family, type)
    if reuseaddr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not laddr:
        laddr=('0.0.0.0', 0)
    sock.bind(laddr)
    sock.setblocking(False)
    #yield from loop.sock_connect(sock, raddr)
    try:
        yield from asyncio.wait_for(loop.sock_connect(sock, raddr), timeout=timeout)
        return sock
    except:
        return None


@asyncio.coroutine
def real_gethostbyname(fqdn, raddr, laddr, timeouts=[0], socktype='udp'):
    """
    fqdn: Domain name to be resolved
    addr: Tuple of IP address and port of DNS server
    timeouts: List with retransmission timeout scheme
    """
    logger = logging.getLogger('gethostbyname')
    logger.debug('Resolving to {} with timeouts {}'.format(raddr, timeouts))
    rdtype = 1
    rdclass = 1
    ipaddr = None
    attempt = 0
    response = None

    # Build query message
    query = dns.message.make_query(fqdn, rdtype, rdclass)

    # Connect socket or fail early
    _socktype = socket.SOCK_STREAM if socktype == 'tcp' else socket.SOCK_DGRAM
    sock = yield from _socket_connect(raddr, laddr, family=socket.AF_INET, type=_socktype, reuseaddr=True, timeout=1)
    if sock is None:
        logger.debug('Socket failed to connect: {}:{} ({}) / {} ({})'.format(raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
        return (ipaddr, query.id, attempt)

    for tout in timeouts:
        attempt += 1
        try:
            if socktype == 'udp':
                _data = query.to_wire()
                yield from loop.sock_sendall(sock, _data)
                dataresponse = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=tout)

            elif socktype == 'tcp':
                _data = query.to_wire()
                _data = struct.pack('!H', len(_data)) + _data
                yield from loop.sock_sendall(sock, _data)
                dataresponse = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=tout)
                _len = struct.unpack('!H', dataresponse[:2])[0]
                dataresponse = dataresponse[2:2+_len]

            response = dns.message.from_wire(dataresponse)
            assert(response.id == query.id)
            # Parsing result
            rrset = response.find_rrset(response.answer, query.question[0].name, rdtype, rdclass)
            for rdata in rrset:
                if rdtype == dns.rdatatype.A:
                    ipaddr = rdata.address
                    break
        except asyncio.TimeoutError:
            logger.info('#{} timeout expired ({:.4f} sec): {}:{} ({}) / {} ({})'.format(attempt, tout, raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            continue
        except ConnectionRefusedError:
            logger.debug('Socket failed to connect: {}:{} ({}) / {} ({})'.format(raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            break
        except AssertionError:
            logger.info('Wrong message id: {}!={} / {} ({})'.format(query.id, response.id, fqdn, dns.rdatatype.to_text(rdtype)))
            break
        except KeyError:
            logger.info('Resource records not found: {} ({})'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            break
        except Exception as e:
            logger.warning('Exception {}: {}:{} ({}) / {} ({})'.format(e, raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            break

    sock.close()
    return (ipaddr, query.id, attempt)


@asyncio.coroutine
def real_sendrecv(data, raddr, laddr, timeouts=[0], socktype='udp'):
    """
    data: Data to send
    raddr: remote tuple information
    laddr: source tuple information
    timeouts: List with retransmission timeout scheme
    socktype: L4 protocol ['udp', 'tcp']
    """
    logger = logging.getLogger('sendrecv')
    logger.debug('Echoing to {}:{} ({}) with timeouts {}'.format(raddr[0], raddr[1], socktype, timeouts))
    recvdata = None
    attempt = 0

    # Connect socket or fail early
    _socktype = socket.SOCK_STREAM if socktype == 'tcp' else socket.SOCK_DGRAM
    sock = yield from _socket_connect(raddr, laddr, family=socket.AF_INET, type=_socktype, reuseaddr=True, timeout=1)
    if sock is None:
        logger.debug('Socket failed to connect: {}:{} ({})'.format(raddr[0], raddr[1], socktype))
        return (recvdata, attempt)

    for tout in timeouts:
        attempt += 1
        try:
            yield from loop.sock_sendall(sock, data)
            recvdata = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=tout)
            break
        except asyncio.TimeoutError:
            logger.info('#{} timeout expired ({:.4f} sec): {}:{} ({})'.format(attempt, tout, raddr[0], raddr[1], socktype))
            continue
        except ConnectionRefusedError:
            logger.debug('Socket failed to connect: {}:{} ({}) / echoing {}'.format(raddr[0], raddr[1], socktype, data))
            break
        except Exception as e:
            logger.warning('Exception {}: {}:{} ({}) / echoing {}'.format(e, raddr[0], raddr[1], socktype, data))
            break

    sock.close()
    return (recvdata, attempt)


class RealDNSDataTraffic():
    # TCP based data
    # {'type': 'dnsdata',  'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('tcp2000.host.demo', 2000, 6)]},

    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (dict) results dictionary
        '''
        utils3.set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDNSDataTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            # Select parameters randomly
            _dns_laddr, _dns_raddr, = self._get_dns_parameters()
            _data_laddr, _data_raddr, = self._get_data_parameters()
            # Schedule task
            args = (_dns_laddr, _dns_raddr, _data_laddr, _data_raddr)
            loop.call_at(taskdelay, lambda: asyncio.ensure_future(self.run(*args)))
            self.logger.info('Scheduled task / {} @ {} / {}'.format(self.type, taskdelay, args))

    def _get_dns_parameters(self):
        # TODO: Match protocol of remote address with local address information
        i = self.dns_laddr[random.randint(0, len(self.dns_laddr) - 1)]
        j = self.dns_raddr[random.randint(0, len(self.dns_raddr) - 1)]
        return (i, j)

    def _get_data_parameters(self):
        # TODO: Match protocol of remote address with local address information
        i = self.data_laddr[random.randint(0, len(self.data_laddr) - 1)]
        j = self.data_raddr[random.randint(0, len(self.data_raddr) - 1)]
        return (i, j)

    @asyncio.coroutine
    def run(self, dns_laddr, dns_raddr, data_laddr, data_raddr):
        self.logger.info('[{}] Running task / {}'.format(_now(), (dns_laddr, dns_raddr, data_laddr, data_raddr)))
        ts_start = _now()

        # Store partial results
        extra_d = {'dns':{}, 'data':{}}

        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Select socket type based on protocol number
        dns_sockettype = 'tcp' if dns_rproto == 6 else 'udp'
        # DNS timeout template
        dns_timeouts = [5, 5, 5, 1]

        # Unpack Data related data
        data_fqdn,    data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'
        # DNS timeout template
        data_timeouts = [1]

        ## Run DNS resolution
        data_ripaddr, query_id, dns_attempt = yield from real_gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                            timeouts=dns_timeouts, socktype=dns_sockettype)
        # Evaluate DNS resolution
        if data_ripaddr is None:
            extra_d['dns'] = {'success': False, 'attempts': dns_attempt}
            self._add_result(False, extra_d, ts_start, _now())
            return
        # Create partial results
        extra_d['dns'] = {'success': True, 'attempts': dns_attempt}

        ## Run data transfer
        data_b = '{}@{}'.format(data_fqdn, data_ripaddr)
        data_recv, data_attempt = yield from real_sendrecv(data_b.encode(), (data_ripaddr, data_rport), (data_lipaddr, data_lport),
                                                           timeouts=data_timeouts, socktype=data_sockettype)
        # Evaluate data transfer
        if data_recv is None:
            extra_d['data'] = {'success': False, 'attempts': data_attempt}
            self._add_result(False, extra_d, ts_start, _now())
            return
        # Create partial results
        extra_d['data'] = {'success': True, 'attempts': data_attempt}
        # Add final results
        self._add_result(True, extra_d, ts_start, _now())

    def _add_result(self, success, extra_d, ts_start, ts_end):
        '''
        sucess: True or False
        extra_d: Dictionary with metadata for the current type
        '''
        # Get list of results stored for current type
        type_results = self.results.setdefault(self.type, [])
        # Add new result
        type_results.append({'success': success, 'extra': extra_d, 'ts_start': ts_start, 'ts_end': ts_end})


class RealDNSTraffic():
    # dns: UDP based resolution
    # {'type': 'dns',      'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('udp2002.host.demo', 2002, 17)]},

    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (dict) results dictionary
        '''
        utils3.set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDNSTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            # Select parameters randomly
            _dns_laddr, _dns_raddr, = self._get_dns_parameters()
            _data_laddr, _data_raddr, = self._get_data_parameters()
            # Schedule task
            args = (_dns_laddr, _dns_raddr, _data_laddr, _data_raddr)
            loop.call_at(taskdelay, lambda: asyncio.ensure_future(self.run(*args)))
            self.logger.info('Scheduled task / {} @ {} / {}'.format(self.type, taskdelay, args))

    def _get_dns_parameters(self):
        # TODO: Match protocol of remote address with local address information
        i = self.dns_laddr[random.randint(0, len(self.dns_laddr) - 1)]
        j = self.dns_raddr[random.randint(0, len(self.dns_raddr) - 1)]
        return (i, j)

    def _get_data_parameters(self):
        # TODO: Match protocol of remote address with local address information
        i = self.data_laddr[random.randint(0, len(self.data_laddr) - 1)]
        j = self.data_raddr[random.randint(0, len(self.data_raddr) - 1)]
        return (i, j)

    @asyncio.coroutine
    def run(self, dns_laddr, dns_raddr, data_laddr, data_raddr):
        self.logger.info('[{}] Running task / {}'.format(_now(), (dns_laddr, dns_raddr, data_laddr, data_raddr)))
        ts_start = _now()

        # Store partial results
        extra_d = {'dns':{}, 'data':{}}

        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Select socket type based on protocol number
        dns_sockettype = 'tcp' if dns_rproto == 6 else 'udp'
        # DNS timeout template
        dns_timeouts = [5, 5, 5, 1]

        # Unpack Data related data
        data_fqdn,    data_rport, data_rproto = data_raddr
        #data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'
        # DNS timeout template
        data_timeouts = [1]

        ## Run DNS resolution
        data_ripaddr, query_id, dns_attempt = yield from real_gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                            timeouts=dns_timeouts, socktype=dns_sockettype)
        # Evaluate DNS resolution
        if data_ripaddr is None:
            extra_d['dns'] = {'success': False, 'attempts': dns_attempt}
            self._add_result(False, extra_d, ts_start, _now())
            return
        # Create partial results
        extra_d['dns'] = {'success': True, 'attempts': dns_attempt}
        # Add final results
        self._add_result(True, extra_d, ts_start, _now())

    def _add_result(self, success, extra_d, ts_start, ts_end):
        '''
        sucess: True or False
        extra_d: Dictionary with metadata for the current type
        '''
        # Get list of results stored for current type
        type_results = self.results.setdefault(self.type, [])
        # Add new result
        type_results.append({'success': success, 'extra': extra_d, 'ts_start': ts_start, 'ts_end': ts_end})


class RealDataTraffic():
    # data: TCP based data
    # {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('195.148.125.202', 3000, 6)]},
    # data: UDP based data
    # {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('195.148.125.202', 3001, 17)]},

    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (dict) results dictionary
        '''
        utils3.set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDataTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            # Select parameters randomly
            _data_laddr, _data_raddr, = self._get_data_parameters()
            # Schedule task
            args = (_data_laddr, _data_raddr)
            loop.call_at(taskdelay, lambda: asyncio.ensure_future(self.run(*args)))
            self.logger.info('Scheduled task / {} @ {} / {}'.format(self.type, taskdelay, args))

    def _get_data_parameters(self):
        # TODO: Match protocol of remote address with local address information
        i = self.data_laddr[random.randint(0, len(self.data_laddr) - 1)]
        j = self.data_raddr[random.randint(0, len(self.data_raddr) - 1)]
        return (i, j)

    @asyncio.coroutine
    def run(self, data_laddr, data_raddr):
        self.logger.info('[{}] Running task / {}'.format(_now(), (data_laddr, data_raddr)))
        ts_start = _now()

        # Store partial results
        extra_d = {'dns':{}, 'data':{}}

        # Unpack Data related data
        data_ripaddr, data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'
        # DNS timeout template
        data_timeouts = [1]

        ## Run data transfer
        data_b = '{}@{}'.format(data_ripaddr, data_ripaddr)
        data_recv, data_attempt = yield from real_sendrecv(data_b.encode(), (data_ripaddr, data_rport), (data_lipaddr, data_lport),
                                                           timeouts=data_timeouts, socktype=data_sockettype)
        # Evaluate data transfer
        if data_recv is None:
            extra_d['data'] = {'success': False, 'attempts': data_attempt}
            self._add_result(False, extra_d, ts_start, _now())
            return
        # Create partial results
        extra_d['data'] = {'success': True, 'attempts': data_attempt}
        # Add final results
        self._add_result(True, extra_d, ts_start, _now())

    def _add_result(self, success, extra_d, ts_start, ts_end):
        '''
        sucess: True or False
        extra_d: Dictionary with metadata for the current type
        '''
        # Get list of results stored for current type
        type_results = self.results.setdefault(self.type, [])
        # Add new result
        type_results.append({'success': success, 'extra': extra_d, 'ts_start': ts_start, 'ts_end': ts_end})


class MainTestClient(object):
    def __init__(self, config_d):
        self.logger = logging.getLogger('MainTestClient')

        # Main dictionary to store results
        self.results = {}
        duration = config_d['duration']
        ts_backoff = 3
        ts_start = _now() + ts_backoff

        #print(config_d)

        type2class = {
                      'dnsdata': RealDNSDataTraffic,
                      'dns':     RealDNSTraffic,
                      'data':    RealDataTraffic,
                      }

        for item_d in config_d['traffic']:
            # Get class
            cls = type2class[item_d['type']]
            # Add globals to parameter dictionary
            item_d.setdefault('duration', duration)
            item_d.setdefault('ts_start', ts_start)
            item_d.setdefault('results', self.results)
            # Create object
            obj = cls(**item_d)


    @asyncio.coroutine
    def monitor_pending_tasks(self, watchdog = WATCHDOG):
        # Monitor number of remaining tasks and exit when done
        i = 0
        t0 = loop.time()
        while len(loop._scheduled):
            i += 1 # Counter of iterations
            self.logger.warning('({:.3f}) [{}] Pending tasks: {}'.format(_now(t0), i, len(loop._scheduled)))
            yield from asyncio.sleep(watchdog)
        self.logger.warning('({:.3f}) [{}] All tasks completed!'.format(_now(t0), i))
        return loop.time()

    def process_results(self):
        # TODO: This needs complete re-doing
        print(self.results)

        # Count results
        for data_key, data_l in self.results.items():
            nof_ok  = len([1 for _ in data_l if _['success'] is True])
            nof_nok = len([0 for _ in data_l if _['success'] is False])
            self.logger.info('{} ok={} nok={}'.format(data_key, nof_ok, nof_nok))



        '''
    def process_results(self):
        # TODO: This needs complete re-doing

        self._logger.warning('Processing results')
        self.close_result_log(self.logfile+'.results')
        self.results = self.read_result_log(self.logfile+'.results')
        self._logger.info('Found {} results'.format(len(self.results)))

        ok = nok = 0
        dns_ok = dns_nok = 0
        data_ok = data_nok = 0
        dns1 = dns2 = dns3 = dns4 = dns5 = 0
        totaldnsatt = totaldataatt = 0
        percent = lambda x,y: 0 if y == 0 else (x/y)*100
        skewvalues = []
        tdnsvalues = []
        tdatavalues = []
        totalconn = len(self.results)

        # Count results
        for value in self.results:
            if value['result']:                     ok += 1
            else:                                  nok += 1
            if   value['dns']['result']:         dns_ok +=1
            else:                               dns_nok +=1
            if   value['data']['result']:       data_ok +=1
            else:                              data_nok +=1
            if   value['dns']['attempt'] == 1:    dns1 += 1
            elif value['dns']['attempt'] == 2:    dns2 += 1
            elif value['dns']['attempt'] == 3:    dns3 += 1
            elif value['dns']['attempt'] == 4:    dns4 += 1
            elif value['dns']['attempt'] == 5:    dns5 += 1

            totaldnsatt += value['dns']['attempt']
            totaldataatt += value['data']['attempt']
            tdnsvalues.append(value['time']['dns'])
            tdatavalues.append(value['time']['data'])
            skew_ms = (value['time']['start_real'] - value['time']['start_sche'])*1000
            skewvalues.append(skew_ms)

        pok   = percent(ok,totalconn)
        pnok  = percent(nok,totalconn)
        pdns_ok  = percent(dns_ok,totalconn)
        pdns_nok = percent(dns_nok,totalconn)
        pdata_ok  = percent(data_ok,totalconn)
        pdata_nok = percent(data_nok,totalconn)

        pdns1 = percent(dns1,totalconn)
        pdns2 = percent(dns2,totalconn)
        pdns3 = percent(dns3,totalconn)
        pdns4 = percent(dns4,totalconn)
        pdns5 = percent(dns5,totalconn)

        tduration = self.results[-1]['time']['end']   - self.results[0]['time']['start_real']
        tgen = self.last_task_at - self.first_task_at
        #tgen = self.results[-1]['time']['start_real'] - self.results[0]['time']['start_real']
        if tgen == 0: tgen = 1 # Bug if we only create 1 connection

        # Write line with TABS for easy row importing
        with open(self.logfile+'.summary', 'w') as outfile:
            # Write heading
            top = ('{}\t{}\t{}\t{}\t{}\t{}\t'
                   '{}\t{}\t{}\t{}\t{}\t'
                   '{}\t{}\t{}\t{}'.format('Filename','DNS#1','DNS#2','DNS#3','DNS#4','DNS#5',
                                           'DNS#1 (%)','DNS#2 (%)','DNS#3 (%)','DNS#4 (%)','DNS#5 (%)',
                                           'Success', 'Fail', 'DNS OK (%)', 'DNS NOK (%)',
                                           'DNS queries', 'Data queries'))
            outfile.write(top+'\n')
            # Write data
            res = ('{}\t{}\t{}\t{}\t{}\t{}\t'
                   '{}\t{}\t{}\t{}\t{}\t'
                   '{}\t{}\t{}\t{}'.format(self.logfile,dns1,dns2,dns3,dns4,dns5,
                                           pdns1,pdns2,pdns3,pdns4,pdns5,
                                           ok, nok, pdns_ok, pdns_nok,
                                           totaldnsatt,totaldataatt))
            outfile.write(res+'\n')


        with open(self.logfile+'.skew', 'w') as outfile:
            outfile.write('{}\t{}\t{}\t{}\t{}\n'.format('Start schedule','Start real','Start skew (ms)', 'End', 'Total duration'))
            for value in self.results:
                start_sche = value['time']['start_sche']
                start_real = value['time']['start_real']
                skew_ms = (start_real-start_sche)*1000
                end = value['time']['end']
                tlen = end - start_real
                outfile.write('{}\t{}\t{}\t{}\t{}\t{}\n'.format(start_sche, start_real, skew_ms, end, tlen, json.dumps(value)))

        # Display results
        print('\n####################')
        print('Generated {} connections\n'.format(totalconn))
        print('Duration and rate : ({:.3f}) sec / ({:.3f}) conn/sec'.format(tduration, totalconn/tgen))
        print('# General\n>> Success {}\t({:.2f}%)\n>> Fail    {}\t({:.2f}%)'.format(ok, pok, nok, pnok))
        print('# DNS\n>> Success {}\t({:.2f}%)\n>> Fail    {}\t({:.2f}%)'.format(dns_ok, pdns_ok, dns_nok, pdns_nok))
        print('# Data\n>> Success {}\t({:.2f}%)\n>> Fail    {}\t({:.2f}%)'.format(data_ok, pdata_ok, data_nok, pdata_nok))
        print('--------------------')
        print('DNS #1 attempt:  {} ({:.2f})%'.format(dns1, pdns1))
        print('DNS #2 attempt:  {} ({:.2f})%'.format(dns2, pdns2))
        print('DNS #3 attempt:  {} ({:.2f})%'.format(dns3, pdns3))
        print('DNS #4 attempt:  {} ({:.2f})%'.format(dns4, pdns4))
        print('DNS #5 attempt:  {} ({:.2f})%'.format(dns5, pdns5))
        print('--------------------')
        print('Skew start delay   min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms '.format(min(skewvalues) , statistics.mean(skewvalues) ,max(skewvalues) ,statistics.median(map(float, skewvalues))))
        print('DNS resolutions    min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms '.format(min(tdnsvalues) , statistics.mean(tdnsvalues) ,max(tdnsvalues) ,statistics.median(map(float, tdnsvalues))))
        print('DATA connections   min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms '.format(min(tdatavalues), statistics.mean(tdatavalues),max(tdatavalues),statistics.median(map(float, tdatavalues))))
        print('--------------------')
        #print('First started at: {}'.format(self.results[0]['time']['start_real']))
        #print('Last  started at: {}'.format(self.results[-1]['time']['start_real']))
        #print('Last finished at: {}'.format(self.results[-1]['time']['end']))
        print('####################')
        '''

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

if __name__ == '__main__':
    # Use function to configure logging from file
    setup_logging_yaml()

    loop = asyncio.get_event_loop()
    loop.set_debug(True)

    logger = logging.getLogger('')

    config_d = {
     'duration': 1,
     # Globals for traffic tests ?
     #'service_dns': [('tcp2000.host.demo', 2000, 6), ('udp2001.host.demo', 2001, 17)],
     #'service_data': [('195.148.125.202', 2000, 6), ('195.148.125.203', 2001, 17)],
     # This models all the test traffic
     'traffic': [
                # dnsdata: TCP based data & UDP based resolution
                 {'type': 'dnsdata',  'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('google.es', 2000, 6)]},
                # dnsdata: UDP based data & UDP based resolution
                 {'type': 'dnsdata',  'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('udp2001.host.demo', 2001, 17)]},

                # dns: UDP based resolution
                 {'type': 'dns',      'load': 1, 'dns_laddr':[('0.0.0.0', 0, 17)], 'dns_raddr':[('8.8.8.8', 53, 17)], 'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('udp2002.host.demo', 2002, 17)]},

                # data: TCP based data
                 {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 6)],  'data_raddr': [('195.148.125.202', 3000, 6)]},
                # data: UDP based data
                 {'type': 'data',     'load': 1,                                                                      'data_laddr': [('0.0.0.0', 0, 17)], 'data_raddr': [('195.148.125.202', 3001, 17)]},
                 ]
     }

    main = MainTestClient(config_d)

    try:
        loop.run_until_complete(main.monitor_pending_tasks())
    except KeyboardInterrupt:
        logger.warning('KeyboardInterrupt!')

    #logger.warning('All tasks completed!')
    loop.stop()
    logger.warning('Processing results...')
    main.process_results()
    sys.exit(0)
