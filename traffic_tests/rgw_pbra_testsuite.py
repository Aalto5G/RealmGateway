#!/usr/bin/env python3

"""
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
We use Scapy for packet manipulation.

#5. Spoofed data clients
d. Spoofed data transfer: Send TCP SYN or UDP messages as an echo client instance to the given IP address and port.
We use Scapy for packet manipulation.


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
 - Retransmission scheme ?
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


NB: A configuration file example is added at the end of the file, after the Python code

Requires: ./async_echoserver_v3.py -b 127.0.0.1:12345
Requires: ./async_echoserver_v3.py -b 127.0.0.1:2000 127.0.0.1:2001 127.0.0.1:2002 127.0.0.1:2003 127.0.0.1:2004 127.0.0.1:2005 127.0.0.1:2006 127.0.0.1:2007 127.0.0.1:2008 127.0.0.1:2009

"""


import asyncio
import argparse
import functools
import json
import logging
import math
import os
import random
import socket
import statistics
import struct
import sys
import time
import yaml

import dns
import dns.message
import dns.edns
import dns.rdataclass
import dns.rdatatype

# For Scapy
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *


WATCHDOG = 1.0 #Sleep 1 second before displaying loop stats
RESULTS = []   #List to store TestResult objects

loop = asyncio.get_event_loop()
TS_ZERO = loop.time()
TASK_NUMBER = 0

def set_attributes(obj, override=False, **kwargs):
    """Set attributes in object from a dictionary"""
    for k,v in kwargs.items():
        if hasattr(obj, k) and not override:
            continue
        setattr(obj, k, v)

def _now(ref = 0):
    """ Return current time based on event loop """
    return loop.time() - ref

@asyncio.coroutine
def _timeit(coro, scale = 1):
    """ Execute a coroutine and return the time consumed in second scale """
    t0 = _now()
    r = yield from coro
    return (_now(t0)*scale, r)

@asyncio.coroutine
def _socket_connect(raddr, laddr, family=socket.AF_INET, type=socket.SOCK_DGRAM, reuseaddr=True, timeout=1):
    sock = socket.socket(family, type)
    if reuseaddr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not laddr:
        laddr=('0.0.0.0', 0)
    if type == socket.SOCK_STREAM:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 0, 0))

    sock.bind(laddr)
    sock.setblocking(False)
    try:
        yield from asyncio.wait_for(loop.sock_connect(sock, raddr), timeout=timeout)
        return sock
    except Exception as e:
        logger = logging.getLogger('_socket_connect')
        logger.exception(e)
        return None

@asyncio.coroutine
def _gethostbyname(fqdn, raddr, laddr, timeouts=[0], socktype='udp', reuseaddr=False):
    """
    fqdn: Domain name to be resolved
    raddr: Remote tuple information
    raddr: Local tuple information
    timeouts: List with retransmission timeout scheme
    """
    global TS_ZERO
    logger = logging.getLogger('gethostbyname')
    logger.debug('Resolving to {} with timeouts {}'.format(raddr, timeouts))
    rdtype = dns.rdatatype.A
    rdclass = dns.rdataclass.IN
    ipaddr = None
    attempt = 0
    response = None

    # Build query message
    query = dns.message.make_query(fqdn, rdtype, rdclass)

    # Connect socket or fail early
    _socktype = socket.SOCK_STREAM if socktype == 'tcp' else socket.SOCK_DGRAM
    sock = yield from _socket_connect(raddr, laddr, family=socket.AF_INET, type=_socktype, reuseaddr=reuseaddr, timeout=2)
    if sock is None:
        logger.warning('Socket failed to connect: {}:{} > {}:{} ({}) / {} ({})'.format(laddr[0], laddr[1], raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
        return (ipaddr, query.id, attempt)

    for tout in timeouts:
        attempt += 1
        try:
            if socktype == 'udp':
                _data = query.to_wire()
                yield from loop.sock_sendall(sock, _data)
                dataresponse = yield from asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=tout)
                response = dns.message.from_wire(dataresponse)
                # Check if response is truncated and retry in TCP with a recursive call
                if (response.flags & dns.flags.TC == dns.flags.TC):
                    _data_ripaddr, _query_id, _dns_attempts = yield from _gethostbyname(fqdn, raddr, laddr, timeouts, socktype='tcp', reuseaddr=reuseaddr)
                    return (_data_ripaddr, _query_id, _dns_attempts)

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
            ## With new PBRA DNS design, we might receive a CNAME instead of an A record, so we have to follow up with a new query to the given domain
            ## First try to obtain the A record and return if successful
            for rrset in response.answer:
                for rdata in rrset:
                    if rdata.rdtype == dns.rdatatype.A:
                        ipaddr = rdata.address
                        logger.debug('[{:.3f}] {} @ {} via {}'.format(_now(TS_ZERO), fqdn, ipaddr, raddr[0]))
                        sock.close()
                        return (ipaddr, query.id, attempt)
            ## Alternatively, try to follow-up through the CNAME record and with a recursive call
            for rrset in response.answer:
                for rdata in rrset:
                    if rdata.rdtype == dns.rdatatype.CNAME:
                        target = rdata.to_text()
                        logger.debug('[{:.3f}] {} @ {} via {}'.format(_now(TS_ZERO), fqdn, target, raddr[0]))
                        _data_ripaddr, _query_id, _dns_attempts = yield from _gethostbyname(target, raddr, laddr, timeouts, socktype='udp')
                        return (_data_ripaddr, _query_id, _dns_attempts)

        except asyncio.TimeoutError:
            logger.info('#{} timeout expired ({:.4f} sec): {}:{} ({}) / {} ({})'.format(attempt, tout, raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            continue
        except ConnectionRefusedError:
            logger.exception('Socket failed to connect: {}:{} ({}) / {} ({})'.format(raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            break
        except AssertionError:
            # This may happen if we have many sockets open
            _laddr = sock.getsockname()
            logger.exception('Wrong message id: {}!={} / {} ({}) / {}:{}'.format(query.id, response.id, fqdn, dns.rdatatype.to_text(rdtype), _laddr[0], _laddr[1]))
            break
        except KeyError:
            logger.exception('Resource records not found: {} ({})'.format(fqdn, dns.rdatatype.to_text(rdtype)))
            break
        except Exception as e:
            logger.warning('Exception {}: {}:{} ({}) / {} ({})'.format(e, raddr[0], raddr[1], socktype, fqdn, dns.rdatatype.to_text(rdtype)))
            break

    sock.close()
    return (ipaddr, query.id, attempt)

@asyncio.coroutine
def _sendrecv(data, raddr, laddr, timeouts=[0], socktype='udp', reuseaddr=False):
    """
    data: Data to send
    raddr: Remote tuple information
    laddr: Source tuple information
    timeouts: List with retransmission timeout scheme
    socktype: L4 protocol ['udp', 'tcp']
    """
    logger = logging.getLogger('sendrecv')
    logger.debug('Echoing to {}:{} ({}) with timeouts {}'.format(raddr[0], raddr[1], socktype, timeouts))
    recvdata = None
    attempt = 0

    # Connect socket or fail early
    _socktype = socket.SOCK_STREAM if socktype == 'tcp' else socket.SOCK_DGRAM
    sock = yield from _socket_connect(raddr, laddr, family=socket.AF_INET, type=_socktype, reuseaddr=reuseaddr, timeout=2)
    if sock is None:
        logger.warning('Socket failed to connect: {}:{} > {}:{} ({})'.format(laddr[0], laddr[1], raddr[0], raddr[1], socktype))
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


def _scapy_build_packet(src, dst, proto, sport, dport, payload=b''):
    if sport == 0:
        sport = random.randint(1,65535)
    if dport == 0:
        dport = random.randint(1,65535)
    if proto == 6:
        layer_4 = TCP(sport=sport, dport=dport, seq=random.randint(1,2**32-1))
    elif proto == 17:
        layer_4 = UDP(sport=sport, dport=dport)/Raw(payload)
    else:
        raise Exception('Protocol <{}> not supported'.format(proto))

    eth_pkt = Ether()/IP(src=src, dst=dst)/layer_4
    return eth_pkt

_l2socket_cache = {}
def _scapy_send_packet(packet, iface):
    """ Accepts packet of type Packet() or bytes """
    try:
        # Get sending raw socket
        if iface is None and not isinstance(packet, bytes):
            sendp(packet, iface=iface, verbose=False)
            return True

        # Create new L2Socket and add it to the local cache
        if iface not in _l2socket_cache:
            _l2socket_cache[iface] = scapy.arch.linux.L2Socket(iface=iface)
        # Continue with L2Socket
        l2socket = _l2socket_cache[iface]
        # Obtain wire representation of the packet
        if not isinstance(packet, bytes):
            packet = bytes(packet)
        # Streamlined send function
        l2socket.outs.send(packet)
        return True
    except OSError as e:
        if isinstance(packet, bytes):
            # Packetize to enhance logging information
            packet = Ether(packet)
        logger.error('Failed to send packet via {} <{}> / {}'.format(iface, e, packet.command()))
        return False

def _get_service_tuple(local_l, remote_l):
    # Return a random match from the list of local and remote services tuples
    ## Use all options on the first iteration, then adjust protocol if no match was found
    if len(local_l) == 0:
        j = remote_l[random.randrange(0, len(remote_l))]
        return (None, j)
    elif len(remote_l) == 0:
        i = local_l[random.randrange(0, len(local_l))]
        return (i, None)

    base = list(local_l)
    while True:
        i = base[random.randrange(0, len(base))]
        r_matches = [_ for _ in remote_l if _[2]==i[2]]
        # No match found in remote services for given protocol, readjust base and try again
        if len(r_matches) == 0:
            base = [_ for _ in base if _[2]!=i[2]]
            continue

        j = r_matches[random.randrange(0, len(r_matches))]
        return (i, j)

def _get_data_dict(d, tree, default=''):
    # Generic function to access result data
    try:
        _d = dict(d)
        for branch in tree:
            _d = _d[branch]
        return _d
    except KeyError:
        return default

def add_result(name, success, metadata, ts_start, ts_end):
    # Add a result dictionary entry
    global RESULTS
    RESULTS.append({'name':name, 'success':success, 'metadata': metadata, 'ts_start': ts_start, 'ts_end': ts_end, 'duration': ts_end - ts_start})


class RealDNSDataTraffic(object):
    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (list) results list
        '''
        global TS_ZERO
        global TASK_NUMBER

        self.reuseaddr = False
        set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDNSDataTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            # Select parameters randomly
            _dns_laddr, _dns_raddr, = _get_service_tuple(self.dns_laddr, self.dns_raddr)
            _data_laddr, _data_raddr, = _get_service_tuple(self.data_laddr, self.data_raddr)
            # Use timeout template(s) and data_delay
            _dns_timeouts, _data_timeouts = self.dns_timeouts, self.data_timeouts
            _data_delay = random.uniform(self.data_delay[0], self.data_delay[1])
            # Schedule task
            args = (task_nth, _dns_laddr, _dns_raddr, _dns_timeouts, _data_laddr, _data_raddr, _data_timeouts, _data_delay)
            cb = functools.partial(asyncio.ensure_future, self.run(*args))
            loop.call_at(taskdelay, cb)
            args_str = 'DNS {}:{}/{} => {}:{}/{} timeouts={} // Data {}:{}/{} => {}:{}/{} timeouts={} delay={:.4f}'.format(_dns_laddr[0], _dns_laddr[1], _dns_laddr[2],
                                                                                                                           _dns_raddr[0], _dns_raddr[1], _dns_raddr[2],
                                                                                                                           _dns_timeouts,
                                                                                                                           _data_laddr[0], _data_laddr[1], _data_laddr[2],
                                                                                                                           _data_raddr[0], _data_raddr[1], _data_raddr[2],
                                                                                                                           _data_timeouts, _data_delay)
            self.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, self.type, taskdelay - TS_ZERO, args_str))

    @asyncio.coroutine
    def run(self, task_nth, dns_laddr, dns_raddr, dns_timeouts, data_laddr, data_raddr, data_timeouts, data_delay):
        global TS_ZERO
        self.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}

        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Select socket type based on protocol number
        dns_sockettype = 'tcp' if dns_rproto == 6 else 'udp'

        # Unpack Data related data
        data_fqdn,    data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'

        ## Run DNS resolution
        data_ripaddr, query_id, dns_attempts = yield from _gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                         timeouts=dns_timeouts, socktype=dns_sockettype,
                                                                         reuseaddr=self.reuseaddr)

        # Populate partial results
        ts_end = _now()
        metadata_d['dns_attempts'] = dns_attempts
        metadata_d['dns_duration'] = ts_end - ts_start
        metadata_d['dns_laddr'] = dns_laddr
        metadata_d['dns_raddr'] = dns_raddr
        metadata_d['dns_fqdn'] = data_fqdn

        # Evaluate DNS resolution
        if data_ripaddr is None:
            sucess = False
            metadata_d['dns_success'] = False
            metadata_d['duration'] = ts_end - ts_start
            add_result(self.type, sucess, metadata_d, ts_start, ts_end)
            return
        else:
            metadata_d['dns_success'] = True

        # Await for data_delay
        if data_delay > 0:
            self.logge.warning('RealDNSDataTraffic sleep({}) before sending data', data_delay)
            yield from asyncio.sleep(data_delay)

        ## Run data transfer
        ts_start_data = _now()
        data_b = '{}@{}'.format(data_fqdn, data_ripaddr)
        data_recv, data_attempts = yield from _sendrecv(data_b.encode(), (data_ripaddr, data_rport),
                                                       (data_lipaddr, data_lport),
                                                        timeouts=data_timeouts, socktype=data_sockettype,
                                                        reuseaddr=self.reuseaddr)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_attempts'] = data_attempts
        metadata_d['data_duration'] = ts_end - ts_start_data
        metadata_d['data_laddr'] = data_laddr
        metadata_d['data_raddr'] = (data_ripaddr, data_rport, data_rproto)
        metadata_d['duration'] = ts_end - ts_start

        # Evaluate data transfer
        if data_recv is None:
            sucess = False
            metadata_d['data_success'] = False
        else:
            sucess = True
            metadata_d['data_success'] = True

        add_result(self.type, sucess, metadata_d, ts_start, ts_end)


class RealDNSTraffic(object):
    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (list) results list
        '''
        global TS_ZERO
        global TASK_NUMBER

        self.reuseaddr = False
        set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDNSTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            # Select parameters randomly
            _dns_laddr, _dns_raddr, = _get_service_tuple(self.dns_laddr, self.dns_raddr)
            _data_laddr, _data_raddr, = _get_service_tuple([], self.data_raddr)
            # Use timeout template(s)
            _dns_timeouts = self.dns_timeouts
            # Schedule task
            args = (task_nth, _dns_laddr, _dns_raddr, _dns_timeouts, _data_laddr, _data_raddr)
            cb = functools.partial(asyncio.ensure_future, self.run(*args))
            loop.call_at(taskdelay, cb)
            args_str = 'DNS {}:{}/{} => {}:{}/{} timeouts={}'.format(_dns_laddr[0], _dns_laddr[1], _dns_laddr[2],
                                                                     _dns_raddr[0], _dns_raddr[1], _dns_raddr[2],
                                                                     _dns_timeouts)
            self.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, self.type, taskdelay - TS_ZERO, args_str))

    @asyncio.coroutine
    def run(self, task_nth, dns_laddr, dns_raddr, dns_timeouts, data_laddr, data_raddr):
        global TS_ZERO
        self.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}

        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Select socket type based on protocol number
        dns_sockettype = 'tcp' if dns_rproto == 6 else 'udp'

        # Unpack Data related data
        data_fqdn, data_rport, data_rproto = data_raddr

        ## Run DNS resolution
        data_ripaddr, query_id, dns_attempts = yield from _gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                         timeouts=dns_timeouts, socktype=dns_sockettype,
                                                                         reuseaddr=self.reuseaddr)

        # Populate partial results
        ts_end = _now()
        metadata_d['dns_attempts'] = dns_attempts
        metadata_d['dns_duration'] = ts_end - ts_start
        metadata_d['dns_laddr'] = dns_laddr
        metadata_d['dns_raddr'] = dns_raddr
        metadata_d['dns_fqdn'] = data_fqdn
        metadata_d['duration'] = ts_end - ts_start
        metadata_d['data_raddr'] = (data_ripaddr, data_rport, data_rproto)

        # Evaluate DNS resolution
        if data_ripaddr is None:
            sucess = False
            metadata_d['dns_success'] = False
        else:
            sucess = True
            metadata_d['dns_success'] = True

        add_result(self.type, sucess, metadata_d, ts_start, ts_end)


class RealDataTraffic(object):
    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (list) results list
        '''
        global TS_ZERO
        global TASK_NUMBER

        self.reuseaddr = False
        set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('RealDataTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            # Select parameters randomly
            _data_laddr, _data_raddr, = _get_service_tuple(self.data_laddr, self.data_raddr)
            # Use timeout template(s)
            _data_timeouts = self.data_timeouts
            # Schedule task
            args = (task_nth, _data_laddr, _data_raddr, _data_timeouts)
            cb = functools.partial(asyncio.ensure_future, self.run(*args))
            loop.call_at(taskdelay, cb)
            args_str = 'Data {}:{}/{} => {}:{}/{} timeouts={}'.format(_data_laddr[0], _data_laddr[1], _data_laddr[2],
                                                                      _data_raddr[0], _data_raddr[1], _data_raddr[2],
                                                                      _data_timeouts)
            self.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, self.type, taskdelay - TS_ZERO, args_str))

    @asyncio.coroutine
    def run(self, task_nth, data_laddr, data_raddr, data_timeouts):
        global TS_ZERO
        self.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}

        # Unpack Data related data
        data_ripaddr, data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'

        ## Run data transfer
        data_b = '{}@{}'.format(data_ripaddr, data_ripaddr)
        data_recv, data_attempts = yield from _sendrecv(data_b.encode(), (data_ripaddr, data_rport),
                                                       (data_lipaddr, data_lport),
                                                        timeouts=data_timeouts, socktype=data_sockettype,
                                                        reuseaddr = self.reuseaddr)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_attempts'] = data_attempts
        metadata_d['data_duration'] = ts_end - ts_start
        metadata_d['data_laddr'] = data_laddr
        metadata_d['data_raddr'] = data_raddr
        metadata_d['duration'] = ts_end - ts_start

        # Evaluate data transfer
        if data_recv is None:
            sucess = False
            metadata_d['data_success'] = False
        else:
            sucess = True
            metadata_d['data_success'] = True

        add_result(self.type, sucess, metadata_d, ts_start, ts_end)


class SpoofDNSTraffic(object):
    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (list) results list
        '''
        global TS_ZERO
        global TASK_NUMBER

        self.interface = None
        set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('SpoofDNSTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)
        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            # Select parameters randomly
            _dns_laddr, _dns_raddr, = _get_service_tuple(self.dns_laddr, self.dns_raddr)
            _data_laddr, _data_raddr, = _get_service_tuple([], self.data_raddr)
            # Pre-compute packet build to avoid lagging due to Scapy.
            ## Build query message
            _data_b = dns.message.make_query(_data_raddr[0], 1, 1).to_wire()
            _eth_pkt = _scapy_build_packet(_dns_laddr[0], _dns_raddr[0], _dns_raddr[2], _dns_laddr[1], _dns_raddr[1], _data_b)
            # Schedule task
            args = (task_nth, _dns_laddr, _dns_raddr, _data_laddr, _data_raddr, bytes(_eth_pkt))
            cb = functools.partial(asyncio.ensure_future, self.run(*args))
            loop.call_at(taskdelay, cb)
            args_str = 'SpoofDNS {}:{}/{} => {}:{}/{}'.format(_dns_laddr[0], _dns_laddr[1], _dns_laddr[2],
                                                              _dns_raddr[0], _dns_raddr[1], _dns_raddr[2])
            self.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, self.type, taskdelay - TS_ZERO, args_str))

    @asyncio.coroutine
    def run(self, task_nth, dns_raddr, dns_laddr, data_laddr, data_raddr, eth_pkt):
        global TS_ZERO
        self.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}

        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Unpack Data related data
        data_fqdn, data_rport, data_rproto = data_raddr
        # Send the packet
        success = _scapy_send_packet(eth_pkt, self.interface)
        # Populate partial results
        ts_end = _now()
        metadata_d['dns_laddr'] = dns_laddr
        metadata_d['dns_raddr'] = dns_raddr
        metadata_d['dns_fqdn'] = data_fqdn
        # Add results
        add_result(self.type, success, metadata_d, ts_start, ts_end)


class SpoofDataTraffic(object):
    def __init__(self, **kwargs):
        '''
        # Common parameters
        duration: (int) test duration in seconds
        ts_start: (float) absolute starting time to schedule events
        results: (list) results list
        '''
        global TS_ZERO
        global TASK_NUMBER

        self.interface = None
        set_attributes(self, override=True, **kwargs)
        self.logger = logging.getLogger('SpoofDataTraffic')

        # Adjust next taskdelay time
        taskdelay = self.ts_start
        iterations = int(self.load * self.duration)

        for i in range(0, iterations):
            # Set starting time for task
            taskdelay += random.expovariate(self.load)
            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            # Select parameters randomly
            _data_laddr, _data_raddr, = _get_service_tuple(self.data_laddr, self.data_raddr)
            # Pre-compute packet build to avoid lagging due to Scapy.
            _data_b = '{}@{}'.format(_data_raddr[0], _data_raddr[0]).encode()
            _eth_pkt = _scapy_build_packet(_data_laddr[0], _data_raddr[0], _data_raddr[2], _data_laddr[1], _data_raddr[1], _data_b)
            # Schedule task
            args = (task_nth, _data_laddr, _data_raddr, bytes(_eth_pkt))
            cb = functools.partial(asyncio.ensure_future, self.run(*args))
            loop.call_at(taskdelay, cb)
            args_str = 'SpoofData {}:{}/{} => {}:{}/{}'.format(_data_laddr[0], _data_laddr[1], _data_laddr[2],
                                                          _data_raddr[0], _data_raddr[1], _data_raddr[2])
            self.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, self.type, taskdelay - TS_ZERO, args_str))

    @asyncio.coroutine
    def run(self, task_nth, data_laddr, data_raddr, eth_pkt):
        global TS_ZERO
        self.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}

        # Unpack Data related data
        data_ripaddr, data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Send the packet
        success = _scapy_send_packet(eth_pkt, self.interface)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_laddr'] = data_laddr
        metadata_d['data_raddr'] = data_raddr
        # Add results
        add_result(self.type, success, metadata_d, ts_start, ts_end)



class MainTestClient(object):
    def __init__(self, args):
        self.logger = logging.getLogger('MainTestClient')
        self.args = args

        # Read configuration file
        with open(self.args.config, 'r') as infile:
            config_d = yaml.load(infile)

        # Schedule test intances
        self._spawn_traffic_tests(config_d)

    def _spawn_traffic_tests(self, config_d):
        # TODO: Use parameters defined in globals as base, then overwrite with test specific?

        global TS_ZERO
        duration = config_d['duration']
        ts_backoff = config_d['backoff']
        ts_start = _now() + ts_backoff

        self.logger.warning('({:.3f}) Starting task generation!'.format(_now(TS_ZERO)))
        self.logger.warning('({:.3f}) Scheduling first task @{}!'.format(_now(TS_ZERO), ts_backoff))

        # Define test test specific parameters
        type2config = {'dnsdata':   (RealDNSDataTraffic, ['dns_laddr', 'dns_raddr', 'data_laddr', 'data_raddr', 'dns_timeouts', 'data_timeouts', 'data_delay']),
                       'dns':       (RealDNSTraffic,     ['dns_laddr', 'dns_raddr', 'data_raddr', 'dns_timeouts']),
                       'data':      (RealDataTraffic,    ['data_laddr', 'data_raddr', 'data_timeouts']),
                       'dnsspoof':  (SpoofDNSTraffic,    ['dns_laddr', 'dns_raddr', 'data_raddr', 'interface']),
                       'dataspoof': (SpoofDataTraffic,   ['data_laddr', 'data_raddr', 'interface']),
                       }

        for item_d in config_d['traffic']:
            # Get class and config parameters
            cls, parameters = type2config[item_d['type']]

            # Add globals to parameter dictionary if test specific are not defined
            item_d.setdefault('duration', duration)
            ts_start_test = item_d.setdefault('ts_start', 0)
            item_d['ts_start'] = ts_start + ts_start_test

            for p in parameters:
                # Use global settings if test-specific are not enabled
                global_param_d = _get_data_dict(config_d, ['global_traffic',item_d['type'], p], [])
                item_d.setdefault(p, global_param_d)

            # Create object
            obj = cls(**item_d)

        self.logger.warning('({:.3f}) Terminated task generation!'.format(_now(TS_ZERO)))

    @asyncio.coroutine
    def monitor_pending_tasks(self, watchdog = WATCHDOG):
        # Monitor number of remaining tasks and exit when done
        i = 0
        global TS_ZERO
        while len(loop._scheduled):
            i += 1 # Counter of iterations
            self.logger.warning('({:.3f}) [{}] Pending tasks: {}'.format(_now(TS_ZERO), i, len(loop._scheduled)))
            yield from asyncio.sleep(watchdog)
        self.logger.warning('({:.3f}) [{}] All tasks completed!'.format(_now(TS_ZERO), i))
        return loop.time()

    def process_results(self):
        # Process results and show brief statistics
        self.logger.warning('Processing results')
        self._save_to_json()
        self._save_to_csv()
        self._save_to_csv_summarized()

    def _save_to_csv_summarized(self):
        # Save a CSV file
        global RESULTS

        # Classify indidivual results from RESULTS list into a dictionary indexed by type
        results_d = {}
        for result_d in RESULTS:
            data_l = results_d.setdefault(result_d['name'], [])
            data_l.append(result_d)

        # Create list of lines to save result statistics
        lines = []
        header_fmt = 'name,total,success,failure,dns_success,dns_failure,dns_1,dns_2,dns_3,dns_4,dns_5,data_success,data_failure'
        lines.append(header_fmt)

        for data_key, data_l in results_d.items():
            name = data_key
            total = len(data_l)
            success = len([1 for _ in data_l if _['success'] == True])
            failure = len([1 for _ in data_l if _['success'] == False])
            dns_success = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True])
            dns_failure = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],True) == False])
            data_success = len([1 for _ in data_l if _get_data_dict(_,['metadata','data_success'],False) == True])
            data_failure = len([1 for _ in data_l if _get_data_dict(_,['metadata','data_success'],True) == False])
            # Calculate DNS retransmission if DNS phase was successful
            dns_1 = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True and _get_data_dict(_,['metadata','dns_attempts'],0) == 1])
            dns_2 = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True and _get_data_dict(_,['metadata','dns_attempts'],0) == 2])
            dns_3 = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True and _get_data_dict(_,['metadata','dns_attempts'],0) == 3])
            dns_4 = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True and _get_data_dict(_,['metadata','dns_attempts'],0) == 4])
            dns_5 = len([1 for _ in data_l if _get_data_dict(_,['metadata','dns_success'],False) == True and _get_data_dict(_,['metadata','dns_attempts'],0) == 5])
            # Create comma separated line matching header_fmt
            line = '{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(name,total,success,failure,
                                                                   dns_success,dns_failure,
                                                                   dns_1,dns_2,dns_3,dns_4,dns_5,
                                                                   data_success,data_failure)
            lines.append(line)
            # Log via console
            self.logger.warning('{0: <10}\tsuccess={1}\tfailure={2}\tdns_success={3}\tdns_failure={4}\tdns_rtx={5}'.format(name, success, failure, dns_success, dns_failure, (dns_1,dns_2,dns_3,dns_4,dns_5)))

        # Save results to file in csv
        if self.args.results:
            filename = self.args.results + '.summary.csv'
            self.logger.warning('Writing results to file <{}>'.format(filename))
            with open(filename, 'w') as outfile:
                outfile.writelines('\n'.join(lines))

    def _save_to_csv(self):
        # Save a CSV file
        global RESULTS

        # Create list of lines to save result statistics
        lines = []
        header_fmt = 'name,success,ts_start,ts_end,duration,dns_success,dns_attempts,dns_duration,data_success,data_attempts,data_duration'
        lines.append(header_fmt)

        for result_d in RESULTS:
            name          = result_d['name']
            success       = result_d['success']
            ts_start      = result_d['ts_start']
            ts_end        = result_d['ts_end']
            duration      = result_d['duration']
            metadata_d    = result_d.setdefault('metadata', {})
            dns_success   = metadata_d.get('dns_success', '')
            dns_attempts  = metadata_d.get('dns_attempts', '')
            dns_duration  = metadata_d.get('dns_duration', '')
            data_success  = metadata_d.get('data_success', '')
            data_attempts = metadata_d.get('data_attempts', '')
            data_duration = metadata_d.get('data_duration', '')
            line = '{},{},{},{},{},{},{},{},{},{},{}'.format(name,success,ts_start,ts_end,duration,
                                                             dns_success,dns_attempts,dns_duration,
                                                             data_success,data_attempts,data_duration)
            lines.append(line)

        # Save results to file in csv
        if self.args.results:
            filename = self.args.results + '.csv'
            self.logger.warning('Writing results to file <{}>'.format(filename))
            with open(filename, 'w') as outfile:
                outfile.writelines('\n'.join(lines))

    def _save_to_json(self):
        # Save results to file in json
        global RESULTS
        if self.args.results:
            filename = self.args.results + '.json'
            self.logger.warning('Writing results to file <{}>'.format(filename))
            with open(filename, 'w') as outfile:
                json.dump(RESULTS, outfile)




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
    parser = argparse.ArgumentParser(description='Realm Gateway Traffic Test Suite v0.1')
    parser.add_argument('--config', type=str, required=True,
                        help='Input configuration file (yaml)')
    parser.add_argument('--results', type=str, required=False,
                        help='Output results file (json)')
    return parser.parse_args()

if __name__ == '__main__':
    # Use function to configure logging from file
    setup_logging_yaml()
    logger = logging.getLogger('')

    # Parse arguments
    args = parse_arguments()

    loop = asyncio.get_event_loop()
    #loop.set_debug(True)

    try:
        main = MainTestClient(args)
        loop.run_until_complete(main.monitor_pending_tasks())
    except KeyboardInterrupt:
        logger.warning('KeyboardInterrupt!')

    #logger.warning('All tasks completed!')
    loop.stop()
    main.process_results()
    sys.exit(0)



"""
File: example_traffic.yaml

# YAML configuration file for Realm Gateway Traffic Test Suite v0.1
## Modify and test via yaml.load(open('config_test.yaml', 'r'))

# Total duration of the test (sec)
duration: 1

# Backoff time before scheduling tests (sec)
backoff: 3

# Global definitions for traffic tests, used if no test specific parameter is defined
global_traffic:
    dnsdata:
        dns_laddr: [["0.0.0.0", 0, 6], ["0.0.0.0", 0, 17]]
        dns_raddr: [["8.8.8.8", 53, 17], ["8.8.8.8", 53, 6], ["8.8.4.4", 53, 17], ["8.8.4.4", 53, 6]]
        data_laddr: [["0.0.0.0", 0, 6], ["0.0.0.0", 0, 17]]
        data_raddr: [["example.com", 80, 6], ["google-public-dns-a.google.com", 53, 17]]
        dns_timeouts: [1,5,5,5]
        data_timeouts: [1]
        data_delay: [0.050, 0.250]
    dns:
        dns_laddr: [["0.0.0.0", 0, 6], ["0.0.0.0", 0, 17]]
        dns_raddr: [["8.8.8.8", 53, 17], ["8.8.8.8", 53, 6], ["8.8.4.4", 53, 17], ["8.8.4.4", 53, 6]]
        data_raddr: [["example.com", 0, 0], ["google-public-dns-a.google.com", 0, 0]]
        dns_timeouts: [1,5,5,5]
    data:
        data_laddr: [["0.0.0.0", 0, 6], ["0.0.0.0", 0, 17]]
        data_raddr: [["93.184.216.34", 80, 6], ["8.8.8.8", 53, 17]]
        data_timeouts: [1]
    dnsspoof:
        dns_laddr: [["1.1.1.1", 2000, 17], ["2.2.2.2", 2000, 17]]
        dns_raddr: [["8.8.8.8", 53, 17], ["8.8.4.4", 53, 17], ["195.148.125.201", 53, 17], ["100.64.1.130", 53, 17]]
        data_raddr: [["dnsspoof.example.com", 0, 0], ["dnsspoof.google.es", 0, 0]]
        interface: "wan0"
    dataspoof:
        data_laddr: [["1.1.1.1", 3000, 17], ["1.1.1.1", 0, 6]]
        data_raddr: [["8.8.8.8", 0, 17], ["8.8.8.8", 0, 6], ["195.148.125.201", 0, 17], ["195.148.125.201", 0, 6], ["100.64.1.130", 0, 17], ["100.64.1.130", 0, 6]]
        interface: "wan0"

# This models all the test traffic
traffic:
    # Example of tests with global_traffic parameters
    - {"type": "dnsdata",   "load": 2}
    - {"type": "dns",       "load": 2}
    - {"type": "data",      "load": 2}
    - {"type": "dataspoof", "load": 2, interface: "ens18"}
    - {"type": "dnsspoof",  "load": 2, interface: "ens18"}

    ## Example of tests with specific values
    ## dnsdata: Specific duration and starting time
    - {"type": "dnsdata",   "load": 2, "ts_start": 10, "duration": 10}
    ## dnsdata: TCP based data & TCP based resolution
    #- {"type": "dnsdata",  "load": 1, dns_laddr:[["0.0.0.0", 0, 6]], dns_raddr:[["8.8.8.8", 53, 6]], data_laddr: [["0.0.0.0", 0, 6]],  data_raddr: [["google.es", 2000, 6]]}
    ## dnsdata: UDP based data & UDP based resolution
    #- {"type": "dnsdata",  "load": 1, dns_laddr:[["0.0.0.0", 0, 17]], dns_raddr:[["8.8.8.8", 53, 17]], data_laddr: [["0.0.0.0", 0, 17]], data_raddr: [["udp2001.host.demo", 2001, 17]]}
    #
    ## dns: UDP based resolution
    #- {"type": "dns",      "load": 1, dns_laddr:[["0.0.0.0", 0, 17]], dns_raddr:[["8.8.8.8", 53, 17]], data_raddr: [["udp2002.host.demo", 2002, 17]]}
    #
    ## data: TCP & UDP based data
    #- {"type": "data",     "load": 1,                                                                      data_laddr: [["0.0.0.0", 0, 6]],  data_raddr: [["195.148.125.202", 3000, 6]]}
    #- {"type": "data",     "load": 1,                                                                      data_laddr: [["0.0.0.0", 0, 17]], data_raddr: [["195.148.125.202", 3001, 17]]}
    #
    ## dnsspoof: UDP based resolution only
    #- {"type": "dnsspoof", "load": 1, dns_laddr:[["198.18.0.1", 0, 17]], dns_raddr:[["195.148.125.201", 53, 17]], data_raddr: [["udp5002.host.demo", 5002, 17]]}
    #
    ## dataspoof: UDP based data
    #- {"type": "dataspoof", "load": 1,                                                                     data_laddr: [["1.1.1.1", 65535, 6]],  data_raddr: [["9.9.9.9", 65535, 6]]}
    #- {"type": "dataspoof", "load": 1,                                                                     data_laddr: [["2.2.2.2", 65535, 17]], data_raddr: [["9.9.9.9", 65535, 17]]}

"""
