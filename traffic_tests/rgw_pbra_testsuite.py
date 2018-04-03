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
import base64
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

# Global message counter
MSG_SENT = 0
MSG_RECV = 0

WATCHDOG = 1.0 #Sleep 1 second before displaying loop stats
RESULTS = []   #List to store TestResult objects

loop = asyncio.get_event_loop()
TS_ZERO = loop.time()
TASK_NUMBER = 0

DETERMINISTIC_ALLOCATION = True

LAST_UDP_PORT = 30000
LAST_TCP_PORT = 30000
LAST_QUERY_ID = 30000
UDP_PORT_RANGE = (20000, 65535)
TCP_PORT_RANGE = (20000, 65535)
QUERY_ID_RANGE = (20000, 65535)

def get_deterministic_port(proto):
    if proto in ['tcp', 6, socket.SOCK_STREAM]:
        global LAST_TCP_PORT
        LAST_TCP_PORT += 1
        # Further logic to port allocation
        if LAST_TCP_PORT > TCP_PORT_RANGE[1]:
            LAST_TCP_PORT = TCP_PORT_RANGE[0]
        port = LAST_TCP_PORT
    elif proto in ['udp', 17, socket.SOCK_DGRAM]:
        global LAST_UDP_PORT
        LAST_UDP_PORT += 1
        # Further logic to port allocation
        if LAST_UDP_PORT > UDP_PORT_RANGE[1]:
            LAST_UDP_PORT = UDP_PORT_RANGE[0]
        port = LAST_UDP_PORT
    return port

def get_deterministic_queryid():
    global LAST_QUERY_ID
    LAST_QUERY_ID += 1
    # Further logic to port allocation
    if LAST_QUERY_ID > QUERY_ID_RANGE[1]:
        LAST_QUERY_ID = QUERY_ID_RANGE[0]
    queryid = LAST_QUERY_ID
    return queryid

if DETERMINISTIC_ALLOCATION is False:
    get_deterministic_port = lambda x: random.randrange(1025, 65536)
    get_deterministic_queryid = lambda : random.randrange(1025, 65536)


def set_attributes(obj, override=False, **kwargs):
    """Set attributes in object from a dictionary"""
    for k,v in kwargs.items():
        if hasattr(obj, k) and not override:
            continue
        setattr(obj, k, v)

def _now(ref = 0):
    """ Return current time based on event loop """
    return loop.time() - ref

async def _timeit(coro, scale = 1):
    """ Execute a coroutine and return the time consumed in second scale """
    t0 = _now()
    r = await coro
    return (_now(t0)*scale, r)

async def _socket_connect(raddr, laddr, family, type, reuseaddr=True, timeout=0):
    # Set socket family
    if family in ['ipv4', 0x0800]:
        socketfamily = socket.AF_INET
    elif family in ['ipv6', 0x86dd]:
        socketfamily = socket.AF_INET6
    # Set socket type
    if type in ['tcp', 6]:
        sockettype = socket.SOCK_STREAM
    elif type in ['udp', 17]:
        sockettype = socket.SOCK_DGRAM

    # Create socket object
    sock = socket.socket(socketfamily, sockettype)
    # Sanitize connect timeout value
    timeout = 0 if timeout is None else int(timeout)
    # Enable address reuse
    if reuseaddr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not laddr:
        laddr = ('0.0.0.0', 0)

    if sockettype == socket.SOCK_STREAM:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Check local port selection and use deterministic approach if not selected
    _local_addr, _local_port = laddr[0], laddr[1]
    if _local_port == 0:
        _local_port = get_deterministic_port(type)

    # Try to bind a port up to 2 times. Get a new deterministic port if the first choice fails.
    for i in range(2):
        try:
            sock.bind((_local_addr, _local_port))
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, raddr), timeout=timeout, loop=loop)
            return sock
        except OSError as e:
            logger = logging.getLogger('_socket_connect')
            logger.error('{} @ {}:{} [{}] - reattempt'.format(e, _local_addr, _local_port, type))
            _local_port = get_deterministic_port(type)
            continue
        except Exception as e:
            logger = logging.getLogger('_socket_connect')
            logger.error('{} @ {}:{} [{}]'.format(e, _local_addr, _local_port, type))
            return None
    return None


from asyncio import Queue
class AsyncSocketQueue(object):
    """
    This class attempts to solve the bug found with loop.sock_recv() used via asyncio.wait_for()
    It uses a simple internal asyncio.Queue() to store the received messages of a *connected socket*
    """
    def __init__(self, sock, loop, queuesize=0, msgsize=1024):
        self._sock = sock
        self._loop = loop
        self._queue = Queue(maxsize=queuesize, loop=loop)
        # Register reader in loop
        self._sock.setblocking(False)
        self._loop.add_reader(self._sock.fileno(), AsyncSocketQueue._recv_callback, self._sock, self._queue, msgsize)

    def _recv_callback(sock, queue, msgsize):
        # Socket is read-ready
        try:
            data = sock.recv(msgsize)
        except ConnectionRefusedError:
            data = None
        finally:
            queue.put_nowait(data)

    async def recv(self):
        data = await self._queue.get()
        self._queue.task_done()
        return data

    async def sendall(self, data):
        await self._loop.sock_sendall(self._sock, data)

    def close(self):
        # Deregister reader in loop
        self._loop.remove_reader(self._sock.fileno())
        self._sock.close()
        del self._sock
        del self._queue


async def _sendrecv(data, raddr, laddr, timeouts=[0], socktype='udp', reuseaddr=True):
    """
    data: Data to send
    raddr: Remote tuple information
    laddr: Source tuple information
    timeouts: List with retransmission timeout scheme
    socktype: L4 protocol ['udp', 'tcp']

    There seem to be issues with iterating over asyncio.wait_for(loop.sock_recv())
    """
    global MSG_SENT
    global MSG_RECV

    logger = logging.getLogger('sendrecv')

    # Connect socket or fail early
    sock = await _socket_connect(raddr, laddr, family='ipv4', type=socktype, reuseaddr=reuseaddr, timeout=2)
    if sock is None:
        logger.warning('Socket failed to connect: {}:{} > {}:{} ({})'.format(laddr[0], laddr[1], raddr[0], raddr[1], socktype))
        return (None, 0)

    _laddr = sock.getsockname()
    logger.debug('Socket succeeded to connect: {}:{} > {}:{} ({})'.format(_laddr[0], _laddr[1], raddr[0], raddr[1], socktype))

    # Create async socket wrapper object
    asock = AsyncSocketQueue(sock, loop)

    for i, tout in enumerate(timeouts):
        try:
            await asock.sendall(data)
            MSG_SENT += 1
            recvdata = await asyncio.wait_for(asock.recv(), timeout=tout)
            MSG_RECV += 1
            logger.debug('[#{}] Received response: {}:{} > {}:{} ({}) / {}'.format(i+1, _laddr[0], _laddr[1], raddr[0], raddr[1], socktype, recvdata))
            break
        except asyncio.TimeoutError:
            logger.debug('#{} timeout expired ({:.4f} sec): {}:{} > {}:{} ({})'.format(i+1, tout, _laddr[0], _laddr[1], raddr[0], raddr[1], socktype))
            recvdata = None
            continue
        except Exception as e:
            logger.exception('Exception <{}>: {}:{} > {}:{} ({}) / {}'.format(e, _laddr[0], _laddr[1], raddr[0], raddr[1], socktype, data))
            recvdata = None
            break

    attempt = i+1
    asock.close()
    return (recvdata, attempt)


async def _gethostbyname(fqdn, raddr, laddr, timeouts=[0], socktype='udp', reuseaddr=True):
    """
    fqdn: Domain name to be resolved
    raddr: Remote tuple information
    raddr: Local tuple information
    timeouts: List with retransmission timeout scheme
    """
    global TS_ZERO
    logger = logging.getLogger('gethostbyname')
    logger.debug('Resolving {} via {}:{} > {}:{} ({}) with timeouts {}'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype, timeouts))
    rdtype = dns.rdatatype.A
    rdclass = dns.rdataclass.IN
    ipaddr = None
    attempt = 0
    response = None

    # Build query message
    query = dns.message.make_query(fqdn, rdtype, rdclass)
    query.id = get_deterministic_queryid()

    if socktype == 'udp':
        data = query.to_wire()
        # Send query and await for response with retransmission template
        data_recv, data_attempts = await _sendrecv(data, raddr, laddr, timeouts, socktype, reuseaddr)
        # Resolution did not succeed
        if data_recv is None:
            logger.debug('Resolution failed: {} via {}:{} > {}:{} ({})'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype))
            return (None, query.id, data_attempts)
        response = dns.message.from_wire(data_recv)
        assert(response.id == query.id)
        # Check if response is truncated and retry in TCP with a recursive call
        if (response.flags & dns.flags.TC == dns.flags.TC):
            logger.debug('Truncated response, reattempt via TCP: {} via {}:{} > {}:{} ({})'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype))
            return await _gethostbyname(fqdn, raddr, laddr, timeouts, socktype='tcp', reuseaddr=reuseaddr)

    elif socktype == 'tcp':
        _data = query.to_wire()
        data = struct.pack('!H', len(_data)) + _data
        # Send query and await for response with retransmission template
        data_recv, data_attempts = await _sendrecv(data, raddr, laddr, timeouts, socktype, reuseaddr)
        # Resolution did not succeed
        if data_recv is None:
            logger.debug('Resolution failed: {} via {}:{} > {}:{} ({})'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype))
            return (None, query.id, data_attempts)
        _len = struct.unpack('!H', data_recv[:2])[0]
        response = dns.message.from_wire(data_recv[2:2+_len])
        assert(response.id == query.id)

    # Parsing result
    ## With new PBRA DNS design, we might receive a CNAME instead of an A record, so we have to follow up with a new query to the given domain
    ## First try to obtain the A record and return if successful
    for rrset in response.answer:
        for rdata in rrset:
            if rdata.rdtype == dns.rdatatype.A:
                ipaddr = rdata.address
                logger.debug('Resolution succeeded: {} via {}:{} > {}:{} ({}) yielded {}'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype, ipaddr))
                return (ipaddr, query.id, data_attempts)

    ## Alternatively, try to follow-up through the CNAME record and with a recursive call
    for rrset in response.answer:
        for rdata in rrset:
            if rdata.rdtype == dns.rdatatype.CNAME:
                target = rdata.to_text()
                logger.debug('Resolution continues: {} via {}:{} > {}:{} ({}) yielded {}'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype, target))
                return await _gethostbyname(target, raddr, laddr, timeouts, socktype='udp', reuseaddr=reuseaddr)

    # Resolution did not succeed
    logger.debug('Resolution failed: {} via {}:{} > {}:{} ({})'.format(fqdn, laddr[0], laddr[1], raddr[0], raddr[1], socktype))
    return (None, query.id, data_attempts)


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

    return Ether()/IP(src=src, dst=dst)/layer_4

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


class _TestTraffic(object):
    ''' Define base class and implement these methods for traffic tests '''
    @staticmethod
    def schedule_tasks(**kwargs):
        pass

    async def run(**kwargs):
        pass


class RealDNSDataTraffic(_TestTraffic):
    ''' Use static classes just to access the specific method for the tests '''
    logger = logging.getLogger('RealDNSDataTraffic')

    @staticmethod
    def schedule_tasks(**kwargs):
        ''' Return a list of schedule tasks in dictionary format for later spawning '''
        global TS_ZERO
        global TASK_NUMBER


        # Use a list to store scheduled tasks parameters
        scheduled_tasks = []
        # Set default variables that might not be defined in configuration / Allow easy test of specific features
        reuseaddr = kwargs.setdefault('reuseaddr', True)
        # Adjust next taskdelay time
        taskdelay = kwargs['ts_start']
        iterations = int(kwargs['load'] * kwargs['duration'])
        distribution = kwargs.setdefault('distribution', 'exp')
        for i in range(0, iterations):
            # Set starting time for task
            if distribution == 'exp':
                taskdelay += random.expovariate(kwargs['load'])
            elif distribution == 'uni':
                taskdelay += 1 / kwargs['load']

            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            task_type = kwargs['type']
            # Select parameters randomly
            dns_laddr, dns_raddr   = _get_service_tuple(kwargs['dns_laddr'],  kwargs['dns_raddr'])
            data_laddr, data_raddr = _get_service_tuple(kwargs['data_laddr'], kwargs['data_raddr'])
            # Use timeout template(s) and data_delay
            dns_timeouts, data_timeouts = kwargs['dns_timeouts'], kwargs['data_timeouts']
            data_delay = random.uniform(*kwargs['data_delay'])
            # Log task parameters
            task_str = 'DNS {}:{}/{} => {}:{}/{} timeouts={} // Data {}:{}/{} => {}:{}/{} timeouts={} delay={:.4f}'.format(dns_laddr[0], dns_laddr[1], dns_laddr[2],
                                                                                                                           dns_raddr[0], dns_raddr[1], dns_raddr[2],
                                                                                                                           dns_timeouts,
                                                                                                                           data_laddr[0], data_laddr[1], data_laddr[2],
                                                                                                                           data_raddr[0], data_raddr[1], data_raddr[2],
                                                                                                                           data_timeouts, data_delay)
            RealDNSDataTraffic.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, task_type, taskdelay - TS_ZERO, task_str))
            # Build dictionary with selected parameters for running the task
            args_d = {'task_nth': task_nth, 'task_type': task_type, 'reuseaddr': reuseaddr,
                      'dns_laddr': dns_laddr, 'dns_raddr': dns_raddr, 'dns_timeouts': dns_timeouts,
                      'data_laddr': data_laddr, 'data_raddr': data_raddr, 'data_timeouts': data_timeouts, 'data_delay': data_delay,
                      }
            # Append the newly defined task with its parameters
            scheduled_tasks.append({'offset': taskdelay - TS_ZERO, 'cls': task_type, 'kwargs': args_d})

        # Return list of scheduled tasks for later spawning
        return scheduled_tasks


    async def run(**kwargs):
        global TS_ZERO
        # Get parameters
        task_nth        = kwargs['task_nth']
        task_type       = kwargs['task_type']
        dns_laddr       = kwargs['dns_laddr']
        dns_raddr       = kwargs['dns_raddr']
        dns_timeouts    = kwargs['dns_timeouts']
        data_laddr      = kwargs['data_laddr']
        data_raddr      = kwargs['data_raddr']
        data_timeouts   = kwargs['data_timeouts']
        data_delay      = kwargs['data_delay']
        reuseaddr       = kwargs['reuseaddr']

        RealDNSDataTraffic.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
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
        data_ripaddr, query_id, dns_attempts = await _gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                         timeouts=dns_timeouts, socktype=dns_sockettype,
                                                                         reuseaddr=reuseaddr)

        # Populate partial results
        ts_end = _now()
        metadata_d['dns_attempts'] = dns_attempts
        metadata_d['dns_duration'] = ts_end - ts_start
        metadata_d['dns_start']    = ts_start
        metadata_d['dns_end']      = ts_end
        metadata_d['dns_laddr'] = dns_laddr
        metadata_d['dns_raddr'] = dns_raddr
        metadata_d['dns_fqdn'] = data_fqdn

        # Evaluate DNS resolution
        if data_ripaddr is None:
            sucess = False
            metadata_d['dns_success'] = False
            metadata_d['duration'] = ts_end - ts_start
            add_result(task_type, sucess, metadata_d, ts_start, ts_end)
            return
        else:
            metadata_d['dns_success'] = True

        # Await for data_delay
        if data_delay > 0:
            RealDNSDataTraffic.logger.debug('RealDNSDataTraffic sleep {:.4f} sec before sending data'.format(data_delay))
            await asyncio.sleep(data_delay)

        ## Run data transfer
        ts_start_data = _now()
        data_b = '{}@{}'.format(data_fqdn, data_ripaddr)
        data_recv, data_attempts = await _sendrecv(data_b.encode(), (data_ripaddr, data_rport),
                                                       (data_lipaddr, data_lport),
                                                        timeouts=data_timeouts, socktype=data_sockettype,
                                                        reuseaddr=reuseaddr)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_attempts'] = data_attempts
        metadata_d['data_duration'] = ts_end - ts_start_data
        metadata_d['data_start']    = ts_start_data
        metadata_d['data_end']      = ts_end
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

        add_result(task_type, sucess, metadata_d, ts_start, ts_end)


class RealDNSTraffic(_TestTraffic):
    ''' Use static classes just to access the specific method for the tests '''
    logger = logging.getLogger('RealDNSTraffic')

    @staticmethod
    def schedule_tasks(**kwargs):
        ''' Return a list of schedule tasks in dictionary format for later spawning '''
        global TS_ZERO
        global TASK_NUMBER

        # Use a list to store scheduled tasks parameters
        scheduled_tasks = []
        # Set default variables that might not be defined in configuration / Allow easy test of specific features
        reuseaddr = kwargs.setdefault('reuseaddr', True)
        # Adjust next taskdelay time
        taskdelay = kwargs['ts_start']
        iterations = int(kwargs['load'] * kwargs['duration'])
        distribution = kwargs.setdefault('distribution', 'exp')
        for i in range(0, iterations):
            # Set starting time for task
            if distribution == 'exp':
                taskdelay += random.expovariate(kwargs['load'])
            elif distribution == 'uni':
                taskdelay += 1 / kwargs['load']

            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            task_type = kwargs['type']
            # Select parameters randomly
            dns_laddr, dns_raddr   = _get_service_tuple(kwargs['dns_laddr'],  kwargs['dns_raddr'])
            data_laddr, data_raddr = _get_service_tuple(kwargs['data_laddr'], kwargs['data_raddr'])
            # Use timeout template(s)
            dns_timeouts = kwargs['dns_timeouts']
            # Log task parameters
            task_str = 'DNS {}:{}/{} => {}:{}/{} timeouts={} // Data {}:{}/{}'.format(dns_laddr[0], dns_laddr[1], dns_laddr[2],
                                                                                      dns_raddr[0], dns_raddr[1], dns_raddr[2],
                                                                                      dns_timeouts,
                                                                                      data_raddr[0], data_raddr[1], data_raddr[2])
            RealDNSTraffic.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, task_type, taskdelay - TS_ZERO, task_str))
            # Build dictionary with selected parameters for running the task
            args_d = {'task_nth': task_nth, 'task_type': task_type, 'reuseaddr': reuseaddr,
                      'dns_laddr': dns_laddr, 'dns_raddr': dns_raddr, 'dns_timeouts': dns_timeouts,
                      'data_laddr': data_laddr, 'data_raddr': data_raddr,
                      }
            # Append the newly defined task with its parameters
            scheduled_tasks.append({'offset': taskdelay - TS_ZERO, 'cls': task_type, 'kwargs': args_d})

        # Return list of scheduled tasks for later spawning
        return scheduled_tasks

    async def run(**kwargs):
        global TS_ZERO
        # Get parameters
        task_nth        = kwargs['task_nth']
        task_type       = kwargs['task_type']
        dns_laddr       = kwargs['dns_laddr']
        dns_raddr       = kwargs['dns_raddr']
        dns_timeouts    = kwargs['dns_timeouts']
        data_laddr      = kwargs['data_laddr']
        data_raddr      = kwargs['data_raddr']
        reuseaddr       = kwargs['reuseaddr']

        RealDNSTraffic.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
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
        data_ripaddr, query_id, dns_attempts = await _gethostbyname(data_fqdn, (dns_ripaddr, dns_rport), (dns_lipaddr, dns_lport),
                                                                         timeouts=dns_timeouts, socktype=dns_sockettype,
                                                                         reuseaddr=reuseaddr)

        # Populate partial results
        ts_end = _now()
        metadata_d['dns_attempts'] = dns_attempts
        metadata_d['dns_duration'] = ts_end - ts_start
        metadata_d['dns_start']    = ts_start
        metadata_d['dns_end']      = ts_end
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

        add_result(task_type, sucess, metadata_d, ts_start, ts_end)


class RealDataTraffic(_TestTraffic):
    ''' Use static classes just to access the specific method for the tests '''
    logger = logging.getLogger('RealDataTraffic')

    @staticmethod
    def schedule_tasks(**kwargs):
        ''' Return a list of schedule tasks in dictionary format for later spawning '''
        global TS_ZERO
        global TASK_NUMBER

        # Use a list to store scheduled tasks parameters
        scheduled_tasks = []
        # Set default variables that might not be defined in configuration / Allow easy test of specific features
        reuseaddr = kwargs.setdefault('reuseaddr', True)
        # Adjust next taskdelay time
        taskdelay = kwargs['ts_start']
        iterations = int(kwargs['load'] * kwargs['duration'])
        distribution = kwargs.setdefault('distribution', 'exp')
        for i in range(0, iterations):
            # Set starting time for task
            if distribution == 'exp':
                taskdelay += random.expovariate(kwargs['load'])
            elif distribution == 'uni':
                taskdelay += 1 / kwargs['load']

            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            task_type = kwargs['type']
            # Select parameters randomly
            data_laddr, data_raddr = _get_service_tuple(kwargs['data_laddr'],  kwargs['data_raddr'])
            # Use timeout template(s)
            data_timeouts = kwargs['data_timeouts']
            # Log task parameters
            task_str = 'Data {}:{}/{} => {}:{}/{} timeouts={}'.format(data_laddr[0], data_laddr[1], data_laddr[2],
                                                                      data_raddr[0], data_raddr[1], data_raddr[2],
                                                                      data_timeouts)
            RealDataTraffic.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, task_type, taskdelay - TS_ZERO, task_str))
            # Build dictionary with selected parameters for running the task
            args_d = {'task_nth': task_nth, 'task_type': task_type, 'reuseaddr': reuseaddr,
                      'data_laddr': data_laddr, 'data_raddr': data_raddr, 'data_timeouts': data_timeouts,
                      }
            # Append the newly defined task with its parameters
            scheduled_tasks.append({'offset': taskdelay - TS_ZERO, 'cls': task_type, 'kwargs': args_d})

        # Return list of scheduled tasks for later spawning
        return scheduled_tasks

    async def run(**kwargs):
        global TS_ZERO
        # Get parameters
        task_nth        = kwargs['task_nth']
        task_type       = kwargs['task_type']
        data_laddr      = kwargs['data_laddr']
        data_raddr      = kwargs['data_raddr']
        data_timeouts   = kwargs['data_timeouts']
        reuseaddr       = kwargs['reuseaddr']

        RealDataTraffic.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}
        # Unpack Data related data
        data_ripaddr, data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Select socket type based on protocol number
        data_sockettype = 'tcp' if data_rproto == 6 else 'udp'

        ## Run data transfer
        data_b = '{}@{}'.format(data_ripaddr, data_ripaddr)
        data_recv, data_attempts = await _sendrecv(data_b.encode(), (data_ripaddr, data_rport),
                                                       (data_lipaddr, data_lport),
                                                        timeouts=data_timeouts, socktype=data_sockettype,
                                                        reuseaddr = reuseaddr)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_attempts'] = data_attempts
        metadata_d['data_duration'] = ts_end - ts_start
        metadata_d['data_start']    = ts_start
        metadata_d['data_end']      = ts_end
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

        add_result(task_type, sucess, metadata_d, ts_start, ts_end)


class SpoofDNSTraffic(_TestTraffic):
    ''' Use static classes just to access the specific method for the tests '''
    logger = logging.getLogger('SpoofDNSTraffic')

    @staticmethod
    def schedule_tasks(**kwargs):
        ''' Return a list of schedule tasks in dictionary format for later spawning '''
        global TS_ZERO
        global TASK_NUMBER

        # Use a list to store scheduled tasks parameters
        scheduled_tasks = []
        # Adjust next taskdelay time
        taskdelay = kwargs['ts_start']
        iterations = int(kwargs['load'] * kwargs['duration'])
        distribution = kwargs.setdefault('distribution', 'exp')
        for i in range(0, iterations):
            # Set starting time for task
            if distribution == 'exp':
                taskdelay += random.expovariate(kwargs['load'])
            elif distribution == 'uni':
                taskdelay += 1 / kwargs['load']

            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            task_type = kwargs['type']
            # Select parameters randomly
            dns_laddr, dns_raddr   = _get_service_tuple(kwargs['dns_laddr'],  kwargs['dns_raddr'])
            data_laddr, data_raddr = _get_service_tuple(kwargs['data_laddr'], kwargs['data_raddr'])
            # Pre-compute packet build to avoid lagging due to Scapy.
            ## Build query message
            interface = kwargs.get('interface', None)
            query = dns.message.make_query(data_raddr[0], 1, 1)
            query.id = get_deterministic_queryid()
            data_b = query.to_wire()
            eth_pkt = _scapy_build_packet(dns_laddr[0], dns_raddr[0], dns_raddr[2], dns_laddr[1], dns_raddr[1], data_b)
            ## Encode/decode to base64 for obtaning str representation / serializable
            eth_pkt_str = base64.b64encode(bytes(eth_pkt)).decode('utf-8')
            # Log task parameters
            task_str = 'SpoofDNS {}:{}/{} => {}:{}/{} // Data {}:{}/{} // via {}'.format(dns_laddr[0], dns_laddr[1], dns_laddr[2],
                                                                                         dns_raddr[0], dns_raddr[1], dns_raddr[2],
                                                                                         data_raddr[0], data_raddr[1], data_raddr[2],
                                                                                         interface)
            SpoofDNSTraffic.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, task_type, taskdelay - TS_ZERO, task_str))
            # Build dictionary with selected parameters for running the task
            args_d = {'task_nth': task_nth, 'task_type': task_type,
                      'dns_laddr': dns_laddr, 'dns_raddr': dns_raddr,
                      'data_laddr': data_laddr, 'data_raddr': data_raddr,
                      'eth_pkt': eth_pkt_str, 'interface': interface,
                      }
            # Append the newly defined task with its parameters
            scheduled_tasks.append({'offset': taskdelay - TS_ZERO, 'cls': task_type, 'kwargs': args_d})

        # Return list of scheduled tasks for later spawning
        return scheduled_tasks

    async def run(**kwargs):
        global TS_ZERO
        # Get parameters
        task_nth        = kwargs['task_nth']
        task_type       = kwargs['task_type']
        dns_laddr       = kwargs['dns_laddr']
        dns_raddr       = kwargs['dns_raddr']
        data_laddr      = kwargs['data_laddr']
        data_raddr      = kwargs['data_raddr']
        eth_pkt         = kwargs['eth_pkt']
        interface       = kwargs['interface']

        SpoofDNSTraffic.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}
        # Unpack DNS related data
        dns_ripaddr, dns_rport, dns_rproto = dns_raddr
        dns_lipaddr, dns_lport, dns_lproto = dns_laddr
        # Unpack Data related data
        data_fqdn, data_rport, data_rproto = data_raddr
        # Send the packet
        ## decode from base64 to obtain bytes representation
        success = _scapy_send_packet(base64.b64decode(eth_pkt), interface)
        # Populate partial results
        ts_end = _now()
        metadata_d['dns_duration'] = ts_end - ts_start
        metadata_d['dns_start']    = ts_start
        metadata_d['dns_end']      = ts_end
        metadata_d['dns_laddr'] = dns_laddr
        metadata_d['dns_raddr'] = dns_raddr
        metadata_d['dns_fqdn'] = data_fqdn
        # Add results
        add_result(task_type, success, metadata_d, ts_start, ts_end)


class SpoofDataTraffic(_TestTraffic):
    ''' Use static classes just to access the specific method for the tests '''
    logger = logging.getLogger('SpoofDataTraffic')

    @staticmethod
    def schedule_tasks(**kwargs):
        ''' Return a list of schedule tasks in dictionary format for later spawning '''
        global TS_ZERO
        global TASK_NUMBER

        # Use a list to store scheduled tasks parameters
        scheduled_tasks = []
        # Adjust next taskdelay time
        taskdelay = kwargs['ts_start']
        iterations = int(kwargs['load'] * kwargs['duration'])
        distribution = kwargs.setdefault('distribution', 'exp')
        for i in range(0, iterations):
            # Set starting time for task
            if distribution == 'exp':
                taskdelay += random.expovariate(kwargs['load'])
            elif distribution == 'uni':
                taskdelay += 1 / kwargs['load']

            TASK_NUMBER += 1
            task_nth = TASK_NUMBER
            task_type = kwargs['type']
            # Select parameters randomly
            data_laddr, data_raddr = _get_service_tuple(kwargs['data_laddr'], kwargs['data_raddr'])
            # Pre-compute packet build to avoid lagging due to Scapy
            interface = kwargs.get('interface', None)
            data_b = '{}@{}'.format(data_raddr[0], data_raddr[0]).encode()
            eth_pkt = _scapy_build_packet(data_laddr[0], data_raddr[0], data_raddr[2], data_laddr[1], data_raddr[1], data_b)
            ## Encode/decode to base64 for obtaning str representation / serializable
            eth_pkt_str = base64.b64encode(bytes(eth_pkt)).decode('utf-8')
            # Log task parameters
            task_str = 'SpoofData {}:{}/{} => {}:{}/{} // via {}'.format(data_laddr[0], data_laddr[1], data_laddr[2],
                                                                         data_raddr[0], data_raddr[1], data_raddr[2],
                                                                         interface)
            SpoofDataTraffic.logger.info('[#{}] Scheduled task {} @ {:.4f} / {}'.format(task_nth, task_type, taskdelay - TS_ZERO, task_str))
            # Build dictionary with selected parameters for running the task
            args_d = {'task_nth': task_nth, 'task_type': task_type,
                      'data_laddr': data_laddr, 'data_raddr': data_raddr,
                      'eth_pkt': eth_pkt_str, 'interface': interface,
                      }
            # Append the newly defined task with its parameters
            scheduled_tasks.append({'offset': taskdelay - TS_ZERO, 'cls': task_type, 'kwargs': args_d})

        # Return list of scheduled tasks for later spawning
        return scheduled_tasks

    async def run(**kwargs):
        global TS_ZERO
        # Get parameters
        task_nth        = kwargs['task_nth']
        task_type       = kwargs['task_type']
        data_laddr      = kwargs['data_laddr']
        data_raddr      = kwargs['data_raddr']
        eth_pkt         = kwargs['eth_pkt']
        interface       = kwargs['interface']

        SpoofDataTraffic.logger.info('[{:.4f}] Running task #{}'.format(_now(TS_ZERO), task_nth))
        ts_start = _now()
        metadata_d = {}
        # Unpack Data related data
        data_ripaddr, data_rport, data_rproto = data_raddr
        data_lipaddr, data_lport, data_lproto = data_laddr
        # Send the packet
        ## decode from base64 to obtain bytes representation
        success = _scapy_send_packet(base64.b64decode(eth_pkt), interface)
        # Populate partial results
        ts_end = _now()
        metadata_d['data_duration'] = ts_end - ts_start
        metadata_d['data_start']    = ts_start
        metadata_d['data_end']      = ts_end
        metadata_d['data_laddr'] = data_laddr
        metadata_d['data_raddr'] = data_raddr
        # Add results
        add_result(task_type, success, metadata_d, ts_start, ts_end)



class MainTestClient(object):
    def __init__(self, args):
        self.logger = logging.getLogger('MainTestClient')
        self.args = args

        # Create list to store the schedule tasks
        self.scheduled_tasks = []

        if self.args.config:
            # Read YAML configuration file
            with open(self.args.config, 'r') as infile:
                config_d = yaml.load(infile)
            # Populate self.scheduled_tasks with scheduled test instances
            self._create_schedule_session(config_d)
            # Dump tasks to json
            self._dump_session_to_json(self.scheduled_tasks)

        elif self.args.session:
            # Read JSON session schedule
            with open(self.args.session, 'r') as infile:
                self.scheduled_tasks = json.load(infile)

        # Continue with ready session
        # Spawn test session
        self._spawn_test_session(self.scheduled_tasks)


    def _create_schedule_session(self, config_d):
        ''' Take config_d configuration as read from YAML. Populates self.scheduled_tasks list in the compatible format for later spawn. '''
        global TS_ZERO
        duration = config_d['duration']
        ts_backoff = config_d['backoff']
        ts_start = _now() + ts_backoff

        self.logger.warning('({:.3f}) Starting task generation!'.format(_now(TS_ZERO)))
        self.logger.warning('({:.3f}) Scheduling first task @{}!'.format(_now(TS_ZERO), ts_backoff))

        # Define test test specific parameters
        type2config = {'dnsdata':   (RealDNSDataTraffic, ['dns_laddr', 'dns_raddr', 'data_laddr', 'data_raddr', 'dns_timeouts', 'data_timeouts', 'data_delay']),
                       'dns':       (RealDNSTraffic,     ['dns_laddr', 'dns_raddr', 'data_laddr', 'data_raddr', 'dns_timeouts']),
                       'data':      (RealDataTraffic,    ['data_laddr', 'data_raddr', 'data_timeouts']),
                       'dnsspoof':  (SpoofDNSTraffic,    ['dns_laddr', 'dns_raddr', 'data_laddr', 'data_raddr', 'interface']),
                       'dataspoof': (SpoofDataTraffic,   ['data_laddr', 'data_raddr', 'interface']),
                       }

        for item_d in config_d['traffic']:
            # Get class and config parameters
            cls, parameters = type2config[item_d['type']]

            # Add globals to parameter dictionary if test specific are not defined
            item_d.setdefault('duration', duration)
            ts_start_test = item_d.setdefault('ts_start', 0)
            item_d['ts_start'] = ts_start + ts_start_test

            # Use global settings if test-specific are not defined
            # TODO: Do this automatically! Iterate globals and setdefault the parameters
            for p in parameters:
                global_param_d = _get_data_dict(config_d, ['global_traffic',item_d['type'], p], [])
                item_d.setdefault(p, global_param_d)

            # Append scheduled tasks to local list
            self.scheduled_tasks += cls.schedule_tasks(**item_d)

        self.logger.warning('({:.3f}) Terminated generation of {} tasks'.format(_now(TS_ZERO), len(self.scheduled_tasks)))

    def _spawn_test_session(self, session_d):
        # TODO: Use parameters defined in globals as base, then overwrite with test specific?
        global TS_ZERO
        ts_start = _now()

        # Define test test specific parameters
        type2cls = {'dnsdata':   RealDNSDataTraffic,
                    'dns':       RealDNSTraffic,
                    'data':      RealDataTraffic,
                    'dnsspoof':  SpoofDNSTraffic,
                    'dataspoof': SpoofDataTraffic,
                    }

        for entry in session_d:
            # Obtain parameters from entry
            offset = entry['offset']
            cls    = type2cls[entry['cls']]
            kwargs = entry['kwargs']
            taskdelay = TS_ZERO + offset
            cb = functools.partial(asyncio.ensure_future, cls.run(**kwargs))
            loop.call_at(taskdelay, cb)

    async def monitor_pending_tasks(self, watchdog = WATCHDOG):
        # Monitor number of remaining tasks and exit when done
        i = 0
        global TS_ZERO
        while len(loop._scheduled):
            i += 1 # Counter of iterations
            self.logger.warning('({:.3f}) [{}] Pending tasks: {}'.format(_now(TS_ZERO), i, len(loop._scheduled)))
            await asyncio.sleep(watchdog)
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
        header_fmt = 'name,success,ts_start,ts_end,duration,dns_success,dns_attempts,dns_start,dns_end,dns_duration,data_success,data_attempts,data_start,data_end,data_duration,debug'
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
            dns_start     = metadata_d.get('dns_start', '')
            dns_end       = metadata_d.get('dns_end', '')
            dns_duration  = metadata_d.get('dns_duration', '')
            data_success  = metadata_d.get('data_success', '')
            data_attempts = metadata_d.get('data_attempts', '')
            data_start    = metadata_d.get('data_start', '')
            data_end      = metadata_d.get('data_end', '')
            data_duration = metadata_d.get('data_duration', '')
            debug         = 'dns_laddr={}'.format(metadata_d.get('dns_laddr', ''))
            line = '{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}'.format(
                     name,success,ts_start,ts_end,duration,
                     dns_success,dns_attempts,dns_start,dns_end,dns_duration,
                     data_success,data_attempts,data_start,data_end,data_duration,
                     debug)
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

    def _dump_session_to_json(self, tasks):
        # Save scheduled session tasks to file in json
        filename = self.args.config + '.session.json'
        self.logger.warning('Writing session tasks to file <{}>'.format(filename))
        with open(filename, 'w') as outfile:
            json.dump(tasks, outfile)


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
        #logging.basicConfig(level=level)
        logging.basicConfig(level=level, format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Realm Gateway Traffic Test Suite v0.1')
    parser.add_argument('--config', type=str, default=None, required=False,
                        help='Input configuration file (yaml)')
    parser.add_argument('--session', type=str, default=None, required=False,
                        help='Input session file (json)')
    parser.add_argument('--results', type=str, required=False,
                        help='Output results file (json)')
    args = parser.parse_args()
    # Validate args
    assert (args.config or args.session)
    return args


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

    print('MSG_SENT      {}'.format(MSG_SENT))
    print('MSG_RECV      {}'.format(MSG_RECV))
    print('LAST_UDP_PORT {}'.format(LAST_UDP_PORT))
    print('LAST_TCP_PORT {}'.format(LAST_TCP_PORT))
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
    - {"type": "dns",       "load": 2, distribution: "exp"}
    - {"type": "data",      "load": 2, distribution: "uni"}
    - {"type": "dataspoof", "load": 2, interface: "ens18"}
    - {"type": "dnsspoof",  "load": 2, interface: "ens18"}

    ## Example of tests with specific values
    ## dnsdata: Specific duration and starting time
    #- {"type": "dnsdata",   "load": 2, "ts_start": 10, "duration": 10}
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
