#!/usr/bin/env python3

'''
NOTE: If run into the problem of too many files open, add to the file /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535

Run as:   ./async_echoclient_v4.py --duration 3 --load 300 --distribution const --dnstimeout 1 1 1 --datatimeout 1 --fqdn localhost.demo:12345 --dnsaddr 127.0.0.1 --dnsport 54
Requires: ./async_echoserver_v3.py -b 127.0.0.1:12345

Run as: ./async_echoclient_v4.py --duration 3 --load 300 --distribution const --dnstimeout 1 1 1 --datatimeout 1 --dnsaddr 127.0.0.1 --dnsport 54 --fqdn localhost.demo:2000 --sfqdn udp2000.localhost.demo:2000 udp2001.localhost.demo:2001 udp2002.localhost.demo:2002 udp2003.localhost.demo:2003 udp2004.localhost.demo:2004 udp2005.localhost.demo:2005 udp2006.localhost.demo:2006 udp2007.localhost.demo:2007 udp2008.localhost.demo:2008 udp2009.localhost.demo:2009 --trafficshape 0
Requires: ./async_echoserver_v3.py -b 127.0.0.1:2000 127.0.0.1:2001 127.0.0.1:2002 127.0.0.1:2003 127.0.0.1:2004 127.0.0.1:2005 127.0.0.1:2006 127.0.0.1:2007 127.0.0.1:2008 127.0.0.1:2009
'''

import asyncio
import argparse
import json
import logging
import random
import socket
import statistics
import sys
import time

import math
import struct


import dns
import dns.message
import dns.name
import dns.edns
import dns.zone
import dns.rcode
import dns.rdatatype
import dns.inet

from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

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


ECS = 8
class MyECSOption(dns.edns.Option):
# Currently copied from official Github repo until included in the next release
    """EDNS Client Subnet (ECS, RFC7871)"""

    def __init__(self, address, srclen=None, scopelen=0):
        """*address*, a ``text``, is the client address information.
        *srclen*, an ``int``, the source prefix length, which is the
        leftmost number of bits of the address to be used for the
        lookup.  The default is 24 for IPv4 and 56 for IPv6.
        *scopelen*, an ``int``, the scope prefix length.  This value
        must be 0 in queries, and should be set in responses.
        """

        super(MyECSOption, self).__init__(ECS)
        af = dns.inet.af_for_address(address)

        if af == dns.inet.AF_INET6:
            self.family = 2
            if srclen is None:
                srclen = 56
        elif af == dns.inet.AF_INET:
            self.family = 1
            if srclen is None:
                srclen = 24
        else:
            raise ValueError('Bad ip family')

        self.address = address
        self.srclen = srclen
        self.scopelen = scopelen

        addrdata = dns.inet.inet_pton(af, address)
        nbytes = int(math.ceil(srclen/8.0))

        # Truncate to srclen and pad to the end of the last octet needed
        # See RFC section 6
        self.addrdata = addrdata[:nbytes]
        nbits = srclen % 8
        if nbits != 0:
            last = struct.pack('B', ord(self.addrdata[-1:]) & (0xff << nbits))
            self.addrdata = self.addrdata[:-1] + last

    def to_text(self):
        return "ECS %s/%s scope/%s" % (self.address, self.srclen,
                                       self.scopelen)

    def to_wire(self, file):
        file.write(struct.pack('!H', self.family))
        file.write(struct.pack('!BB', self.srclen, self.scopelen))
        file.write(self.addrdata)

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        family, src, scope = struct.unpack('!HBB', wire[cur:cur+4])
        cur += 4

        addrlen = int(math.ceil(src/8.0))

        if family == 1:
            af = dns.inet.AF_INET
            pad = 4 - addrlen
        elif family == 2:
            af = dns.inet.AF_INET6
            pad = 16 - addrlen
        else:
            raise ValueError('unsupported family')

        addr = dns.inet.inet_ntop(af, wire[cur:cur+addrlen] + b'\x00' * pad)
        return cls(addr, src, scope)

    def _cmp(self, other):
        if self.addrdata == other.addrdata:
            return 0
        if self.addrdata > other.addrdata:
            return 1
        return -1

class uDNSResolverCustom():
    '''
    # Instantiated as follows
    resolver = uDNSResolver()
    response = yield from resolver.do_resolve(query, raddr, timeouts=[1, 1, 1])
    '''

    @asyncio.coroutine
    def do_resolve(self, query, addr, timeouts=[0]):
        self._logger = logging.getLogger('uDNSResolverCustom #{}'.format(id(self)))
        self._logger.debug('Resolving to {} with timeouts {}'.format(addr, timeouts))
        loop = asyncio.get_event_loop()
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        yield from loop.sock_connect(self.sock, addr)
        fqdn = query.question[0].name
        queryid = query.id
        ipaddr = None
        attempt = 0
        response = None
        for tout in timeouts:
            attempt += 1
            try:
                yield from loop.sock_sendall(self.sock, query.to_wire())
                dataresponse = yield from asyncio.wait_for(loop.sock_recv(self.sock, 1024), timeout=tout)
                self.sock.close()
                ipaddr = dns.message.from_wire(dataresponse).answer[0][0].address
                break
            except asyncio.TimeoutError:
                self._logger.info('#{} timeout expired: {:.4f} sec ({})'.format(attempt, tout, fqdn))
                continue
            except ConnectionRefusedError:
                self._logger.warning('ConnectionRefusedError: Resolving {} via {}:{}'.format(fqdn, addr[0], addr[1]))
                break
            except Exception as e:
                self._logger.warning('Exception {}: Resolving {} via {}:{}'.format(e, fqdn, addr[0], addr[1]))
                break

        return (ipaddr, queryid, attempt)

class uDataEchoCustom():
    '''
    # Instantiated as follows
    echo = uDataEchoCustom()
    response = yield from echo.do_echo(data, raddr, timeouts=[1, 1, 1])
    '''

    @asyncio.coroutine
    def do_echo(self, data, addr, timeouts=[0]):
        self._logger = logging.getLogger('uDataEchoCustom #{}'.format(id(self)))
        self._logger.debug('Echoing to {} with timeouts {}'.format(addr, timeouts))
        loop = asyncio.get_event_loop()
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(False)
        yield from loop.sock_connect(self.sock, addr)
        recvdata = None
        attempt = 0
        for tout in timeouts:
            attempt += 1
            try:
                yield from loop.sock_sendall(self.sock, query.to_wire())
                recvdata = yield from asyncio.wait_for(loop.sock_recv(self.sock, 1024), timeout=tout)
                self.sock.close()
                break
            except asyncio.TimeoutError:
                self._logger.info('#{} timeout expired: {:.4f} sec ({})'.format(attempt, tout, data))
                continue
            except ConnectionRefusedError:
                self._logger.warning('ConnectionRefusedError: Echoing {} via {}:{}'.format(data, addr[0], addr[1]))
                break
            except Exception as e:
                self._logger.warning('Exception {}: Echoing {} via {}:{}'.format(e, data, addr[0], addr[1]))
                break

        return (recvdata, dataattempt)



class UdpTestClient():
    def __init__(self, **kwargs):
        self.cb           = kwargs.setdefault('cb', lambda x,y: (x,y))
        self.tzero        = kwargs.setdefault('tzero', _now())
        self.index        = kwargs.setdefault('index', 1)
        self.fqdn         = kwargs.setdefault('fqdn', 'foo.bar.')
        self.ipaddr       = kwargs.setdefault('ipaddr', '127.0.0.1')
        self.port         = kwargs.setdefault('port', 13245)
        self.dnsaddr      = kwargs.setdefault('dnsaddr', '8.8.8.8')
        self.dnsport      = kwargs.setdefault('dnsport', 53)
        self.dnstimeouts  = kwargs.setdefault('dnstimeouts', [1])
        self.datatimeouts = kwargs.setdefault('datatimeouts', [1])
        self.datadelay    = kwargs.setdefault('datadelay', 0.0)
        self.edns0        = kwargs.setdefault('edns0', [])
        self.opmode       = kwargs.setdefault('opmode', 'full')

        self._logger = logging.getLogger('UdpTestClient{:06d}'.format(self.index))
        self._loop = asyncio.get_event_loop()

        # Set running function based on opmode
        self._run = self._run_full
        if self.opmode == 'dnsonly':
            self._run = self._run_dnsonly
        elif self.opmode == 'dataonly':
            self._run = self._run_dataonly

        if self.opmode != 'dataonly':
            self.create_dns_query()

    def run(self):
        self._tzero = _now()
        asyncio.async(self._run())

    @asyncio.coroutine
    def get_local_ipaddr(self, remote_ip):
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        yield from self._loop.sock_connect(s , (remote_ip, 65000))
        ipaddr = s.getsockname()[0]
        s.close()
        return ipaddr

    @asyncio.coroutine
    def _run_full(self):
        # Untested
        yield from self._run_dnsonly()
        yield from self._run_dataonly()

    def create_dns_query(self):
        self.query = dns.message.make_query(self.fqdn, 1)
        if self.edns0:
            options = self.create_edns0_options(self.edns0)
            self.query.use_edns(edns=True, ednsflags=0, options=options)

    def create_edns0_options(self, rawoptions):
        options = []
        for opt in rawoptions:
            opt_code, opt_data = opt.split(':')
            # Do specific parsing per EDNS0 extension
            if int(opt_code) == 8:
                ipaddr, mask = opt_data.split(',')
                ecs = MyECSOption(ipaddr, int(mask))
                options.append(ecs)
            else:
                self._logger.warning('Unsupported EDNS0 {}/{}'.format(opt_code, opt_data))
        return options

    @asyncio.coroutine
    def _run_dnsonly(self):
        self._logger.debug('#{} {} @ {}'.format(self.index, self.fqdn, '???'))
        coro = uDNSResolverCustom().do_resolve(self.query, (self.dnsaddr, self.dnsport), self.dnstimeouts)
        (t, (self.ipaddr, queryid, dnsattempt)) = yield from _timeit(coro, 1000)
        # Evaluate DNS resolution
        if self.ipaddr is None:
            self._logger.info('#{} {} {} @ {} / DNS KO ({} {:.3f}ms)'.format(self.index, queryid, self.fqdn, '!#%!#%', dnsattempt, t))
            self._add_result(dnsok = False, dnsattempt = dnsattempt, dnstime = t)
            return

        self._logger.info('#{} {} {} @ {} / DNS OK ({} {:.3f}ms)'.format(self.index, queryid, self.fqdn, self.ipaddr, dnsattempt, t))
        self._add_result(ok=True, dnsok = True, dnsattempt = dnsattempt, dnstime = t)

    @asyncio.coroutine
    def _run_dataonly(self):
        # Validate destination IP address
        if self.ipaddr is None:
            return

        self._logger.debug('#{} @{}:{}'.format(self.index, self.ipaddr, self.port))
        # Create DATA connection coroutine and yield from it
        msg = '{} {}:{}\n'.format(self.index, self.ipaddr, self.ipaddr, self.port)
        coro = uDataEchoCustom().do_echo(msg.encode(), (self.ipaddr, self.port), self.datatimeouts)
        (t, (recvdata, dataattempt)) = yield from _timeit(coro, 1000)
        # Set fqdn for result logging
        self.fqdn = 'N/A'
        if recvdata is None:
            self._logger.info('#{} @{}:{} / DATA KO {} {:.3f}ms)'.format(self.index, self.ipaddr, self.port, dataattempt, t))
            self._add_result(dataok = False, dataattempt = dataattempt, datatime = t)
            return
        self._logger.info('#{} @{}:{} / DATA OK {} {:.3f}ms)'.format(self.index, self.ipaddr, self.port, dataattempt, t))
        self._add_result(ok = True, dataok = True, dataattempt = dataattempt, datatime = t)

    def _add_result(self, ok = False, dnsok = False, dataok = False, dnsattempt = 0, dataattempt = 0, dnstime = 0, datatime = 0):
        tend = _now()
        value = {'index':self.index,
                 'domain':self.fqdn,
                 'ipaddr':self.ipaddr,
                 'result':ok,
                 'dns':{'result':dnsok,
                        'attempt':dnsattempt},
                 'data':{'result':dataok,
                         'attempt':dataattempt},
                 'time':{'start_real':self._tzero, #corouting started
                         'start_sche':self.tzero,  #corouting scheduled
                         'end':tend,
                         'dns':dnstime,
                         'data':datatime}
                 }
        # Use callback function to add results
        self.cb(self.index, value)


class EchoClientMain(object):
    def __init__(self, args):
        self.args = args
        self.setup_logging(args)
        self.setup_result_log(self.logfile+'.results')
        # Create domain list
        self.domains = self.build_domain_list(args.fqdn, args.sfqdn, args.trafficshape, args.shuffle, args.shufflefqdn, args.shufflesfqdn, args.dataport)


    def setup_logging(self, args):
        # Set loglevel
        loglevel = args.loglevel
        # Enable verbose mode
        if args.verbose or loglevel == logging.DEBUG:
            loglevel = logging.DEBUG
            asyncio.get_event_loop().set_debug(True)

        # Set logfile
        self.logfile = args.logfile
        if not self.logfile:
            lt = time.localtime()
            ctime = "%02d%02d%02d" % (lt.tm_mday,lt.tm_mon,lt.tm_year)
            self.logfile = '{}_{}_{}sec_{}cs'.format(ctime,args.distribution,args.duration,args.load)

        self._logger = logging.getLogger('EchoClient')
        self._logger.setLevel(loglevel)
        format = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(format)
        self._logger.addHandler(ch)
        #fh = logging.handlers.RotatingFileHandler(self.logfile+'.log', maxBytes=(1048576*5), backupCount=7)
        fh = logging.FileHandler(self.logfile+'.log', mode='w')
        fh.setFormatter(format)
        self._logger.addHandler(fh)
        self._logger.critical('Logging to files {}'.format(self.logfile))

    def setup_result_log(self, filename):
        # Open file for storing the results
        self._fd_results = open(filename, 'w')

    def close_result_log(self, filename):
        # Close results file
        self._fd_results.close()

    def read_result_log(self, filename):
        l = []
        with open(filename, 'r') as infile:
            [l.append(json.loads(line)) for line in infile.readlines()]
        return l

    def build_domain_list(self, fqdn, sfqdn, shape, shuffle, shufflefqdn, shufflesfqdn, dataport):
        fqdn_n = shape
        sfqdn_n = 100 - shape
        self._logger.info('FQDN {}% / SFQDN {}%'.format(fqdn_n, sfqdn_n))

        # Mangle domain list
        fqdn_list = []
        for x in fqdn:
            # Initialize to domain X and port 0
            d, p = x, dataport
            if ':' in x:
                d, p = tuple(x.split(':'))
            fqdn_list.append((d,p))
        # Mangle domain list
        sfqdn_list = []
        for x in sfqdn:
            # Initialize to domain X and port 0
            d, p = x, dataport
            if ':' in x:
                d, p = tuple(x.split(':'))
            sfqdn_list.append((d,p))

        # Create empty list to store the domains
        domains = []
        # Process FQDN traffic
        for n in range(fqdn_n):
            i = n % len(fqdn_list)
            if shufflefqdn:
                i = random.randrange(0, len(fqdn_list))
            domains.append(fqdn_list[i])
        # Process SFQDN traffic
        for n in range(sfqdn_n):
            i = n % len(sfqdn_list)
            if shufflesfqdn:
                i = random.randrange(0, len(sfqdn_list))
            domains.append(sfqdn_list[i])
        # Shuffle all traffic
        if shuffle:
            random.shuffle(domains)
        return domains


    @asyncio.coroutine
    def run(self):
        (self.t_gen, self.first_task_at, self.last_task_at) = yield from self.prepare_tasks(self.args)
        self._logger.warning('Generation took {:.3f} sec'.format(self.t_gen))
        self.last_task_ended_at = yield from self.monitor_pending_tasks()


    @asyncio.coroutine
    def prepare_tasks(self, args):
        loop = asyncio.get_event_loop()
        maxiter = int(args.load * args.duration)
        self._logger.warning('Generating {} connection attemps'.format(maxiter))
        # Delay task start by 5 seconds to allow scheduling preparation
        t0 = loop.time()
        taskdelay = t0 + args.startdelay
        global FIRST_START_AT
        FIRST_START_AT = taskdelay
        first_task_at = taskdelay
        for n in range(0, maxiter):
            domain, port = self.domains[n%len(self.domains)]
            index = n+1
            # Set values for operation mode
            if args.opmode == 'full':
                ipaddr = 'N/A'
                fqdn = domain
            elif args.opmode == 'dnsonly':
                ipaddr = 'N/A'
                fqdn = domain
            elif args.opmode == 'dataonly':
                ipaddr = domain
                fqdn = 'N/A'
            # Set values for operation mode
            if args.dnsmode == 'win':
                dnstimeout = [1, 1, 2, 4, 1]      #At: 0,1,2,4,8 (all same query)
            elif args.dnsmode == 'linux':
                dnstimeout = [5, 5, 5, 1]         #At: 0,5,10,15 (10 & 15 -> new query)
            elif args.dnsmode == 'mac':
                dnstimeout = [1, 3, 9, 1]         #At: 0,1,4,13  (all same query)
            elif args.dnsmode == 'manual':
                dnstimeout = args.dnstimeout      #User defined

            # Schedule the task at taskdelay time
            self._logger.info('Running task at {:.3f} sec / {}:{}'.format(taskdelay-(t0+args.startdelay), domain, port))

            # Fix **kwargs in here
            kwargs = dict(args.__dict__)
            del kwargs['fqdn']
            test_client = UdpTestClient(cb = self.callback_testclient, tzero = taskdelay, index = index, fqdn = fqdn, ipaddr = ipaddr, port = port, **kwargs)
            loop.call_at(taskdelay, test_client.run)
            # Adjust next taskdelay time
            if args.distribution == 'exp':
                taskdelay += random.expovariate(args.load)
            else:
                taskdelay += 1/args.load

        t_gen = loop.time()-t0
        last_task_at = taskdelay
        return (t_gen, first_task_at, last_task_at)

    @asyncio.coroutine
    def monitor_pending_tasks(self, watchdog = WATCHDOG):
        # Monitor number of remaining tasks and exit when done
        i = 0
        t0 = loop.time()
        while len(loop._scheduled):
            i += 1 # Counter of iterations
            self._logger.warning('({:.3f}) [{}] Pending tasks: {}'.format(loop.time()-t0, i, len(loop._scheduled)))
            yield from asyncio.sleep(watchdog)
        return loop.time()

    def callback_testclient(self, k, v):
        self._fd_results.write(json.dumps(v) + '\n')

    '''
    def filter_results(self, trim):
        todelete = []
        print('FIRST_START_AT ', FIRST_START_AT)
        print('LAST_START_AT ', LAST_START_AT)

        if trim == 0:
            # Do not trim any values
            return

        # Count results only during high-load period
        for value in RESULTS:
            if value['time']['start_real'] < (FIRST_START_AT+trim) or value['time']['end'] > (LAST_START_AT-trim):
                todelete.append(value)
        print('Removing {} elements from calculations'.format(len(todelete)))
        for value in todelete:
            #print('Removing {}'.format(value))
            RESULTS.remove(value)
    '''

    def process_results(self):
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Data test client with python3 and asyncio')
    parser.add_argument('--duration', type=float, required=True,
                        help='test duration')
    parser.add_argument('--distribution', type=str, default='exp',
                        help='Interarrival times follows the given distribution',
                        choices=['exp', 'const'])
    parser.add_argument('--load', type=float, required=True,
                        help='number of new connection per second')
    parser.add_argument('--dnstimeout', nargs='+', type=float, default=[1, 1],
                        help='timeout of the DNS resolution (sec)')
    parser.add_argument('--datatimeout', nargs='+', type=float, default=[0.250, 0.500],
                        help='timeout of the data transmission (sec)')
    parser.add_argument('--fqdn', nargs='*', default=[],
                        help='FQDN of the destination in format (FQDN:port)')
    parser.add_argument('--sfqdn', nargs='*', default=[],
                        help='SFQDN of the destination in format (SFQDN:port)')
    parser.add_argument('--trafficshape', type=int, default=100,
                        help='FQDN resolutions per 100 connections')
    parser.add_argument('--shuffle', action="store_true",
                        help='shuffle all destination domains')
    parser.add_argument('--shufflefqdn', action="store_true",
                        help='shuffle FQDN destination domains')
    parser.add_argument('--shufflesfqdn', action="store_true",
                        help='shuffle SFQDN destination domains')
    parser.add_argument('--dnsaddr', type=str, default='198.18.0.1',
                        help='IP address of the DNS server')
    parser.add_argument('--dnsport', type=int, default=53,
                        help='UDP port of the DNS server')
    parser.add_argument('--dnsmode', type=str, default='win',
                        help='DNS resolution mode: [win, linux, mac, manual]',
                        choices=['win', 'linux', 'mac', 'manual'])
    parser.add_argument('--edns0', nargs='*', default=[],
                        help='Use DNS extension: code:data1;data2;data3')
    parser.add_argument('--opmode', type=str, default='full',
                        help='Client operation mode: [full, dnsonly, dataonly]',
                        choices=['full', 'dnsonly', 'dataonly'])
    parser.add_argument('--datadelay', type=float, default=0.0,
                        help='delay data connection after DNS resolution')
    parser.add_argument('--dataport', type=int, default=50000,
                        help='default data port')
    parser.add_argument('--startdelay', type=float, default=3.0,
                        help='delay start of tests')
    parser.add_argument('--trim', type=float, default=0.0,
                        help='trim value in seconds for calculating high-load period only')
    parser.add_argument('--logfile', type=str,
                        help='logfile')
    parser.add_argument('--loglevel', type=int, default=logging.INFO,
                        help='loglevel [10, 20, 30, 40]')
    parser.add_argument('--verbose', action="store_true",
                        help='enable verbose mode')

    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    echo_client = EchoClientMain(args)
    logger = logging.getLogger('')
    loop.run_until_complete(echo_client.run())
    logger.warning('All tasks completed!')
    loop.stop()
    logger.warning('Processing results...')
    echo_client.process_results()
    sys.exit(0)
