import asyncio
import logging
from customdns.dnsutils import *

import struct
from socket import IPPROTO_TCP, TCP_NODELAY


class DNSProxy(asyncio.DatagramProtocol):
    def __init__(self, soa_list = [], cb_soa = None, cb_nosoa = None):
        self._logger = logging.getLogger('DNSProxy')
        self.soa_list = soa_list
        self.cb_soa   = cb_soa   if cb_soa   is not None else lambda x,y,z: self.callback_send(x,y,None)
        self.cb_nosoa = cb_nosoa if cb_nosoa is not None else lambda x,y,z: self.callback_send(x,y,None)

    def connection_made(self, transport):
        self._transport = transport

    def error_received(self, exc):
        addr = self._transport.get_extra_info('sockname')
        self._logger.warning('Error received @{0}:{1} {2}'.format(addr[0], addr[1], exc))

    def datagram_received(self, data, addr):
        try:
            self._logger.debug('Data received from {}"'.format(debug_data_addr(data, addr)))
            query = dns.message.from_wire(data)
            query.transport = 'udp'
            fqdn = format(query.question[0].name)
            cb_f = self.callback_send
            if self._name_in_soa(fqdn) and self.cb_soa:
                self.cb_soa(query, addr, cb_f)
            elif self.cb_nosoa:
                self.cb_nosoa(query, addr, cb_f)
        except Exception as e:
            self._logger.error('Failed to process DNS message: {}\n{}'.format(e, data))

    def callback_send(self, query, addr, response=None):
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
        else:
            self._send_msg(response, addr)

    def _name_in_soa(self, name):
        """ Return True if the name belongs to any registered SOA """
        for soa in self.soa_list:
            if name.endswith(soa):
                return True
        return False

    def _send_msg(self, dnsmsg, addr):
        self._transport.sendto(dnsmsg.to_wire(), addr)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)


class DNSTCPProxy(asyncio.Protocol):
    # start -> connection_made() [-> data_received() *] [-> eof_received() ?] -> connection_lost() -> end
    def __init__(self, soa_list = [], cb_soa = None, cb_nosoa = None):
        self._logger = logging.getLogger('DNSTCPProxy')
        self.soa_list = soa_list
        self.cb_soa = cb_soa
        self.cb_nosoa = cb_nosoa

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

    def connection_lost(self, exc):
        self._logger.debug('Connection lost @{0}:{1} {2}'.format(self.raddr[0], self.raddr[1], exc))
        self._transport = None

    def data_received(self, data):
        try:
            addr = self.raddr
            self._logger.debug('Data received from {}"'.format(debug_data_addr(data, addr)))
            query = dns.message.from_wire(data[2:])
            query.transport = 'tcp'
            fqdn = format(query.question[0].name)
            cb_f = self.callback_send
            if self._name_in_soa(fqdn) and self.cb_soa:
                self.cb_soa(query, addr, cb_f)
            elif self.cb_nosoa:
                self.cb_nosoa(query, addr, cb_f)
        except Exception as e:
            self._logger.error('Failed to process DNS message: {}\n{}'.format(e, data))

    def callback_send(self, query, addr, response=None):
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
        else:
            self._send_msg(response, addr)

    def _name_in_soa(self, name):
        """ Return True if the name belongs to any registered SOA """
        for soa in self.soa_list:
            if name.endswith(soa):
                return True
        return False

    def _send_msg(self, dnsmsg, addr):
        dnsmsg_b = dnsmsg.to_wire()
        self._transport.write(struct.pack('!H', len(dnsmsg_b)) + dnsmsg_b)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)