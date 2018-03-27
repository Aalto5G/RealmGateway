#!/usr/bin/env python3

import asyncio
import argparse
import socket
import sys

MONITOR_INTERVAL = 2
TCP_CON_COUNTER = 0
UDP_CON_COUNTER = 0
TCP_MSG_COUNTER = 0
UDP_MSG_COUNTER = 0

class UdpEchoServer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.laddr = transport.get_extra_info('sockname')
        global UDP_CON_COUNTER
        UDP_CON_COUNTER += 1

    def datagram_received(self, data, addr):
        print('[UDP] Received {} from <{}:{}>'.format(data, addr[0], addr[1]))
        self.transport.sendto(data, addr)
        global UDP_MSG_COUNTER
        UDP_MSG_COUNTER += 1


class TcpEchoServer(asyncio.Protocol):
    # start -> connection_made() [-> data_received() *] [-> eof_received() ?] -> connection_lost() -> end
    def connection_made(self, transport):
        global TCP_CON_COUNTER
        TCP_CON_COUNTER += 1
        self._transport = transport
        # Get local and remote addresses from transport
        self.laddr = transport.get_extra_info('sockname')
        self.raddr = transport.get_extra_info('peername')
        # Set TCP_NODELAY
        sock = transport.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def data_received(self, data):
        global TCP_MSG_COUNTER
        TCP_MSG_COUNTER += 1
        addr = self.raddr
        print('[TCP] Received {} from <{}:{}>'.format(data, addr[0], addr[1]))
        self._transport.write(data)


@asyncio.coroutine
def monitor(period = MONITOR_INTERVAL):
    while True:
        print('TCP messages / connections: {} / {}'.format(TCP_MSG_COUNTER, TCP_CON_COUNTER), file=sys.stderr, flush=True)
        print('UDP messages / connections: {} / {}'.format(UDP_MSG_COUNTER, UDP_CON_COUNTER), file=sys.stderr, flush=True)
        yield from asyncio.sleep(period)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Data test server with python3 and asyncio')
    parser.add_argument('--udp', nargs='+', default=[], required=False, help='Server UDP address (ipaddr:port)')
    parser.add_argument('--tcp', nargs='+', default=[], required=False, help='Server TCP address (ipaddr:port)')
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    transports = []
    for addr in args.udp:
        laddr = tuple(addr.split(':'))
        print('Starting UDP EchoServer @{}:{}'.format(laddr[0], laddr[1]))
        udp_endpoint = loop.create_datagram_endpoint(UdpEchoServer, local_addr=laddr, reuse_address=True)
        transport, protocol = loop.run_until_complete(udp_endpoint)
        transports.append(transport)
    for addr in args.tcp:
        laddr = tuple(addr.split(':'))
        print('Starting TCP EchoServer @{}:{}'.format(laddr[0], laddr[1]))
        server = loop.create_server(TcpEchoServer, host=laddr[0], port=laddr[1], reuse_address=True)
        transport = loop.run_until_complete(server)
    # Run monitor task
    loop.run_until_complete(monitor())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('Terminating!', file=sys.stderr, flush=True)
        pass

    for transport in transports:
        transport.close()
    loop.close()
    print('TCP messages / connections: {} / {}'.format(TCP_MSG_COUNTER, TCP_CON_COUNTER), file=sys.stderr, flush=True)
    print('UDP messages / connections: {} / {}'.format(UDP_MSG_COUNTER, UDP_CON_COUNTER), file=sys.stderr, flush=True)
