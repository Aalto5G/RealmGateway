#!/usr/bin/env python3

import asyncio
import argparse

COUNTER = 0

class EchoServerProtocol:
    def connection_made(self, transport):
        self.transport = transport
        self.laddr = transport.get_extra_info('sockname')

    def datagram_received(self, data, addr):
        print('Received {} from <{}:{}>'.format(data, addr[0], addr[1]))
        self.transport.sendto(data, addr)
        global COUNTER
        COUNTER += 1

@asyncio.coroutine
def handle_echo(reader, writer, n=100):
    data = yield from reader.read(n)
    addr = writer.get_extra_info('peername')
    print('Received {} from <{}:{}>'.format(data, addr[0], addr[1]))
    writer.write(data)
    yield from writer.drain()
    writer.close()
    global COUNTER
    COUNTER += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Data test server with python3 and asyncio')
    parser.add_argument('--udp', nargs='+', required=False, help='Server UDP address (ipaddr:port)')
    parser.add_argument('--tcp', nargs='+', required=False, help='Server TCP address (ipaddr:port)')
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    transports = []
    for addr in args.udp:
        laddr = tuple(addr.split(':'))
        print('Starting UDP EchoServer @{}:{}'.format(laddr[0], laddr[1]))
        udp_endpoint = loop.create_datagram_endpoint(EchoServerProtocol, local_addr=laddr)
        transport, protocol = loop.run_until_complete(udp_endpoint)
        transports.append(transport)
    for addr in args.tcp:
        laddr = tuple(addr.split(':'))
        print('Starting TCP EchoServer @{}:{}'.format(laddr[0], laddr[1]))
        coro = asyncio.start_server(handle_echo, laddr[0], laddr[1])
        transport = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    for transport in transports:
        transport.close()
    loop.close()
    print('Answered {} messages'.format(COUNTER))
