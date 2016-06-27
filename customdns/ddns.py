import asyncio
import logging

from customdns.dnsutils import *

LOGLEVELDNS = logging.DEBUG

class DDNSServer(asyncio.DatagramProtocol):
    def __init__(self, cb_default=None, cb_add=None, cb_delete=None):
        self._logger = logging.getLogger('DDNSServer')
        self._logger.setLevel(LOGLEVELDNS)
        # Set default functions
        self._do_add = self._do_add_default
        self._do_delete = self._do_delete_default
        self._do_process = self._do_process_default
        # Set specific functions
        if cb_default:
            self._do_process = cb_default
        if cb_add:
            self._do_add = cb_add
        if cb_delete:
            self._do_delete = cb_delete

    def connection_made(self, transport):
        self._transport = transport

    def error_received(self, exc):
        addr = transport.get_extra_info('sockname')
        self._logger.warning('Error received @{0}:{1} {2}'.format(addr[0], addr[1], exc))
        
    def datagram_received(self, data, addr):
        self._logger.debug('Received data from {0}:{1} ({2} bytes) "{3}"'.format(addr[0], addr[1], len(data), data))
        try:
            query = dns.message.from_wire(data)
        except Exception as e:
            self._logger.error('Failed to parse! {0}:{1} ({2} bytes) "{3}"'.format(addr[0], addr[1], len(data), data))
            return
        try:
            self.process_message(query, addr)
        except Exception as e:
            self._logger.error('Failed to process! {0}:{1} ({2} bytes) "{3}"'.format(addr[0], addr[1], len(data), data))
            return

    def process_message(self, query, addr):
        """ Process a DNS message received by the DNS Server """
        # Sanitize incoming query
        if not sanitize_query(query):
            self._send_error(query, addr, dns.rcode.FORMERR)
            return

        q = query.question[0]
        name, rdtype, rdclass = q.name, q.rdtype, q.rdclass
        opcode = query.opcode()

        self._logger.debug('Process message {}/{} {}/{} from {}{}'.format(
            dns.opcode.to_text(opcode), query.id, name.to_text(),
            dns.rdatatype.to_text(rdtype), addr[0], addr[1]))

        #Process only DNS Update message
        if opcode != dns.opcode.UPDATE:
            self._logger.warning('Not a DNS Update message')
            return

        self._do_process(query, addr, self.callback_sendto)

    def _do_add_default(self, name, rdtype, ipaddr):
        self._logger.info('Add user {} @{}'.format(name, ipaddr))

    def _do_delete_default(self, name, rdtype, ipaddr):
        self._logger.info('Delete user {} @{}'.format(name, ipaddr))

    def _do_process_default(self, query, addr, cback):
        """ Generate NoError DNS response """
        try:
            rr_a = None
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A:
                    rr_a = rr
                    break

            if not rr_a:
                # isc-dhcp-server uses additional TXT records -> don't process
                self._logger.warning('Failed to update: "A" record not found')
                return

            name_str = rr_a.name.to_text()
            if rr_a.ttl:
                self._do_add(name_str, rr_a.rdtype, rr_a[0].address)
            else:
                self._do_delete(name_str, rr_a.rdtype, rr_a[0].address)

        except Exception as e:
            self._logger.warning('Failed to process UPDATE DNS message')
        finally:
            # Send generic DDNS Response NOERROR
            response = make_response_rcode(query, RetCodes.DNS_NOERROR)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, response, addr)

    def callback_sendto(self, query, response, addr):
        """ Send response to host """
        self._logger.debug('Callback for query {}'.format(query.id))
        if response is None:
            self._send_error(query, addr, dns.rcode.REFUSED)
            return
        self._send_msg(response, addr)

    def _send_msg(self, dnsmsg, addr):
        q = dnsmsg.question[0]
        self._logger.debug('Send message {0} {1}/{2} {3} to {4}{5}'.format(
            dnsmsg.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype),
            dns.rcode.to_text(dnsmsg.rcode()), addr[0], addr[1]))

        self._transport.sendto(dnsmsg.to_wire(), addr)

    def _send_error(self, query, addr, rcode):
        response = dns.message.make_response(query, recursion_available=True)
        response.set_rcode(rcode)
        self._send_msg(response, addr)
