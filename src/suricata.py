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

import asyncio
import logging
import json
import os
import subprocess


class SuricataAlert(asyncio.DatagramProtocol):
    def __init__(self):
        self._logger = logging.getLogger('SuricataAlert')

    def connection_made(self, transport):
        self._transport = transport

    def error_received(self, exc):
        addr = self._transport.get_extra_info('sockname')
        self._logger.debug('Error received @{}:{} {}'.format(addr[0], addr[1], exc))

    def datagram_received(self, data, addr):
        '''
        # Data example
        {'alert': {'action': 'allowed',
          'category': 'A Network Trojan was detected',
          'gid': 1,
          'rev': 35,
          'severity': 1,
          'signature': 'ET USER_AGENTS Better Internet Spyware User-Agent (poller)',
          'signature_id': 2002005},
         'dest_ip': '8.8.8.8',
         'dest_port': 53,
         'event_type': 'alert',
         'flow_id': 93833867552496,
         'pcap_cnt': 17,
         'proto': 'TCP',
         'src_ip': '100.64.1.131',
         'src_port': 4567,
         'timestamp': '2018-02-27T15:18:35.546970+0200',
         'tx_id': 0}

        # Example of matching conntrack 5-tuples
        msg_wan_out = {"dest_ip": "8.8.4.4",      "dest_port": 53,    "src_ip": "100.64.1.131", "src_port": 43097,  "proto": "UDP", "alert":{"category": "cat_foo", "signature": "sig_foo"}}
        msg_wan_in  = {"dest_ip": "100.64.1.131", "dest_port": 43097,  "src_ip": "8.8.4.4",      "src_port": 53,    "proto": "UDP", "alert":{"category": "cat_foo", "signature": "sig_foo"}}
        msg_lan_out = {"dest_ip": "8.8.8.8",      "dest_port": 53,    "src_ip": "100.64.1.133", "src_port": 40749, "proto": "TCP", "alert":{"category": "cat_foo", "signature": "sig_foo"}}
        msg_lan_in  = {"dest_ip": "100.64.1.133", "dest_port": 40749, "src_ip": "8.8.8.8",      "src_port": 53,    "proto": "TCP", "alert":{"category": "cat_foo", "signature": "sig_foo"}}
        '''
        try:
            self._logger.debug('Received data {} {}'.format(data, addr))
            msg_d = json.loads(data.decode())

            # Incoming packet of a connection originated from WAN
            wan_in  = 'conntrack -D conntrack --orig-src {}  --orig-dst {}   --proto {} --orig-port-src {}  --orig-port-dst {} '.format(msg_d['src_ip'], msg_d['dest_ip'], msg_d['proto'], msg_d['src_port'], msg_d['dest_port'])
            # Outgoing packet of a connection originated from WAN
            wan_out = 'conntrack -D conntrack --orig-src {}  --orig-dst {}   --proto {} --orig-port-src {}  --orig-port-dst {} '.format(msg_d['dest_ip'], msg_d['src_ip'], msg_d['proto'], msg_d['dest_port'], msg_d['src_port'])

            # Incoming packet of a connection originated from LAN
            lan_in  = 'conntrack -D conntrack --reply-src {} --reply-dst {}  --proto {} --reply-port-src {} --reply-port-dst {}'.format(msg_d['src_ip'], msg_d['dest_ip'], msg_d['proto'], msg_d['src_port'], msg_d['dest_port'])
            # Outgoing packet of a connection originated from LAN
            lan_out = 'conntrack -D conntrack --reply-src {} --reply-dst {}  --proto {} --reply-port-src {} --reply-port-dst {}'.format(msg_d['dest_ip'], msg_d['src_ip'], msg_d['proto'], msg_d['dest_port'], msg_d['src_port'])

            for msg in [wan_in, wan_out, lan_in, lan_out]:
                if self._conntrack_delete(msg, silent = True):
                    self._logger.warning('Removed hazardous flow! [{}] {}:{} > {}:{} // {} / {}'.format(msg_d['proto'], msg_d['src_ip'], msg_d['src_port'], msg_d['dest_ip'], msg_d['dest_port'], msg_d['alert']['category'], msg_d['alert']['signature']))
        except:
            self._logger.warning('Failed to process data {} {}'.format(data, addr))


    def _conntrack_delete(self, command, silent = False):
        """ Return True if a flow was removed """
        try:
            if silent:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f, stderr=f)
            else:
                subprocess.check_call(command, shell=True)
            return True
        except:
            return False

    def _send_msg(self, data_b, addr):
        self._transport.sendto(data_b, addr)
