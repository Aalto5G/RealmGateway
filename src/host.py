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

import logging

from helpers_n_wrappers import container3
from helpers_n_wrappers import utils3
from customdns.dnsutils import from_address as ptr_from_address

KEY_HOST = 0
KEY_HOST_FQDN = 1
KEY_HOST_IPV4 = 2
KEY_HOST_SERVICE = 3
KEY_SERVICE_SFQDN = 'SFQDN'
KEY_SERVICE_CIRCULARPOOL = 'CIRCULARPOOL'
KEY_SERVICE_FIREWALL = 'FIREWALL'
KEY_SERVICE_CARRIERGRADE = 'CARRIERGRADE'

class HostTable(container3.Container):
    def __init__(self, name='HostTable'):
        """ Initialize as a Container """
        super().__init__(name)

    def has_carriergrade(self, fqdn):
        """ Return True if the FQDN exists for a host defined as carrier grade """
        # 1. Check if the service exists for the given FQDN and if it supports carriergrade
        if self.has((KEY_HOST_SERVICE, fqdn)):
            host = self.get((KEY_HOST_SERVICE, fqdn))
            service_data = host.get_service_sfqdn(fqdn)
            if service_data['carriergrade']:
                self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for FQDN {}'.format(fqdn))
            return service_data['carriergrade']

        # 2. Check host list and check if FQDN is a subdomain of one of our hosts' services
        for host in self.getall():
            for service_data in host.services[KEY_SERVICE_SFQDN]:
                nstoken = '.{}'.format(service_data['fqdn'])
                if not fqdn.endswith(nstoken):
                    continue
                # The given FQDN is nested under the current service_data
                if service_data['carriergrade']:
                    self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for delegated-FQDN {}'.format(fqdn))
                return service_data['carriergrade']
        return False

    def get_carriergrade(self, fqdn):
        """ Return a tuple of host object an service data for which the FQDN exists as carrier grade """
        # 1. Check if the service exists for the given FQDN and if it supports carriergrade
        if self.has((KEY_HOST_SERVICE, fqdn)):
            host = self.get((KEY_HOST_SERVICE, fqdn))
            service_data = host.get_service_sfqdn(fqdn)
            if service_data['carriergrade']:
                self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for FQDN {}'.format(fqdn))
            return (host,service_data)

        # 2. Check host list and check if FQDN is a subdomain of one of our hosts' services
        for host in self.getall():
            for service_data in host.services[KEY_SERVICE_SFQDN]:
                nstoken = '.{}'.format(service_data['fqdn'])
                if not fqdn.endswith(nstoken):
                    continue
                # The given FQDN is nested under the current service_data
                if service_data['carriergrade']:
                    self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for delegated-FQDN {}'.format(fqdn))
                return (host,service_data)
        return None

    def show(self):
        for node in self._list:
            node.show()

class HostEntry(container3.ContainerNode):
    def __init__(self, name='HostEntry', **kwargs):
        """ Initialize as a ContainerNode """
        super().__init__(name)
        # Initialize services dictionary
        self.services = {}
        self.ipv4 = None
        self.fqdn = None
        utils3.set_attributes(self, override=True, **kwargs)
        # Sanitize key in dictionary for lookupkeys()
        self.services.setdefault(KEY_SERVICE_SFQDN, [])
        # Normalize SFQDN service definition
        self._normalize_service_sfqdn()
        # Create hostname by splitting FQDN name
        self.hostname = self.fqdn.split('.')[0]

    def lookupkeys(self):
        """ Return the lookup keys """
        # Create list of keys
        keys = []
        # Add FQDN key entry
        keys.append(((KEY_HOST_FQDN, self.fqdn), True))
        # Add IPv4 key entry
        keys.append(((KEY_HOST_IPV4, self.ipv4), True))
        # Add SFQDN key(s)
        for data in self.services[KEY_SERVICE_SFQDN]:
            keys.append(((KEY_HOST_SERVICE, data['fqdn']), True))
        # Add Reverse IPv4 key entry as KEY_HOST_SERVICE
        keys.append(((KEY_HOST_SERVICE, ptr_from_address(self.ipv4)), True))
        return keys

    def get_service_sfqdn(self, fqdn):
        # Return mapping for an SFQDN of the user
        # Value is returned as a dictionary
        for data in self.services[KEY_SERVICE_SFQDN]:
            if data['fqdn'] != fqdn:
                continue
            return data

    def add_service(self, service_id, service_data):
        if service_id not in self.services:
            # Create service list
            self.services[service_id] = []
        if service_data not in self.services[service_id]:
            self.services[service_id].append(service_data)
        # Normalize SFQDN service definition
        self._normalize_service_sfqdn()

    def remove_service(self, service_id, service_data):
        if service_id in self.services and service_data in self.services[service_id]:
            self.services[service_id].remove(service_data)

    def get_service(self, service_id, default = None):
        if service_id in self.services:
            return self.services[service_id]
        return default

    def has_service(self, service_id):
        return service_id in self.services

    def _normalize_service_sfqdn(self):
        for data in self.services[KEY_SERVICE_SFQDN]:
            data.setdefault('port', 0)
            data.setdefault('protocol', 0)
            data.setdefault('proxy_required', False)
            data.setdefault('carriergrade', False)
            data.setdefault('alias', False)

    def show(self):
        # Pretty(ier) print of the host information
        print('##### Host #####')
        print('> FQDN: {}'.format(self.fqdn))
        print('> IPv4: {}'.format(self.ipv4))
        print('> Services: {}'.format(self.services))
        print('> Lookupkeys: {}'.format(self.lookupkeys()))
        print('################')

    def __repr__(self):
        return '{} @ {}'.format(self.fqdn, self.ipv4)

if __name__ == "__main__":
    table = HostTable()
    d1 = {'ipv4':'192.168.0.100','fqdn':'host100.rgw.'}
    h1 = HostEntry(name='host100', **d1)
    d2 = {'ipv4':'192.168.0.101','fqdn':'host101.rgw.'}
    h2 = HostEntry(name='host101', **d2)
    table.add(h1)
    table.add(h2)
    h1.add_service(KEY_SERVICE_SFQDN, {'fqdn': 'iperf.foo100.rgw.', 'port': 5001, 'protocol': 6 })
    h1.add_service(KEY_SERVICE_SFQDN, {'fqdn': 'ssh.foo100.rgw.',   'port': 22,   'protocol': 6 })
    h1.add_service(KEY_SERVICE_CARRIERGRADE, {'ipv4': '1.1.1.1'})
    h1.add_service(KEY_SERVICE_CARRIERGRADE, {'ipv4': '1.1.1.2'})
    h1.add_service(KEY_SERVICE_CARRIERGRADE, {'ipv4': '1.1.1.3'})
    table.updatekeys(h1)

    print('h1.services')
    print(h1.services)
    print('h1.lookupkeys')
    print(h1.lookupkeys())

    d3 = {'ipv4':'192.168.0.102','fqdn':'host102.rgw.', 'services':{'SFQDN':[{'fqdn': 'host102.rgw.'},{'fqdn': 'telnet.host102.rgw.', 'port': 23, 'protocol': 6 }]}}
    h3 = HostEntry(name='host102', **d3)
    table.add(h3)

    print('h3.services')
    print(h3.services)
    print('h3.lookupkeys')
    print(h3.lookupkeys())

    print(h3.get_service_sfqdn('host102.rgw.'))
    print(h3.get_service_sfqdn('telnet.host102.rgw.'))

    print('table')
    table.show()

    # Check carrier grade functions
    print("table.has_carriergrade('host100.rgw.')")
    print(table.has_carriergrade('host100.rgw.'))
    print("table.has_carriergrade('subdomain.host100.rgw.')")
    print(table.has_carriergrade('subdomain.host100.rgw.'))
    print("table.has_carriergrade('host101.rgw.')")
    print(table.has_carriergrade('host101.rgw.'))
    print("table.has_carriergrade('subdomain.host101.rgw.')")
    print(table.has_carriergrade('subdomain.host101.rgw.'))
    print("h1.get_service(KEY_SERVICE_CARRIERGRADE)")
    print(h1.get_service(KEY_SERVICE_CARRIERGRADE))
