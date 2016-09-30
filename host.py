import container3
import logging
import utils
import pprint

LOGLEVELHOST = logging.INFO

KEY_HOST = 0
KEY_HOST_FQDN = 1
KEY_HOST_IPV4 = 2
KEY_HOST_SERVICE = 3
KEY_HOST_NS = 4
KEY_SERVICE_SFQDN = 'SFQDN'
KEY_SERVICE_CIRCULARPOOL = 'CIRCULARPOOL'
KEY_SERVICE_FIREWALL = 'FIREWALL'
KEY_SERVICE_CARRIERGRADE = 'CARRIERGRADE'

class HostTable(container3.Container):
    def __init__(self, name='HostTable'):
        """ Initialize as a Container """
        super().__init__(name, LOGLEVELHOST)

    def has_carriergrade(self, fqdn):
        """ Return True if a matching host is defined as carrier grade """
        # 1. Check if the host exists for the given FQDN and supports carriergrade
        ## TOCHECK: Should we check KEY_HOST_FQDN or KEY_HOST_SERVICE ?
        host = self.lookup((KEY_HOST_FQDN, fqdn))
        if host and host.has_service(KEY_SERVICE_CARRIERGRADE):
            self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for FQDN {}'.format(fqdn))
            return True
        # 2. Check host list and assume fqdn as a subdomain of one of our hosts
        for host in self.getall():
            if not host.has_service(KEY_SERVICE_CARRIERGRADE):
                continue
            nstoken = '.{}'.format(host.fqdn)
            if fqdn.endswith(nstoken):
                self._logger.debug('Host has KEY_SERVICE_CARRIERGRADE for delegated-FQDN {}'.format(fqdn))
                return True
        return False

    def get_carriergrade(self, fqdn):
        """ Return the host object if a matching host is defined as carrier grade """
        # 1. Check if the host exists for the given FQDN and supports carriergrade
        ## TOCHECK: Should we check KEY_HOST_FQDN or KEY_HOST_SERVICE ?
        host = self.lookup((KEY_HOST_FQDN, fqdn))
        if host and host.has_service(KEY_SERVICE_CARRIERGRADE):
            self._logger.debug('Get host KEY_SERVICE_CARRIERGRADE for FQDN {}'.format(fqdn))
            return host
        # 2. Check host list and assume fqdn as a subdomain of one of our hosts
        for host in self.getall():
            if not host.has_service(KEY_SERVICE_CARRIERGRADE):
                continue
            nstoken = '.{}'.format(host.fqdn)
            if fqdn.endswith(nstoken):
                self._logger.debug('Get host KEY_SERVICE_CARRIERGRADE for delegated-FQDN {}'.format(fqdn))
                return host
        return None

    def show(self):
        for node in self._list:
            node.show()

class HostEntry(container3.ContainerNode):
    def __init__(self, name='HostEntry', **kwargs):
        """ Initialize as a ContainerNode """
        super().__init__(name, LOGLEVELHOST)
        attrlist = ['ipv4','fqdn']
        # Initialize services dictionary
        self.services = {}
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)
        # Sanitize key in dictionary for lookupkeys()
        self.services.setdefault(KEY_SERVICE_SFQDN, [])
        # Normalize SFQDN service definition
        self._normalize_service_sfqdn()

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
            port = data.setdefault('port', 0)
            protocol = data.setdefault('protocol', 0)
            data.setdefault('proxy_required', False)

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
