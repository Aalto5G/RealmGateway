import container3
import logging
import utils
import pprint

LOGLEVELHOSTTABLE = logging.WARNING
LOGLEVELHOSTENTRY = logging.WARNING

KEY_FQDN = 'FQDN'
KEY_SFQDN = 'SFQDN'
KEY_CIRCULARPOOL = 'CIRCULARPOOL'
KEY_FIREWALL = 'FIREWALL'

class HostTable(container3.Container):
    def __init__(self, name='HostTable'):
        """ Initialize as a Container """
        super().__init__(name, LOGLEVELHOSTTABLE)

class HostEntry(container3.ContainerNode):
    def __init__(self, name='HostEntry', **kwargs):
        """ Initialize as a ContainerNode """
        super().__init__(name, LOGLEVELHOSTENTRY)
        # Initialize service dictionary
        self.services = {KEY_FQDN: [], KEY_SFQDN: []}
        attrlist = ['ipv4','fqdn']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)
        # Register basic host service
        self.add_service(KEY_FQDN, {'fqdn': self.fqdn, 'port': None, 'protocol': None})
        '''
        Example of SFQDN service definition
        'SFQDN': [{'fqdn': 'iperf.foo100.rgw.', 'port': 5001, 'protocol': 6}]
        '''

    def lookupkeys(self):
        """ Return the lookup keys """
        # Create list of keys
        keys = []
        # Add ipv4 key entry
        host_key = (self.ipv4, True)
        # Add SFQDN key(s)
        for data in self.services[KEY_FQDN] + self.services[KEY_SFQDN]:
            keys.append((data['fqdn'], True))
        # Register FQDN/SFQDN index keys
        #keys.append((KEY_FQDN, True))
        #keys.append((KEY_SFQDN, True))
        return keys

    def add_service(self, service_id, service_data):
        if service_id not in self.services:
            # Create service list
            self.services[service_id] = []
        if service_data not in self.services[service_id]:
            self.services[service_id].append(service_data)

    def remove_service(self, service_id, service_data):
        if service_id in self.services and service_data in self.services[service_id]:
            self.services[service_id].remove(service_data)

    def get_service(self, service_id):
        if service_id in self.services:
            return self.services[service_id]

    def get_service_fqdn_mapping(self, fqdn):
        # Return mapping for an FQDN of the user (port, protocol)
        # Value is returned as a tuple
        for data in self.services[KEY_FQDN] + self.services[KEY_SFQDN]:
            if data['fqdn'] != fqdn:
                continue
            return (data['port'], data['protocol'])

    def get_service_data_mapping(self, fqdn):
        # Return given data mapping for an FQDN of the user
        # Value is returned as a dictionary
        for data in self.services[KEY_FQDN] + self.services[KEY_SFQDN]:
            if data['fqdn'] != fqdn:
                continue
            return data

    def show(self):
        # Pretty(ier) print of the host information
        print('##### Host #####')
        print('> FQDN: {}'.format(self.fqdn))
        print('> IPv4: {}'.format(self.ipv4))
        print('> Services: {}'.format(self.services))
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
    h1.add_service(KEY_SFQDN, {'fqdn': 'iperf.foo100.rgw.', 'port': 5001, 'protocol': 6 })
    h1.add_service(KEY_SFQDN, {'fqdn': 'ssh.foo100.rgw.', 'port': 22, 'protocol': 6 })
    table.updatekeys(h1)
    d3 = {'ipv4':'192.168.0.102','fqdn':'host102.rgw.', 'services':{'SFQDN':[{'fqdn': 'telnet.host102.rgw.', 'port': 23, 'protocol': 6 }]}}
    h3 = HostEntry(name='host102', **d3)
    table.add(h3)
    print('h1.services')
    print(h1.services)
    print('h1.lookupkeys')
    print(h1.lookupkeys())
    print('h3.services')
    print(h3.services)
    print('h3.lookupkeys')
    print(h3.lookupkeys())
    print('table')
    print(table)
    print(h3.get_service_fqdn_mapping('host102.rgw.'))
    print(h3.get_service_fqdn_mapping('telnet.host102.rgw.'))
    print(h3.get_service_data_mapping('telnet.host102.rgw.'))
    h3.show()
