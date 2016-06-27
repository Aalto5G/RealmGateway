import container3
import logging
import utils

LOGLEVELHOSTTABLE = logging.WARNING
LOGLEVELHOSTENTRY = logging.WARNING

KEY_FQDN = 0
KEY_SFQDN = 1

class HostTable(container3.Container):
    def __init__(self, name='HostTable'):
        """ Initialize as a Container """
        super().__init__(name, LOGLEVELHOSTTABLE)

class HostEntry(container3.ContainerNode):
    def __init__(self, name='HostEntry', **kwargs):
        """ Initialize as a ContainerNode """
        super().__init__(name, LOGLEVELHOSTENTRY)
        attrlist = ['ipv4','fqdn','services']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)
        # Register basic host service
        self.add_service(self.fqdn, None, None)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Create list of keys
        keys = []
        # Add ipv4 key entry
        keys.append((self.ipv4, False))
        # Add service keys
        for skey in self.services:
            keys.append((skey, False))
        # Register FQDN/SFQDN index keys
        keys.append((KEY_FQDN, True))
        keys.append((KEY_SFQDN, True))
        return keys

    def add_service(self, sfqdn, port, proto):
        if self.services is None:
            self.services = {}
        self.services[sfqdn] = (sfqdn, port, proto)

    def get_service(self, sfqdn):
        if sfqdn not in self.services:
            return None
        return self.services[sfqdn]

    def __repr__(self):
        return '{} {}'.format(self.ipv4, self.fqdn)

if __name__ == "__main__":
    table = HostTable()
    d1 = {'ipv4':'192.168.0.100','fqdn':'host100.rgw'}
    h1 = HostEntry(name='host100', **d1)
    d2 = {'ipv4':'192.168.0.101','fqdn':'host101.rgw'}
    h2 = HostEntry(name='host101', **d2)
    table.add(h1)
    table.add(h2)
    h1.add_service('ssh.host100.rgw',22,6)
    h1.add_service('www.host100.rgw',80,6)
    table.updatekeys(h1)
    print(table)
    print(h1.services)
