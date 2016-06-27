import container3
import logging
import utils
import time

LOGLEVELCONNECTIONTABLE = logging.WARNING
LOGLEVELCONNECTIONENTRY = logging.WARNING

KEY_FQDN = 0
KEY_SFQDN = 1

class ConnectionTable(container3.Container):
    def __init__(self, name='ConnectionTable'):
        """ Initialize as a Container """
        super().__init__(name, LOGLEVELCONNECTIONTABLE)

class ConnectionEntryRGW(container3.ContainerNode):
    def __init__(self, name='ConnectionEntryRGW', **kwargs):
        """ Initialize as a ContainerNode.

        @param name: A description of the object.
        @type name: String
        @param public_ipv4: Allocated public IPv4 address.
        @type public_ipv4: String
        @param public_port: Allocated public port number.
        @type public_port: Integer or None
        @param public_proto: Allocated public protocol number.
        @type public_proto: Integer or None
        @param dns_ipv4: Allocating public IPv4 address of the DNS server.
        @type dns_ipv4: String
        @param host_ipv4: Private IPv4 address of the allocated host.
        @type host_ipv4: String
        @param host_fqdn: Allocating FQDN.
        @type host_fqdn: String
        @param timeout: Time to live (sec).
        @type timeout: Integer or float
        """
        super().__init__(name, LOGLEVELCONNECTIONENTRY)
        attrlist = ['public_ipv4','public_port','public_proto','dns_ipv4','host_ipv4','host_fqdn','timeout']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)
        self.timestamp_zero = time.time()
        self.timestamp_eol = self.timestamp_zero + self.timeout

    def lookupkeys(self):
        """ Return the lookup keys """
        extra_key = (KEY_SFQDN, True) if self.public_port else (KEY_FQDN, True)
        return (((self.public_ipv4,self.public_port,self.public_proto), False), extra_key)

    def __repr__(self):
        if self.public_port:
            return '{}:{} -> {}:{} {} ({})'.format(self.public_ipv4, self.public_port, self.host_ipv4,
                                                   self.public_port, self.public_proto, self.dns_ipv4)
        else:
            return '{} -> {} ({})'.format(self.public_ipv4, self.host_ipv4, self.dns_ipv4)


if __name__ == "__main__":
    table = ConnectionTable()
    d1 = {'public_ipv4':'1.2.3.4','dns_ipv4':'8.8.8.8','host_ipv4':'192.168.0.100','host_fqdn':'host100.rgw','timeout':2.0}
    c1 = ConnectionEntryRGW(**d1)
    d2 = {'public_ipv4':'1.2.3.5','dns_ipv4':'8.8.8.8','host_ipv4':'192.168.0.100','host_fqdn':'host100.rgw','timeout':2.0,
          'public_port':12345,'public_proto':6}
    c2 = ConnectionEntryRGW(**d2)
    table.add(c1)
    table.add(c2)
    print(table)
    print(c1.lookupkeys())
    print(c2.lookupkeys())
