import container3
import logging
import utils
import time
import pprint

LOGLEVELCONNECTIONTABLE = logging.INFO
LOGLEVELCONNECTIONENTRY = logging.INFO

KEY_RGW = 0

class ConnectionTable(container3.Container):
    def __init__(self, name='ConnectionTable'):
        """ Initialize as a Container """
        super().__init__(name, LOGLEVELCONNECTIONTABLE)

    def _update_set(self, s):
        myset = set(s)
        for node in myset:
            if node.hasexpired():
                self.remove(node)

    def update_all_rgw(self):
        conn_set = self.lookup(KEY_RGW, update=False, check_expire=False)
        if conn_set is None:
            return
        self._update_set(conn_set)

    def get_all_rgw(self, update=True):
        conn_set = self.lookup(KEY_RGW, update=False, check_expire=False)
        if conn_set is None:
            return []
        if update:
            self._update_set(conn_set)
        return conn_set

    def stats(self, key):
        data = self.lookup(key, update=False, check_expire=False)
        if data is None:
            return 0
        return len(data)


class ConnectionLegacy(container3.ContainerNode):
    TIMEOUT = 2.0
    def __init__(self, name='ConnectionLegacy', **kwargs):
        """ Initialize as a ContainerNode.

        @param name: A description of the object.
        @type name: String
        @param private_ip: Private IPv4 address.
        @type private_ip: String
        @param private_port: Private port number.
        @type private_port: Integer
        @param outbound_ip: Outbound IPv4 address.
        @type outbound_ip: String
        @param outbound_port: Outbound port number.
        @type outbound_port: Integer
        @param remote_ip: Remote IPv4 address.
        @type remote_ip: String
        @param remote_port: Remote port number.
        @type remote_port: Integer
        @param protocol: Protocol number.
        @type protocol: Integer
        @param fqdn: Allocating FQDN.
        @type fqdn: String
        @param dns_server: IPv4 address of the DNS server.
        @type dns_server: String
        @param dns_client: IPv4 address of the DNS client.
        @type dns_client: String
        @param timeout: Time to live (sec).
        @type timeout: Integer or float
        """
        super().__init__(name, LOGLEVELCONNECTIONENTRY)
        # Set attributes
        utils.set_attributes(self, **kwargs)
        # Set default unset attributes
        attrlist_zero = ['private_ip', 'private_port', 'outbound_ip', 'outbound_port', 'remote_ip', 'remote_port', 'protocol']
        attrlist_none = ['fqdn', 'dns_server', 'dns_client']
        utils.set_default_attributes(self, attrlist_zero, 0)
        utils.set_default_attributes(self, attrlist_none, None)
        self.timeout = ConnectionLegacy.TIMEOUT
        # Take creation timestamp
        self.timestamp_zero = time.time()
        ## Override timeout ##
        #self.timeout = 600.0
        ######################
        self.timestamp_eol = self.timestamp_zero + self.timeout
        self._build_lookupkeys()

    def _build_lookupkeys(self):
        # Build set of lookupkeys
        self._built_lookupkeys = []
        # Basic indexing
        self._built_lookupkeys.append((KEY_RGW, False))
        # Private IP-based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.private_ip), False))
        # Outbound IP-based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip), False))
        # 3-tuple semi-fledged based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip, self.outbound_port, self.protocol), True))
        # 5-tuple full-fledged based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip, self.outbound_port, self.remote_ip, self.remote_port, self.protocol), True))

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        return self._built_lookupkeys

    def hasexpired(self):
        """ Return True if the timeout has expired """
        return time.time() > self.timestamp_eol

    def __repr__(self):
        ret = ''
        ret += '[{}]'.format(self.protocol)

        if self.private_port:
            ret += ' {}:{} <- {}:{}'.format(self.private_ip, self.private_port, self.outbound_ip, self.outbound_port)
        else:
            ret += ' {} <- {}'.format(self.private_ip, self.outbound_ip)

        if self.remote_ip:
            ret += ' <=> {}:{}'.format(self.remote_ip, self.remote_port)

        ret += ' ({} sec)'.format(self.timeout)

        if self.fqdn:
            ret += ' | FQDN {}'.format(self.fqdn)

        if self.dns_server:
            ret += ' | DNS {} <- {}'.format(self.dns_server, self.dns_client)

        return ret

if __name__ == "__main__":
    table = ConnectionTable()
    d1 = {'outbound_ip':'1.2.3.4','dns_server':'8.8.8.8','private_ip':'192.168.0.100','fqdn':'host100.rgw','timeout':2.0}
    c1 = ConnectionLegacy(**d1)
    d2 = {'outbound_ip':'1.2.3.5','dns_server':'8.8.8.8','private_ip':'192.168.0.100','fqdn':'host100.rgw','timeout':2.0,
          'outbound_port':12345,'protocol':6}
    c2 = ConnectionLegacy(**d2)
    table.add(c1)
    table.add(c2)

    print('Connection c1 has expired?')
    print(c1.hasexpired())
    print(table)
    print(c1.lookupkeys())
    print(c2.lookupkeys())
    time.sleep(3)
    print('Connection c1 has expired?')
    print(c1.hasexpired())

    table.update_all_rgw()
