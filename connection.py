import container3
import logging
import utils
import time

#TODO: Check if all keys of ConnectionEntryRGW are needed
#TODO: Create a higher level of abstraction in ConnectionEntryRGW to account also for remote side IP/port

LOGLEVELCONNECTIONTABLE = logging.WARNING
LOGLEVELCONNECTIONENTRY = logging.WARNING

KEY_RGW = 0
KEY_RGW_FQDN = 0
KEY_RGW_SFQDN = 1

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


class ConnectionEntryRGW(container3.ContainerNode):
    def __init__(self, name='ConnectionEntryRGW', **kwargs):
        """ Initialize as a ContainerNode.

        @param name: A description of the object.
        @type name: String
        @param public_ipv4: Allocated public IPv4 address.
        @type public_ipv4: String
        @param public_port: Allocated public port number.
        @type public_port: Integer or None
        @param public_protocol: Allocated public protocol number.
        @type public_protocol: Integer or None
        @param dns_server_ipv4: IPv4 address of the DNS querying server.
        @type dns_server_ipv4: String
        @param dns_client_ipv4: IPv4 address of the DNS originating client.
        @type dns_client_ipv4: String
        @param host_ipv4: Private IPv4 address of the allocated host.
        @type host_ipv4: String
        @param host_fqdn: Allocating FQDN.
        @type host_fqdn: String
        @param timeout: Time to live (sec).
        @type timeout: Integer or float
        """
        super().__init__(name, LOGLEVELCONNECTIONENTRY)
        attrlist = ['public_ipv4','public_port','public_protocol','dns_server_ipv4','dns_client_ipv4','host_ipv4','host_fqdn','timeout']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)
        self.timestamp_zero = time.time()
        ## Override timeout ##
        self.timeout = 600.0
        ######################
        self.timestamp_eol = self.timestamp_zero + self.timeout
        self._build_lookupkeys()

    def _build_lookupkeys(self):
        """ Build the lookup keys """
        # Create specific key if the connection is allocated to an SFQDN domain
        '''
        # There are unused keys
        rgw_key = (KEY_RGW, False)
        s_fqdn_key = ((KEY_RGW, KEY_RGW_FQDN), False)
        if (self.public_port, self.public_protocol) != (None, None):
            s_fqdn_key = ((KEY_RGW, KEY_RGW_SFQDN), False)
        host_key = ((KEY_RGW, self.host_ipv4), False)
        public_ipv4_key = ((KEY_RGW, self.public_ipv4), False)
        ntuple_key = ((KEY_RGW, self.public_ipv4, self.public_port, self.public_protocol), True)
        # Create tuple with all calculated keys
        self._built_lookupkeys = (rgw_key, s_fqdn_key, host_key, public_ipv4_key, ntuple_key)
        '''
        # Build minimum set of lookupkeys
        basic_key   = (KEY_RGW, False)
        host_key   = ((KEY_RGW, self.host_ipv4), False)
        public_key = ((KEY_RGW, self.public_ipv4), False)
        n3tuple_key = ((KEY_RGW, self.public_ipv4, self.public_port, self.public_protocol), True)
        # Create tuple with all calculated keys
        self._built_lookupkeys = (basic_key, host_key, public_key, n3tuple_key)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        return self._built_lookupkeys

    def hasexpired(self):
        """ Return True if the timeout has expired """
        return time.time() > self.timestamp_eol

    def __repr__(self):
        return '{}:{} [{}]<- {}:{} [{}] ({}/{})'.format(self.host_ipv4, self.public_port, self.public_protocol,
                                                        self.public_ipv4, self.public_port, self.public_protocol,
                                                        self.dns_server_ipv4, self.dns_client_ipv4)

if __name__ == "__main__":
    table = ConnectionTable()
    d1 = {'public_ipv4':'1.2.3.4','dns_server_ipv4':'8.8.8.8','host_ipv4':'192.168.0.100','host_fqdn':'host100.rgw','timeout':2.0}
    c1 = ConnectionEntryRGW(**d1)
    d2 = {'public_ipv4':'1.2.3.5','dns_server_ipv4':'8.8.8.8','host_ipv4':'192.168.0.100','host_fqdn':'host100.rgw','timeout':2.0,
          'public_port':12345,'public_protocol':6}
    c2 = ConnectionEntryRGW(**d2)
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