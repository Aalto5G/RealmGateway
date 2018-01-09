#TODO: Optimize memory by having the pool and then a bytearray per host (1/0)

import ipaddress
import logging
import random

from aalto_helpers import container3

def _calculate_address_pool(addrmask, ipv6=False):
    """
    Return a pool of addresses contained in the network.

    @param addrmask: Network in IP/mask format.
    @return: A list of ip addresses
    """
    if ipv6:
        netobj = ipaddress.IPv6Network(addrmask, strict=False)
    else:
        netobj = ipaddress.IPv4Network(addrmask, strict=False)

    return [format(addr) for addr in netobj]

class PoolContainer(container3.Container):
    def __init__(self, name='PoolContainer'):
        """ Initialize as a Container """
        super().__init__(name)


class NamePool(container3.ContainerNode):
    def __init__(self, key, addrmask=None, name='NamePool'):
        """ Initialize as a ContainerNode """
        super().__init__(name)
        self._key = key
        self._pool = set()

    def add_to_pool(self, name):
        self._logger.debug('Add name {} to pool'.format(name))
        self._pool.add(addr)

    def get_pool(self):
        return list(self._pool)

    def in_pool(self, addr):
        return (addr in self._pool)

    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, True),)

    def __repr__(self):
        return self._name

class AddressPoolShared(container3.ContainerNode):
    def __init__(self, key, addrmask=None, name='AddressPoolShared'):
        """ Initialize as a ContainerNode """
        super().__init__(name)
        self._key = key
        self._pool = _AddressPoolUnit('{}{}'.format(name,'Unit'))
        if addrmask:
            self.add_to_pool(addrmask)

    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, True),)

    def add_to_pool(self, addrmask):
        return self._pool.add_to_pool(addrmask)

    def get_pool(self):
        return self._pool.get_pool()

    def get_allocated(self):
        return self._pool.get_allocated()

    def get_available(self):
        return self._pool.get_available()

    def get_stats(self):
        return self._pool.get_stats()

    def in_pool(self, addr):
        return self._pool.in_pool(addr)

    def in_allocated(self, addr):
        return self._pool.in_allocated(addr)

    def in_available(self, addr):
        return self._pool.in_available(addr)

    def allocate(self):
        return self._pool.allocate()

    def allocate_random(self):
        return self._pool.allocate_random()

    def release(self, addr):
        return self._pool.release(addr)

    def __repr__(self):
        return self._name


class AddressPoolUser(container3.ContainerNode):
    def __init__(self, key, addrmask=None, name='AddressPoolUser'):
        """ Initialize as a ContainerNode """
        super().__init__(name)
        self._key = key
        self._pool = {}
        self._addrpool = []
        if addrmask:
            self.add_to_pool(addrmask)

    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, True),)

    def add_to_pool(self, addrmask):
        self._addrpool.append(addrmask)

    def create_pool(self, userid):
        if userid in self._pool:
            self._logger.warning('Failed to create pool for {}'.format(userid))
            return

        self._logger.warning('Creating new pool for {}'.format(userid))
        ap = _AddressPoolUnit('AddressPoolUser@{}'.format(userid))
        self._pool[userid] = ap
        for addrmask in self._addrpool:
            ap.add_to_pool(addrmask)

    def destroy_pool(self, userid):
        if userid not in self._pool:
            self._logger.warning('Failed to destroy pool for {}'.format(userid))
            return

        self._logger.warning('Destroy pool for {}'.format(userid))
        del self._pool[userid]

    def get_pool(self, userid):
        return self._pool[userid].get_pool()

    def get_allocated(self, userid):
        return self._pool[userid].get_allocated()

    def get_available(self, userid):
        return self._pool[userid].get_available()

    def get_stats(self, userid):
        return self._pool[userid].get_stats()

    def in_pool(self, userid, addr):
        return self._pool[userid].in_pool(addr)

    def in_allocated(self, userid, addr):
        return self._pool[userid].in_allocated(addr)

    def in_available(self, userid, addr):
        return self._pool[userid].in_available(addr)

    def allocate(self, userid):
        return self._pool[userid].allocate()

    def allocate_random(self):
        return self._pool[userid].allocate_random()

    def release(self, userid, addr):
        return self._pool[userid].release(addr)

    def __repr__(self):
        return self._name

class _AddressPoolUnit_set(object):
    def __init__(self, name='_AddressPoolUnit'):
        """ Initialize the _AddressPoolUnit """
        self._logger = logging.getLogger(name)
        self._pool = set()
        self._allocated = set()
        self._available = set()

    def add_to_pool(self, addrmask):
        self._logger.debug('Add network {} to pool'.format(addrmask))
        for addr in _calculate_address_pool(addrmask):
            if addr in self._pool:
                continue
            self._pool.add(addr)
            self._available.add(addr)

    def get_pool(self):
        return list(self._pool)

    def get_allocated(self):
        return list(self._allocated)

    def get_available(self):
        return list(self._available)

    def get_stats(self):
        """ Return a tuple of (Total/Allocated/Available) """
        return (len(self._pool), len(self._allocated), len(self._available))

    def in_pool(self, addr):
        return (addr in self._pool)

    def in_allocated(self, addr):
        return (addr in self._allocated)

    def in_available(self, addr):
        return (addr in self._available)

    def allocate(self):
        try:
            addr = self._available.pop()
            self._allocated.add(addr)
            return addr
        except:
            return None

    def allocate_random(self):
        # Pop operation in set is always random
        return self.allocate()

    def release(self, addr):
        self._allocated.remove(addr)
        self._available.add(addr)
        return addr

class _AddressPoolUnit_list(object):
    def __init__(self, name='_AddressPoolUnit'):
        """ Initialize the _AddressPoolUnit """
        self._logger = logging.getLogger(name)
        self._pool = []
        self._allocated = []
        self._available = []
        self._sortflag = True

    def add_to_pool(self, addrmask):
        self._logger.debug('Add network {} to pool'.format(addrmask))
        for addr in _calculate_address_pool(addrmask):
            if addr in self._pool:
                continue
            self._pool.append(addr)
            self._available.append(addr)
        if self._sortflag:
           self._pool.sort()
           self._available.sort()

    def get_pool(self):
        return list(self._pool)

    def get_allocated(self):
        return list(self._allocated)

    def get_available(self):
        return list(self._available)

    def get_stats(self):
        """ Return a tuple of (Total/Allocated/Available) """
        return (len(self._pool), len(self._allocated), len(self._available))

    def in_pool(self, addr):
        return (addr in self._pool)

    def in_allocated(self, addr):
        return (addr in self._allocated)

    def in_available(self, addr):
        return (addr in self._available)

    def allocate(self):
        try:
            addr = self._available.pop(0)
            self._allocated.append(addr)
            return addr
        except:
            return None
        finally:
            if self._sortflag:
                self._available.sort()
                self._allocated.sort()

    def allocate_random(self):
        try:
            n = random.randrange(len(self._available))
            addr = self._available.pop(n)
            self._allocated.append(addr)
            return addr
        except:
            return None
        finally:
            if self._sortflag:
                self._available.sort()
                self._allocated.sort()

    def release(self, addr):
        self._allocated.remove(addr)
        self._available.append(addr)
        if self._sortflag:
           self._allocated.sort()
           self._available.sort()
        return addr

# Define AddressPoolUnit in use
_AddressPoolUnit = _AddressPoolUnit_list #Extracts a controlled element
#_AddressPoolUnit = _AddressPoolUnit_set #Extracts a random element
