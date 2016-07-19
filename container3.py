##########################################################################
##                             c o n t a i n e r 3                      ##
##########################################################################

# This module defines a generic Container class and ContainerNode unit

import logging

LOGLEVELCONTAINER = logging.INFO
LOGLEVELNODE = logging.INFO


class Container(object):

    def __init__(self, name="Container", loglevel=LOGLEVELCONTAINER):
        """
        Initialize the Container.
        """
        self._version = 0.5
        self._logger = logging.getLogger(name)
        self._logger.setLevel(loglevel)
        self._name = name
        self._dict = {}             # Indexes lookup keys to nodes
        self._list = set()          # Stores a set of indexed nodes
        self._dict_id2keys = {}     # Indexes node ids to registered keys

    def _add_lookupkeys(self, node, keys):
        for key, isunique in keys:
            # The key is not unique - create a set of items for key
            if not isunique:
                if key not in self._dict:
                    self._dict[key] = set()
                self._dict[key].add(node)
            # Check the unique key is not already in use
            elif key in self._dict:
                raise KeyError('Failed to add: key {} already exists in dictionary for node {}'.format(key, self._dict[key]))
            # Add the unique key to the dictionary
            else:
                self._dict[key] = node

    def _remove_lookupkeys(self, node, keys):
        for key, isunique in keys:
            # The key is not unique - remove from set of items for key
            if not isunique:
                self._dict[key].remove(node)
                # The set has no more items, remove set
                if len(self._dict[key]) == 0:
                    del self._dict[key]
            # Check the unique key is already in use
            elif key not in self._dict:
                raise KeyError('Failed to remove: key {} does not exists in dictionary for node {}'.format(key, node))
            # Add the unique key to the dictionary
            else:
                del self._dict[key]

    def add(self, node):
        """
        Add a ContainerNode to the Container.

        @param node: The node
        """
        if node in self._list:
            raise Exception('Failed to add: node already exists {}'.format(node))

        # Register node lookup keys
        keys = node.lookupkeys()
        self._add_lookupkeys(node, keys)
        # Map node id to lookup keys
        self._dict_id2keys[id(node)] = keys
        # Add node to the set
        self._list.add(node)
        self._logger.debug('Added node {}'.format(node))

    def get(self, key, update=False):
        """
        Obtain a node with the given key.

        @param key: The values of the node.
        @param update: If activated, update the node.
        @return: The node node or KeyError if not found
        """
        node = self._dict[key]
        if update:
            node.update()
        return node

    def getall(self):
        """
        Returns a shallow copy of the internal set
        """
        return list(self._list)

    def has(self, key, check_expire=True):
        """
        Check if there is a node with the given key

        @param key: The values of the node.
        @param check_expire: If activated, check for expired node.
        @return: True if there is a node.
        """
        try:
            node = self._dict[key]
            if not isinstance(node, ContainerNode):
                return True
            if check_expire and node.hasexpired():
                self.delete(node)
                return False
            return True
        except KeyError:
            return False

    def lookup(self, key, update=True, check_expire=True):
        """
        Look up a node with the given key.

        @param key: The values of the node.
        @param update: If activated, update the node.
        @param check_expire: If activated, check for expired node.
        @return: The node node.
        """
        try:
            node = self._dict[key]
            if not isinstance(node, ContainerNode):
                return node
            if check_expire and node.hasexpired():
                self.remove(node)
            if update:
                node.update()
            return node
        except KeyError:
            return None

    def remove(self, node, callback=True):
        """
        Remove an node from the Storage node.

        @param node: The node
        """
        # Remove node lookup keys
        keys = node.lookupkeys()
        self._remove_lookupkeys(node, keys)
        # Remove map node id to lookup keys
        del self._dict_id2keys[id(node)]
        # Remove node from the set
        self._list.remove(node)
        self._logger.debug('Removed node {}'.format(node))
        # Evaluate callback to ContainerNode item
        if callback:
            self._logger.debug('Delete callback for node {}'.format(node))
            node.delete()

    def removeall(self, callback=True):
        # Iterate all nodes in the set and remove them
        for node in self._list:
            self.remove(node, callback)
        # Sanity clear
        self._dict_id2keys.clear()
        self._dict.clear()
        self._list.clear()

    def updatekeys(self, node):
        # Get lookup keys
        old_keys = self._dict_id2keys[id(node)]
        new_keys = node.lookupkeys()
        # Remove previous keys
        self._remove_lookupkeys(node, old_keys)
        # Remove map node id to lookup keys
        del self._dict_id2keys[id(node)]
        # Register node lookup keys
        self._add_lookupkeys(node, new_keys)
        # Map node id to lookup keys
        self._dict_id2keys[id(node)] = new_keys
        self._logger.debug('Updated keys for node {}'.format(node))

    def __len__(self):
        """ Returns the length of the internal list node """
        return len(self._list)

    def __repr__(self):
        return '\n'.join(['{}'.format(node) for node in self._list])


class ContainerNode(object):

    def __init__(self, name="Node", loglevel=LOGLEVELNODE):
        """ Initialize the ContainerNode """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(loglevel)
        self._name = name

    def lookupkeys(self):
        """ Return the lookup keys of the node """
        key = self._name
        isunique = True
        return ((key, isunique),)

    def hasexpired(self):
        """ Return True if the TTL of the node has expired """
        return False

    def update(self):
        """
        Perform additional actions when the node is being updated.
        """
        pass

    def delete(self):
        """
        Perform additional actions when the node is being deleted.
        """
        pass


if __name__ == "__main__":
    ct = Container()
    cn1 = ContainerNode('cn1')
    ct.add(cn1)
    cn2 = ContainerNode('cn2')
    ct.add(cn2)
    print(ct)