##########################################################################
##                             c o n t a i n e r 3                      ##
##########################################################################

# This module defines a generic Container class and ContainerNode unit

#TODO: Replace %s with python3 style {}.format

import logging

LOGLEVELCONTAINER = logging.INFO
LOGLEVELNODE = logging.INFO


class Container(object):

    def __init__(self, name="Container", loglevel=LOGLEVELCONTAINER):
        """
        Initialize the Container.
        """
        self._version = 0.4
        self._logger = logging.getLogger(name)
        self._logger.setLevel(loglevel)
        self._name = name
        self._dict = {}             # Indexes lookup keys to nodes
        self._list = []             # Stores a list of indexed nodes
        self._dict_id2keys = {}     # Indexes node ids to registered keys

    def add(self, node):
        """
        Add a ContainerNode to the Container.

        @param node: The node
        """
        if node in self._list:
            raise KeyError('Failed to add. Node exists in list %s')

        for key, isalist in node.lookupkeys():
            # The key is not unique - append to list
            if isalist:
                if key not in self._dict:
                    self._dict[key] = []
                if node in self._dict[key]:
                    raise KeyError(
                        'Failed to add. Node exists in dictionary %s' %
                        (self._dict[key]))
                self._dict[key].append(node)

            # Check the unique key is not already in use
            elif key in self._dict:
                raise KeyError(
                    'Failed to add. Node exists in dictionary %s' %
                    (self._dict[key]))

            # Add the unique key to the dictionary
            else:
                self._dict[key] = node

        # Add node to the list
        self._list.append(node)
        self._list.sort(key=lambda x: x.getsortkey())
        self._logger.debug('Adding <%s>' % (node))

        # Add node lookup keys to a dictionary - Map node id to lookup keys
        self._dict_id2keys[id(node)] = node.lookupkeys()

    def get(self, key, update=True):
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
        Returns a shallow copy of the internal list node
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
        try:
            if callback:
                node.delete()
            for key, isalist in node.lookupkeys():
                if isalist:
                    self._dict[key].remove(node)
                    # The list has no more nodes, remove
                    if len(self._dict[key]) == 0:
                        del self._dict[key]
                else:
                    del self._dict[key]
            self._list.remove(node)
            del self._dict_id2keys[id(node)]
            self._logger.debug('Removing <%s>' % (node))
        except Exception as ex:
            self._logger.warning(
                'Failed while removing <%s>: %s' %
                (node, str(ex)))
            pass
        
    def removeall(self, instance=None):
        self._dict_id2keys.clear()
        self._dict.clear()
        self._list[:] = []

    

    def updatekeys(self, node):
        # Remove previous keys
        oldKeys = self._dict_id2keys[id(node)]
        try:
            for key, isalist in oldKeys:
                if isalist:
                    self._dict[key].remove(node)
                    # The list has no more nodes, remove
                    if len(self._dict[key]) == 0:
                        del self._dict[key]
                else:
                    del self._dict[key]
            del self._dict_id2keys[id(node)]
            self._logger.debug('Removing keys for <%s>' % (node))
        except Exception as ex:
            self._logger.warning(
                'Failed while removing keys for <%s>: %s' %
                (node, str(ex)))
            return

        # Register new keys
        newKeys = node.lookupkeys()
        for key, isalist in newKeys:
            # The key is not unique - append to list
            if isalist:
                if key not in self._dict:
                    self._dict[key] = []
                if node in self._dict[key]:
                    raise KeyError(
                        'Failed to add. Node exists in dictionary %s' %
                        (self._dict[key]))
                self._dict[key].append(node)

            # Check the unique key is not already in use
            elif key in self._dict:
                raise KeyError(
                    'Failed to add. Node exists in dictionary %s' %
                    (self._dict[key]))

            # Add the unique key to the dictionary
            else:
                self._dict[key] = node

        # Add node lookup keys to a dictionary - Map node id to lookup keys
        self._dict_id2keys[id(node)] = newKeys

    def __len__(self):
        """ Returns the length of the internal list node """
        return len(self._list)

    def __repr__(self):
        return '\n'.join([str(node) for node in self._list])


class ContainerNode(object):

    def __init__(self, name="Node", loglevel=LOGLEVELNODE):
        """ Initialize the ContainerNode """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(loglevel)

    def lookupkeys(self):
        """ Return the lookup keys of the node """
        key = ()
        isalist = False
        return ((key, isalist),)

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

    def getsortkey(self):
        """
        Sort the Container list when an node is added
        """
        return 0
