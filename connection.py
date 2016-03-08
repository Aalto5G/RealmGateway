import container3
import logging

LOGLEVELCONNECTION = logging.WARNING


class ConnectionContainer(container3.Container):
    
    def __init__(self, name='ConnectionContainer'):
        """ Initialize the ConnectionContainer as a Container """
        super().__init__(name, LOGLEVELCONNECTION)

class ConnectionCES(container3.ContainerNode):
    def __init__(self, name='ConnectionCES'):
        """ Initialize the ConnectionCES as a ContainerNode """
        super().__init__(name, LOGLEVELCONNECTION)
    
    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, False),)
