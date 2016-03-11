import asyncio
import aiohttp
import json

import container3
import logging

LOGLEVELNETWORK = logging.WARNING
LOGLEVELCONNECTION = logging.WARNING

KEY_CESLOCAL = 1
KEY_CESPUBLIC = 2

class Network(object):
    def __init__(self, loop, name='Network', **kwargs):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELNETWORK)
        
        self._loop = loop
        self._ports = {}
        
        self._ports['lan']  = kwargs['lan']
        self._ports['wan']  = kwargs['wan']
        self._ports['vtep'] = kwargs['vtep']
        
        self._sdn = kwargs['sdn']
        
        # Create Session with keepalive to reduce request time
        self._session = aiohttp.ClientSession(loop=loop)
        
        print(kwargs)
    
    def create_tunnel(self):
        pass
    
    def delete_tunnel(self):
        pass
    
    def create_connection(self, connection):
        
        if isinstance(connection, ConnectionCESLocal):
            msgs = self._flow_add_local(connection)
            
            for m in msgs:
                print('Sending...\n',m)
                self._loop.create_task(self._sdn_api_post(self._session, self._sdn['add'], m))
                        
    
    def delete_connection(self, connection):
        pass
    
    def _flow_add_local(self, conn):
        #TODO: Add timeouts
        
        mac_src = '00:00:00:00:00:00'
        mac_dst = self._ports['vtep']['mac']
        
        msg1 = {}
        msg1['dpid'] = 1
        msg1['table_id'] = 1
        msg1['priority'] = 1
        msg1['flags'] = 1
        msg1['match'] = {'eth_type':2048, 'ipv4_src':conn.src, 'ipv4_dst':conn.psrc}
        msg1['actions'] = [
                           {'type':'SET_FIELD', 'field':'ipv4_src', 'value':conn.pdst},
                           {'type':'SET_FIELD', 'field':'ipv4_dst', 'value':conn.dst},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_dst},
                           {'type':'OUTPUT', 'port':4294967288}
                           ]
        
        msg2 = {}
        msg2['dpid'] = 1
        msg2['table_id'] = 1
        msg2['priority'] = 1
        msg2['flags'] = 1
        msg2['match'] = {'eth_type':2048, 'ipv4_src':conn.dst, 'ipv4_dst':conn.pdst}
        msg2['actions'] = [{'type':'SET_FIELD', 'field':'ipv4_src', 'value':conn.psrc},
                           {'type':'SET_FIELD', 'field':'ipv4_dst', 'value':conn.src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_dst},
                           {'type':'OUTPUT', 'port':4294967288}
                           ]
        
        return [json.dumps(msg1), json.dumps(msg2)]
        
    @asyncio.coroutine
    def _sdn_api_get(self, session, url, data): 
        response = yield from session.get(url, data=data)
        yield from response.release()
        return response
    
    @asyncio.coroutine
    def _sdn_api_post(self, session, url, data): 
        response = yield from session.post(url, data=data)
        yield from response.release()
        return response
    
    @asyncio.coroutine
    def _sdn_api_delete(self, session, url, data): 
        response = yield from session.delete(url, data=data)
        yield from response.release()
        return response
    

class ConnectionContainer(container3.Container):
    
    def __init__(self, name='ConnectionContainer'):
        """ Initialize the ConnectionContainer as a Container """
        super().__init__(name, LOGLEVELCONNECTION)

class ConnectionCESLocal(container3.ContainerNode):
    def __init__(self, name='ConnectionCESLocal', **kwargs):
        """ Initialize the ConnectionCESLocal as a ContainerNode """
        super().__init__(name, LOGLEVELCONNECTION)
        # Set parameters
        for k,v in kwargs.items():
            print('setattr({},{})'.format(k, v))
            setattr(self, k, v)
        
        '''
        # IP addresses
        src, psrc, dst, pdst
        # FW Rules are a combination of (direction, rules) for both hosts
        TBD
        '''
    
    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return (((self.src, self.psrc), False),
                ((self.dst, self.pdst), False))
        

class ConnectionCESPublic(container3.ContainerNode):
    def __init__(self, name='ConnectionCESPublic', **kwargs):
        """ Initialize the ConnectionCESPublic as a ContainerNode """
        super().__init__(name, LOGLEVELCONNECTION)
    
    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, False),)