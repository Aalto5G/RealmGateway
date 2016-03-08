#!/usr/bin/python3.5

import asyncio
import addresspool
import configparser
import logging
import signal
import sys
import traceback


LOGLEVELCES = logging.WARNING

class CustomerEdgeSwitch(object):
    def __init__(self, name='CustomerEdgeSwitch'):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELCES)
        
        # Get event loop
        self._loop = asyncio.get_event_loop()
        
        # Enable debugging
        self._set_verbose()
        
        # Capture signals
        self._capture_signal()
        
        # Read configuration
        self._config = self._load_configuration('ces.cfg')
        
        # Initialize Address Pools
        self._init_address_pools()
        
        
    
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            self._loop.add_signal_handler(getattr(signal, signame), self._signal_handler, signame)
    
    def _load_configuration(self, filename):
        config = configparser.ConfigParser()
        config.read_file(open(filename,'r'))
        
        print(config.__dict__)
        return config
    
    def _init_address_pools(self):
        # Create container of Address Pools
        self._addresspoolcontainer = addresspool.AddressPoolContainer()
        # Create specific Address Pools
        pass
    
    def _init_dns_servers(self):
        pass
    
    def _set_verbose(self):
        self._logger.warning('Enabling logging.DEBUG')
        logging.basicConfig(level=logging.DEBUG)
        self._loop.set_debug(True)
        
    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        self._loop.stop()
    
    def begin(self):
        print('CESv2 is starting...')



if __name__ == '__main__':
    try:
        ces = CustomerEdgeSwitch()
        ces.begin()
    except Exception:
        print('Exception in user code:')
        print('-' * 60)
        traceback.print_exc(file=sys.stdout)
        print('-' * 60)
    finally:
        loop = asyncio.get_event_loop()
        loop.close()
    print('Bye!')
