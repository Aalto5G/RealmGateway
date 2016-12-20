#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue
import asyncio
import functools
import logging
import sys

class AsyncNFQueue(object):
    def __init__(self, queue, callback = None):
        self.logger = logging.getLogger('AsyncNFQueue#{}'.format(queue))
        self.logger.info('Bind queue #{}'.format(queue))
        self._loop = asyncio.get_event_loop()
        self.queue = queue
        # Create NetfilterQueue object
        self._nfqueue = NetfilterQueue()
        # Bind to queue and register callback
        if callback is None:
            callback = self._nfcallback
        self._nfqueue.bind(self.queue, callback)
        # Register queue with asyncio
        self._nfqueue_fd = self._nfqueue.get_fd()
        # Create callback function to execute actual nfcallback
        cb = functools.partial(self._nfqueue.run, block=False)
        self._loop.add_reader(self._nfqueue_fd, cb)

    def _nfcallback(self, pkt):
        data = pkt.get_payload()
        self.logger.info('Received ({} bytes): {}'.format(len(data), data))
        pkt.drop()

    def set_callback(self, callback):
        self.logger.info('Set callback to {}'.format(callback))
        self._nfqueue.unbind()
        self._nfqueue.bind(self.queue, callback)

    def terminate(self):
        self.logger.info('Unbind queue #{}'.format(self.queue))
        self._loop.remove_reader(self._nfqueue_fd)
        self._nfqueue.unbind()

if __name__ == '__main__':
    # Configure logging
    log = logging.getLogger('')
    format = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)
    log.setLevel(logging.DEBUG)
    # Instantiate loop
    loop = asyncio.get_event_loop()
    # Create AsyncNFQueue object
    nfqueue = AsyncNFQueue(int(sys.argv[1]))
    try:
        loop.run_forever()
    except:
        nfqueue.terminate()
    loop.close()
