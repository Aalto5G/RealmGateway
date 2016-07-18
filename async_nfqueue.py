#!/usr/bin/python3.5

from netfilterqueue import NetfilterQueue
import functools
import asyncio

class AsyncNFQueue(object):
    def __init__(self, queue, callback = None):
        print('Binding to netfilterqueue {}'.format(queue))
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
        print('#{}: {}'.format(self.queue, data))
        pkt.drop()

    def set_callback(self, callback):
        self._nfqueue.unbind()
        self._nfqueue.bind(self.queue, callback)

    def terminate(self):
        self._loop.remove_reader(self._nfqueue_fd)
        self._nfqueue.unbind()
