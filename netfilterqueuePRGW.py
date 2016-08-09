from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

import sys
import random

class NetfilterRGW(object):
    def __init__(self, queue, mark):
        print('Binding to queue {} and mark {}'.format(queue, mark))
        self.queue = queue
        self.mark = mark
        self._nfqueue = NetfilterQueue()
        self._nfqueue.bind(queue, self.callback)

    def callback(self, pkt):
        data = pkt.get_payload()
        ip = IP(data)
        print('#{}: {}'.format(self.queue, ip.summary()))
        pkt.set_mark(self.mark)
        pkt.accept()
        print('>> Set mark {}'.format(mark))

    def run(self):
        try:
            self._nfqueue.run()
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
        self._nfqueue.unbind()


if __name__ == '__main__':
    try:
        nqueue = sys.argv[1]
        mark   = sys.argv[2]
    except Exception as e:
        print('sudo python{python3} netfilterqueuePRGW.py queueNum pktMark')
        print(sys.argv)
        sys.exit()
    
    nfrgw = NetfilterRGW(int(nqueue), int(mark))
    nfrgw.run()
