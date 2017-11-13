import logging
import time
import pprint

from aalto_helpers import container3
from aalto_helpers import utils3
from aalto_helpers import network_helper3

KEY_DNS_IPADDR = 0
KEY_DNS_NCID = 1


class uReputation(object):
    # These values define penalty/reward factor for higher loads of traffic
    # The factor is used as the exponent using the total number of events as the base
    OK_FACTOR = 0
    NOK_FACTOR = 0.15
    NEUTRAL_FACTOR = 0
    # Define an initial reputation value when we do not have any data
    UNKNOWN_REPUTATION = 0.45

    def __init__(self, identifier, ok=0, nok=0, neutral=0):
        self.identifier = identifier
        self.ok = ok
        self.nok = nok
        self.neutral = neutral
        self.total = ok + nok + neutral

    def event_ok(self):
        self.ok += 1
        self.total += 1

    def event_nok(self):
        self.nok += 1
        self.total += 1

    def event_neutral(self):
        self.neutral += 1
        self.total += 1

    @property
    def _ok_factor(self):
        # Define a ok_factor that rewards ok event
        return self.total ** self.OK_FACTOR

    @property
    def _nok_factor(self):
        # Define a nok_factor that penalizes nok events
        return self.total ** self.NOK_FACTOR

    @property
    def _neutral_factor(self):
        # Define a nok_factor that penalizes nok events
        return self.total ** self.NEUTRAL_FACTOR

    @property
    def reputation(self):
        ''' Calculate reputation value based only on locally recorded events '''
        try:
            rep = 0.5 * self._ok_factor * (self.ok / self.total) - \
                  0.5 * self._nok_factor * (self.nok / self.total) + \
                  uReputation.UNKNOWN_REPUTATION * self._neutral_factor
        except ZeroDivisionError as e:
            rep = self.UNKNOWN_REPUTATION

        # Adjust reputation values between [0,1]
        if rep <= 0:
            return 0
        elif rep >= 1:
            return 1
        else:
            return rep

    def __repr__(self):
        return 'identifier={} neutral={} ok={} nok={} reputation={:.3f}'.format(self.identifier, self.neutral, self.ok, self.nok, self.reputation)


class ReputationStateDNSNode(container3.ContainerNode):
    ''' This class stores the state information available for any DNS node (resolver or requestor) '''
    def __init__(self, **kwargs):
        super().__init__('ReputationStateDNSNode')

        # Set default attributes
        self.period_n = 0
        self.period_ts = time.time()
        self.tcp_capable = False
        self.supported_edns0 = []

        # Define weighted values for reputation calculation based on historic data
        self.weight_previous = 0.25
        self.weight_current = 0.75

        # Define initial values for reputation object
        self.init_rep_ok = 0
        self.init_rep_nok = 0
        self.init_rep_neutral = 5

        # Define values for lookupkeys
        ## EDNS0 Name Client Identifier
        self.ncid = ''
        ## IP source / EDNS0 ClientSubnet / Extended Client Information
        self.ipaddr = ''

        # Override attributes
        utils3.set_attributes(self, override=True, **kwargs)

        # Sanity check
        assert(self.ncid or self.ipaddr)

        # Create reputation object
        rep_identifier = '{}.#{}'.format(self.ipaddr, self.period_n)
        self.reputation_current = uReputation(identifier = rep_identifier,
                                              ok = self.init_rep_ok,
                                              nok = self.init_rep_nok,
                                              neutral = self.init_rep_neutral)
        ## Create previous reputation object same as current
        rep_identifier = '{}.#{}'.format(self.ipaddr, self.period_n - 1)
        self.reputation_previous = uReputation(identifier = rep_identifier,
                                              ok = self.init_rep_ok,
                                              nok = self.init_rep_nok,
                                              neutral = self.init_rep_neutral)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        keys = []
        if self.ipaddr:
            # Create unique key based on IP address literal
            keys.append(((KEY_DNS_IPADDR, self.ipaddr), True))
        if self.ncid:
            # Create unique key based on IP address literal + Name Client Identifier
            keys.append(((KEY_DNS_NCID, self.ipaddr, self.ncid), True))
            # Create non-unique key based on IP address literal for Name Client Identifiers
            keys.append(((KEY_DNS_NCID, self.ipaddr), False))
        return keys

    def transition_period(self):
        # Transition to next period
        self.period_n += 1
        self.period_ts = time.time()
        self.reputation_previous = self.reputation_current

        # Create reputation object for current period with weighted values
        ok = self.reputation_previous.ok * self.weight_previous
        nok = self.reputation_previous.nok * self.weight_previous
        ## Adjust neutral to at least a minimum value
        neutral = max(self.reputation_previous.neutral * self.weight_previous, self.init_rep_neutral)

        rep_identifier = '{}.#{}'.format(self.ipaddr, self.period_n)

        self.reputation_current = uReputation(identifier = rep_identifier,
                                              ok = int(ok),
                                              nok = int(nok),
                                              neutral = int(neutral))

    @property
    def reputation(self):
        return self.weight_previous * self.reputation_previous.reputation + \
               self.weight_current * self.reputation_current.reputation

    def event_ok(self):
        self.reputation_current.event_ok()

    def event_nok(self):
        self.reputation_current.event_nok()

    def event_neutral(self):
        self.reputation_current.event_neutral()

    def __repr__(self):
        return '[{}] ipaddr={} ncid={} / reputation previous={:.3f} current={:.3f} weighted_avg={:.3f}'.format(self.period_n, self.ipaddr, self.ncid,
                                                                                                          self.reputation_previous.reputation,
                                                                                                          self.reputation_current.reputation,
                                                                                                          self.reputation)
    def dump(self):
        return self.__repr__()

    def debug(self):
        print(self)
        print('  >> previous: {}'.format(self.reputation_previous))
        print('  >> current:  {}'.format(self.reputation_current))


class ReputationStateDataNode(object):
    pass

class PolicyBasedResourceAllocation(container3.Container):
    '''
    Develop this class to be triggered from: https://gitlab.cloud.mobilesdn.org/CES/customer_edge_switching_v2/blob/master/src/callbacks.py#L323
    '''

    def __init__(self, name='PolicyBasedResourceAllocation'):
        ''' Initialize as a Container '''
        super().__init__(name)


    def load_metadata_query(self, query, addr):
        ''' Parse DNS query and load reputation objects '''
        # Collect metadata from DNS query related to resolver
        ipaddr = addr[0]
        if not self.has((KEY_DNS_IPADDR, ipaddr)):
            self._logger.info('Create ReputationStateDNSNode for resolver ipaddr={}'.format(ipaddr))
            meta_resolver = ReputationStateDNSNode(ipaddr = ipaddr)
            self.add(meta_resolver)
        # Get existing object
        meta_resolver = self.get((KEY_DNS_IPADDR, ipaddr))

        # Collect metadata from DNS query related to requestor
        meta_requestor = None
        meta_ipaddr = None
        meta_ncid = None

        for opt in query.options:
            if opt.otype == 0x08 and meta_ipaddr is None:
                #ClientSubnet
                meta_ipaddr = opt.address
            elif opt.otype == 0xff01:
                #ExtendedClientInformation (preferred)
                meta_ipaddr = opt.address
            elif opt.otype == 0xff02:
                #ExtendedClientInformation
                meta_ncid = opt.id_data

        if meta_ipaddr or meta_ncid:
            if not self.has((KEY_DNS_NCID, meta_ipaddr, meta_ncid)):
                self._logger.info('Create ReputationStateDNSNode for requestor ipaddr={} ncid={}'.format(meta_ipaddr, meta_ncid))
                meta_requestor = ReputationStateDNSNode(ipaddr = meta_ipaddr, ncid = meta_ncid)
                self.add(meta_requestor)
            # Get existing object
            meta_requestor = self.get((KEY_DNS_NCID, meta_ipaddr, meta_ncid))

        # Attach reputation object as metadata to the DNS query
        query.reputation_resolver = meta_resolver
        query.reputation_requestor = meta_requestor

    def process_data_packet(self, packet):
        pass


def generate_ok(obj, n):
    for _ in range(n):
        obj.event_ok()
        print(obj)

def generate_nok(obj, n):
    for _ in range(n):
        obj.event_nok()
        print(obj)

def generate_neutral(obj, n):
    for _ in range(n):
        obj.event_neutral()
        print(obj)


if __name__ == "__main__":
    '''
    obj = uReputation('test1')
    print(obj)
    generate_neutral(obj, 3)

    generate_nok(obj, 10)
    generate_ok(obj, 10)

    obj = uReputation('test2')
    print(obj)
    generate_ok(obj, 20)

    generate_nok(obj, 20)
    generate_neutral(obj, 20)

    obj = uReputation('test3', nok=0, neutral=10)
    print(obj)
    generate_nok(obj, 10)
    generate_ok(obj, 30)
    print(obj)
    '''

    pbra = PolicyBasedResourceAllocation()

    obj1 = ReputationStateDNSNode(ipaddr = '1.2.3.4')

    pbra.add(obj1)

    print(obj1.reputation_previous)
    print(obj1.reputation_current)

    generate_nok(obj1, 10)
    obj1.debug()

    generate_ok(obj1, 10)
    obj1.debug()

    obj1.transition_period()
    obj1.debug()
    obj1.transition_period()
    obj1.debug()
    obj1.transition_period()
    obj1.debug()

    generate_ok(obj1, 10)
    obj1.transition_period()
    obj1.debug()

    generate_ok(obj1, 10)
    obj1.transition_period()
    obj1.debug()

    print(pbra.dump())

    from customdns import edns0

    import dns
    import dns.message
    import socket

    custom_options = [edns0.EDNS0_ECSOption('198.18.0.0', 24, 0),
                      edns0.EDNS0_EClientInfoOption('198.18.0.100', 17, 12345),
                      edns0.EDNS0_EClientID(b'\xde\xad\xbe\xef')]
    fqdn = 'leaf.nsfw.example.com'
    msg = dns.message.make_query(fqdn, 1, 1, use_edns=True, options=custom_options)

    pbra.load_metadata_query(msg, ('8.8.8.8', 12345))
    print(msg.reputation_resolver)
    print(msg.reputation_requestor)
