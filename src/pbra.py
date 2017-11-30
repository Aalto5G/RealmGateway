import logging
import time
from functools import partial

import ipaddress

from aalto_helpers import container3
from aalto_helpers import utils3

import host
from host import KEY_SERVICE_SFQDN

import connection
from connection import ConnectionLegacy

import dns
import dns.message
import dns.rcode

from dns.rdataclass import *
from dns.rdatatype import *

# Control variables
PBRA_DNS_ANTI_SPOOFING = False # Enable TCPCNAME policy
PBRA_DNS_LOAD_POLICING = True # Use load scaling for fine policy enforcement
PBRA_DNS_LOG_UNTRUSTED = True # Log all DNS query attempts (UDP untrusted)

# Keys for uStateDNSResolver
KEY_DNSNODE_IPADDR  = 10
KEY_DNSHOST_NCID    = 11

# Keys for uStateDNSGroup
KEY_DNSGROUP        = 20
KEY_DNSGROUP_ID     = 21
KEY_DNSGROUP_IPADDR = 22

# Keys for uDNSQueryTimer
KEY_TIMER           = 30
KEY_TIMER_FQDN      = 31

# Keys for uStateDNSHost
KEY_DNSHOST_IPADDR  = 40


#HACK: Added this to define initial reputation value
INITIAL_REPUTATION = {'init_rep_ok': 1, 'init_rep_nok': 3, 'init_rep_neutral':5}

# Load levels in 100% (Use -1 value to disable step)
##SYSTEM_LOAD_POLICY    = (load_threshold, reputation_fqdn, reputation_sfqdn)
SYSTEM_LOAD_VERY_HIGH = (-1, -1, 0.80)
SYSTEM_LOAD_HIGH      = (-1, 0.75, 0.60)
SYSTEM_LOAD_MEDIUM    = (-1, 0.50, 0.30)
SYSTEM_LOAD_LOW       = ( 0, 0, 0)
SYSTEM_LOAD_ENABLED   = lambda x: x>=0


class uReputation(object):
    # TODO: Add counters for trusted event, untrusted event ?

    # These values define penalty/reward factor for higher loads of traffic
    # The factor is used as the exponent using the total number of events as the base
    OK_FACTOR = 0
    NOK_FACTOR = 0.15
    NEUTRAL_FACTOR = 0
    # Define an initial reputation value when we do not have any data
    UNKNOWN_REPUTATION = 0.45

    def __init__(self, name, ok=0, nok=0, neutral=0, trusted=0, untrusted=0):
        self.name = name
        self.ok = ok
        self.nok = nok
        self.neutral = neutral
        self.trusted = trusted
        self.untrusted = untrusted
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

    def event_trusted(self):
        self.trusted += 1

    def event_untrusted(self):
        self.untrusted += 1

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
        """ Calculate reputation value based only on locally recorded events """
        try:
            rep = 0.5 * self._ok_factor * (self.ok / self.total) - \
                  0.5 * self._nok_factor * (self.nok / self.total) + \
                  uReputation.UNKNOWN_REPUTATION * self._neutral_factor
        except ZeroDivisionError as e:
            rep = self.UNKNOWN_REPUTATION

        # Normalize reputation values between [0,1]
        if rep <= 0:
            return 0
        elif rep >= 1:
            return 1
        else:
            return rep

    def merge(self, other):
        # Merge self reputation values with other
        [self.event_ok()        for i in range(other.ok)]
        [self.event_nok()       for i in range(other.nok)]
        [self.event_neutral()   for i in range(other.neutral)]
        [self.event_trusted()   for i in range(other.trusted)]
        [self.event_untrusted() for i in range(other.untrusted)]

    def __repr__(self):
        return '[{}] neutral={} ok={} nok={} reputation={:.3f} / trusted={} untrusted={}'.format(self.name, self.neutral, self.ok, self.nok, self.reputation, self.trusted, self.untrusted)


class uDNSQueryTimer(container3.ContainerNode):
    TIMEOUT = 8.0

    def __init__(self, query, ipaddr, fqdn, service, timeout=0):
        """ Initialize as a ContainerNode """
        # Initialize super
        super().__init__('uDNSQueryTimer')
        self.query = query
        self.ipaddr = ipaddr
        self.fqdn = fqdn
        self.service = service
        self.timeout = timeout
        # Set default timeout if not overriden
        if not self.timeout:
            self.timeout = uDNSQueryTimer.TIMEOUT
        # Take creation timestamp
        self.timestamp_zero = time.time()
        self.timestamp_eol = self.timestamp_zero + self.timeout

    def hasexpired(self):
        """ Return True if the timeout has expired """
        return time.time() > self.timestamp_eol

    def lookupkeys(self):
        """ Return the lookup keys """
        return [((KEY_TIMER), False),
                ((KEY_TIMER_FQDN, self.fqdn), True)]

    def show(self):
        # Pretty(ier) print of the host information
        print('### uDNSQueryTimer ##')
        #print('> Query: {}'.format(self.query))
        print('> Resolver: {}'.format(self.ipaddr))
        print('> FQDN: {}'.format(self.fqdn))
        print('> Service: {}'.format(self.service))
        print('> Lookupkeys: {}'.format(self.lookupkeys()))
        print('################')

    def __repr__(self):
        return '[{}] resolver={} fqdn={} service={} timeout={} sec'.format(self._name, self.ipaddr, self.fqdn, self.service, self.timeout)

class uStateDNSHost(container3.ContainerNode):
    """ This class stores the state information representing a requestor DNS node """
    def __init__(self, **kwargs):
        super().__init__('uStateDNSHost')

        # This class defines a DNS advertised node via EDNS0 ClientSubnet / Extended Client Information / Name Client Identifier
        # This object

        ## IP source / EDNS0 ClientSubnet / Extended Client Information
        self.ipaddr      = None
        self.ipaddr_mask = 32

        ## EDNS0 Name Client Identifier -> Tuple of (tag_id, server_ipaddr)
        self.ncid        = (None, None)

        # Override attributes
        utils3.set_attributes(self, override=True, **kwargs)

        ## Convert IPaddr/mask to network address
        self._ipaddr = ipaddress.ip_network('{}/{}'.format(self.ipaddr, self.ipaddr_mask), strict=False)
        # Overwrite ipaddr with network address
        self.ipaddr = format(self._ipaddr.network_address)

        # Sanity check
        #assert(self.ncid or self.ipaddr)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        keys = []
        # Typical keys of an advertised DNS host and data host
        keys.append(((KEY_DNSHOST_IPADDR, self.ipaddr), True))
        keys.append(((KEY_DNSHOST_NCID, self.ncid), True))
        return keys

    def contains(self, ipaddr):
        """ Return True if ipaddr exists in the defined network """
        return ipaddress.ip_address(ipaddr) in self._ipaddr

    def __repr__(self):
        return '[{}] ipaddr={} ipaddr_mask={} ncid={}@{}'.format(self._name, self.ipaddr, self.ipaddr_mask, self.ncid[0], self.ncid[1])


class uStateDNSResolver(container3.ContainerNode):
    """ This class stores the state information available for any DNS resolver node """
    def __init__(self, **kwargs):
        super().__init__('uStateDNSResolver')
        # Set default attributes
        self.edns0_cookie = None
        self.supported_edns0 = []
        self.ipaddr = None
        # Override attributes
        utils3.set_attributes(self, override=True, **kwargs)
        # Sanity check
        assert(self.ipaddr is not None)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        keys = []
        # Create unique key based on IP address literal
        keys.append(((KEY_DNSNODE_IPADDR, self.ipaddr), True))
        return keys

    def __repr__(self):
        return '[{}] ipaddr={}'.format(self._name, self.ipaddr)


class uStateDNSGroup(container3.ContainerNode):
    """ This class stores the state information available for any DNS node (resolver or requestor) """
    def __init__(self, **kwargs):
        super().__init__('uStateDNSGroup')

        # Set default attributes
        self.period_n = 0
        self.period_ts = time.time()

        # Define weighted values for reputation calculation based on historic data
        self.weight_previous = 0.25
        self.weight_current = 0.75

        # Define initial values for reputation object
        self.init_rep_ok = 0
        self.init_rep_nok = 0
        self.init_rep_neutral = 5

        # Define a list for uStateDNSResolver ipaddresses
        self.population = []

        # Override attributes
        utils3.set_attributes(self, override=True, **kwargs)

        # Create reputation object
        rep_identifier = '{}.#{}'.format(id(self), self.period_n)
        self.reputation_current = uReputation(rep_identifier,
                                              ok = self.init_rep_ok,
                                              nok = self.init_rep_nok,
                                              neutral = self.init_rep_neutral)
        ## Create previous reputation object same as current
        rep_identifier = '{}.#{}'.format(id(self), self.period_n - 1)
        self.reputation_previous = uReputation(rep_identifier,
                                               ok = self.init_rep_ok,
                                               nok = self.init_rep_nok,
                                               neutral = self.init_rep_neutral)

    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        keys = []
        for ipaddr in self.population:
            # Create default key to index all same-element
            keys.append((KEY_DNSGROUP, False))
            # Create unique key based on ID of object
            keys.append(((KEY_DNSGROUP_ID, id(self)), True))
            # Create unique key based on IP address literal
            keys.append(((KEY_DNSGROUP_IPADDR, ipaddr), True))
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

        self.reputation_current = uReputation(rep_identifier,
                                              ok = int(ok),
                                              nok = int(nok),
                                              neutral = int(neutral))

    @property
    def id(self):
        return id(self)

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

    def event_trusted(self):
        self.reputation_current.event_trusted()

    def event_untrusted(self):
        self.reputation_current.event_untrusted()

    def __repr__(self):
        return '[{}] period={} ipaddrs={} / reputation previous={:.3f} current={:.3f} weighted_avg={:.3f}'.format(self._name, self.period_n, self.population,
                                                                                                          self.reputation_previous.reputation,
                                                                                                          self.reputation_current.reputation,
                                                                                                          self.reputation)

    def show_reputation(self):
        print(self)
        print('  >> previous: {}'.format(self.reputation_previous))
        print('  >> current:  {}'.format(self.reputation_current))

    def merge(self, other):
        self._logger.warning('Merging 2 DNS groups: {} / {}'.format(self, other))
        # Combine population
        for ipaddr in other.population:
            self.population.append(ipaddr)

        # Calculate last period value and transition reputations to catch up
        last_period_n = max(self.period_n, other.period_n)
        ## Age myself to catch up with last period
        for i in range(self.period_n, last_period_n):
            self.transition_period()
        ## Age other to catch up with last period
        for i in range(other.period_n, last_period_n):
            other.transition_period()

        # Update self reputation values with other
        ## Previous reputation period
        self.reputation_previous.merge(other.reputation_previous)
        ## Current reputation period
        self.reputation_current.merge(other.reputation_current)


class PolicyBasedResourceAllocation(container3.Container):
    """
    Develop this class to be triggered from DNSCallback and PacketCallbacks
    """
    #TODO: Create policy configuration and load it from file

    def __init__(self, **kwargs):
        """ Initialize as a Container """
        super().__init__('PolicyBasedResourceAllocation')
        # Override attributes
        utils3.set_attributes(self, override=True, **kwargs)
        self._init_system_load_policy()

    def _init_system_load_policy(self):
        # Initialize System Load Policy threshold values
        self.cpool_policy = self.datarepository.get_policy_ces('CIRCULARPOOL', None)

        global SYSTEM_LOAD_VERY_HIGH
        global SYSTEM_LOAD_HIGH
        global SYSTEM_LOAD_MEDIUM
        global SYSTEM_LOAD_LOW

        if self.cpool_policy is None:
            self._logger.warning('Using default SYSTEM_LOAD_POLICY values')
        else:
            self._logger.warning('Loading SYSTEM_LOAD_POLICY values from policy file')

            load_threshold = self.cpool_policy['SYSTEM_LOAD_POLICY']['VERYHIGH']['load_threshold']
            reputation_fqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['VERYHIGH']['reputation_fqdn']
            reputation_sfqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['VERYHIGH']['reputation_sfqdn']
            SYSTEM_LOAD_VERY_HIGH = (load_threshold, reputation_fqdn, reputation_sfqdn)

            load_threshold = self.cpool_policy['SYSTEM_LOAD_POLICY']['HIGH']['load_threshold']
            reputation_fqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['HIGH']['reputation_fqdn']
            reputation_sfqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['HIGH']['reputation_sfqdn']
            SYSTEM_LOAD_HIGH = (load_threshold, reputation_fqdn, reputation_sfqdn)

            load_threshold = self.cpool_policy['SYSTEM_LOAD_POLICY']['MEDIUM']['load_threshold']
            reputation_fqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['MEDIUM']['reputation_fqdn']
            reputation_sfqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['MEDIUM']['reputation_sfqdn']
            SYSTEM_LOAD_MEDIUM = (load_threshold, reputation_fqdn, reputation_sfqdn)

            load_threshold = self.cpool_policy['SYSTEM_LOAD_POLICY']['LOW']['load_threshold']
            reputation_fqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['LOW']['reputation_fqdn']
            reputation_sfqdn = self.cpool_policy['SYSTEM_LOAD_POLICY']['LOW']['reputation_sfqdn']
            SYSTEM_LOAD_LOW = (load_threshold, reputation_fqdn, reputation_sfqdn)

        self._logger.info('SYSTEM_LOAD_POLICY    = (load_threshold, reputation_fqdn, reputation_sfqdn)')
        self._logger.info('SYSTEM_LOAD_VERY_HIGH = {}'.format(SYSTEM_LOAD_VERY_HIGH))
        self._logger.info('SYSTEM_LOAD_HIGH      = {}'.format(SYSTEM_LOAD_HIGH))
        self._logger.info('SYSTEM_LOAD_MEDIUM    = {}'.format(SYSTEM_LOAD_MEDIUM))
        self._logger.info('SYSTEM_LOAD_LOW       = {}'.format(SYSTEM_LOAD_LOW))

    def cleanup_timers(self):
        """ Perform a cleanup of expired timer objects """
        # For debugging purposes
        self._debug_dnsgroups()

        nodes = self.lookup(KEY_TIMER, update=False, check_expire=False)
        if nodes is None:
            return
        for node in list(nodes):
            if node.hasexpired():
                self.remove(node)

    def _debug_dnsgroups(self):
        nodes = self.lookup(KEY_DNSGROUP, update=False, check_expire=False)
        if nodes is None:
            return
        [node.show_reputation() for node in nodes]

    def _policy_tcp(self, query):
        # Answer TRUNCATED
        response = dns.message.make_response(query, recursion_available=False)
        response.set_rcode(dns.rcode.NOERROR)
        response.flags |= dns.flags.TC
        return response

    def _policy_cname(self, query):
        # Answer CNAME
        fqdn = format(query.question[0].name)
        MAX_LENGTH_LABEL = 63
        _fqdn = utils3.random_string(MAX_LENGTH_LABEL) + '.' + fqdn
        ttl = 0
        response = dns.message.make_response(query, recursion_available=False)
        response.set_rcode(dns.rcode.NOERROR)
        response.answer = [dns.rrset.from_text(fqdn, ttl, 1, dns.rdatatype.CNAME, _fqdn)]
        return response, _fqdn

    def _load_metadata_resolver(self, query, addr, create=False):
        # Collect metadata from DNS query related to resolver based on IP address
        if self.has((KEY_DNSGROUP_IPADDR, addr[0])) is False and create is True:
            # Create resolver reputation of the DNS query
            ## Create new DNS node
            dnsnode_obj = uStateDNSResolver(ipaddr=addr[0])
            self.add(dnsnode_obj)
            ## Create new DNS group with single DNS node
            dnsgroup_obj = uStateDNSGroup()
            dnsgroup_obj.population.append(dnsnode_obj.ipaddr)
            self.add(dnsgroup_obj)
            # Add reputation to the DNS query
            query.reputation_resolver = dnsgroup_obj
            return
        else:
            # Add reputation to the DNS query
            dnsgroup_obj = self.lookup((KEY_DNSGROUP_IPADDR, addr[0]))
            query.reputation_resolver = dnsgroup_obj

    def _load_metadata_requestor(self, query, addr, create=False):
        # Collect metadata from DNS query related to requestor based on DNS options (EDNS0)
        dnshost_obj = None
        meta_ipaddr = None
        meta_ncid = None
        meta_flag = False

        for opt in query.options:
            self._logger.warning('Found EDNS0: {}'.format(opt.to_text()))
            if opt.otype == 0x08 and meta_ipaddr is None:
                # ClientSubnet
                meta_ipaddr = opt.address
                meta_mask   = opt.srclen
                meta_flag   = True
            elif opt.otype == 0xff01:
                # ExtendedClientInformation (preferred)
                meta_ipaddr = opt.address
                meta_mask   = 32
                meta_flag   = True
            elif opt.otype == 0xff02:
                # ExtendedClientInformation
                meta_ncid   = opt.id_data
                meta_flag   = True

        if meta_flag is False:
            query.reputation_requestor = None
            return

        ipaddr_lookupkey = format(ipaddress.ip_network('{}/{}'.format(meta_ipaddr, meta_mask), strict=False).network_address)
        ncid_lookupkey = (meta_ncid, addr[0]) # tuple of ncid tag and resolver IP address

        if self.has((KEY_DNSHOST_IPADDR, ipaddr_lookupkey)):
            # Get existing object
            dnshost_obj = self.get((KEY_DNSHOST_IPADDR, ipaddr_lookup))
            self._logger.info('Retrieved existing uStateDNSHost for requestor ipaddr={} ipaddr_mask={}'.format(meta_ipaddr, meta_mask))

        elif self.has((KEY_DNSHOST_IPADDR, ipaddr_lookupkey)) is False and create is True:
            self._logger.info('Create uStateDNSHost for requestor ipaddr={} ipaddr_mask={}'.format(meta_ipaddr, meta_mask))
            dnshost_obj = uStateDNSHost(ipaddr = meta_ipaddr, ipaddr_mask = meta_mask)
            self.add(dnshost_obj)

        # Needs to be tested
        elif self.has((KEY_DNSHOST_NCID, ncid_lookupkey)):
            # Get existing object
            dnshost_obj = self.get((KEY_DNSHOST_NCID, ncid_lookupkey))
            self._logger.info('Retrieved existing uStateDNSHost for requestor ncid={}@{}'.format(meta_ncid, addr[0]))

        elif self.has((KEY_DNSHOST_NCID, ncid_lookupkey)) is False and create is True:
            self._logger.info('Create uStateDNSHost for requestor ncid={}@{}'.format(meta_ncid, addr[0]))
            dnshost_obj = uStateDNSHost(ncid = ncid_lookupkey)
            self.add(dnshost_obj)

        # Add reputation to the DNS query
        query.reputation_requestor = dnshost_obj

    def dns_preprocess_rgw_wan_soa(self, query, addr, host_obj, service_data):
        """ This function implements section: Tackling real resolutions and reputation for remote server(s) and DNS clusters """
        fqdn = format(query.question[0].name)
        alias = service_data['alias']

        # Load available reputation metadata in query object
        self._load_metadata_resolver(query, addr, create=PBRA_DNS_LOG_UNTRUSTED)
        self._load_metadata_requestor(query, addr, create=False)

        # Log untrusted requests
        if PBRA_DNS_LOG_UNTRUSTED is True and alias is False and query.transport == 'udp':
            # Register an untrusted event
            if query.reputation_resolver is not None:
                query.reputation_resolver.event_untrusted()


        # Evaluate pre-conditions
        if PBRA_DNS_ANTI_SPOOFING is False:
            return None

        # Ensure spoofed-free communications by triggering TCP requests (by default right now)
        if alias is False and query.transport == 'udp':
            # Create truncated response
            response = self._policy_tcp(query)
            self._logger.info('Create TRUNCATED response')
            return response

        # TODO: Add a case when reputation is very high and UDP.cookie is found for resolver ?

        # Continue processing with *trusted* DNS query

        # Gather further information from unknown DNS resolvers
        if alias is False and query.reputation_resolver is None:
            self._logger.info('Create CNAME response and new DNS group')
            # Create CNAME response
            response, _fqdn = self._policy_cname(query)
            # Register alias service in host
            self._register_host_alias(host_obj, service_data, _fqdn)
            ## Create uDNSQueryTimer object
            timer_obj = uDNSQueryTimer(query, addr[0], _fqdn, service_data)
            # Monkey patch delete function for timer object
            timer_obj.delete = partial(self._cb_dnstimer_expired, timer_obj, host_obj, _fqdn)
            self.add(timer_obj)
            # Create reputation metadata in query object
            self._load_metadata_resolver(query, addr, create=True)
            # Register a neutral event
            query.reputation_resolver.event_neutral()
            # Return CNAME response
            return response

        # Gather further information from known DNS resolvers
        if alias is False and query.reputation_resolver is not None:
            self._logger.info('Create CNAME response for existing DNS group')
            # Create CNAME response
            response, _fqdn = self._policy_cname(query)
            # Register alias service in host
            self._register_host_alias(host_obj, service_data, _fqdn)
            ## Create uDNSQueryTimer object
            timer_obj = uDNSQueryTimer(query, addr[0], _fqdn, service_data)
            # Monkey patch delete function for timer object
            timer_obj.delete = partial(self._cb_dnstimer_expired, timer_obj, host_obj, _fqdn)
            self.add(timer_obj)
            # Register a neutral and trusted event
            query.reputation_resolver.event_trusted()
            query.reputation_resolver.event_neutral()
            # Return CNAME response
            return response

        # We have come this far, let's not get picky if we are using UDP or TCP
        assert(alias is True)

        # Register a neutral and trusted event
        query.reputation_resolver.event_trusted()
        query.reputation_resolver.event_neutral()

        # Query is trusted, load/create metadata related to requestor
        self._load_metadata_requestor(query, addr, create=True)

        # Remove alias service in host and update reputation (+1)
        self._remove_host_alias(host_obj, fqdn, query.reputation_resolver)

        # Remove timer object
        timer_obj = self.get((KEY_TIMER_FQDN, fqdn))
        self.remove(timer_obj)

        # Evaluate seen IP addresses for this query
        if timer_obj.ipaddr not in query.reputation_resolver.population:
            self._logger.warning('New node detected in DNS group')
            # Merge DNS groups
            other_dnsgroup_obj = self.get((KEY_DNSGROUP_IPADDR, timer_obj.ipaddr))
            #
            self._logger.warning('Merging DNS groups\n >{}\n >{}'.format(query.reputation_resolver, other_dnsgroup_obj))
            #
            query.reputation_resolver.merge(other_dnsgroup_obj)
            self.remove(other_dnsgroup_obj)
            self._logger.warning('Merged DNS groups\n >{}'.format(query.reputation_resolver))


    def api_data_newpacket(self, packet):
        pass

    def api_dns_circularpool(self, query, addr, host_obj, service_data, host_ipv4):
        """ Takes in a DNS query for CircularPool... """
        # TODO: Implement logic for policy and reputation checking

        #dns_server_id = query.reputation_requestor.id
        #dns_client_ip = query.reputation_requestor.ipaddr

        # Get Circular Pool policy for host
        host_policy = host_obj.get_service('CIRCULARPOOL')[0]

        # Update table and remove expired connections
        self.connectiontable.update_all_rgw()

        # Get host usage stats of the pool - lookup because there could be none
        rgw_conns = self.connectiontable.stats(connection.KEY_RGW)
        host_conns = self.connectiontable.stats((connection.KEY_RGW, host_obj.fqdn)) # Use host fqdn as connection id

        # Evaluate most basic policy for quick exit
        #if rgw_conns >= node_policy['max']:
        #    self._logger.warning('RealmGateway global policy exceeded: {}'.format(node_policy['max']))
        #    return False

        if host_conns >= host_policy['max']:
            self._logger.warning('RealmGateway host policy exceeded: {}'.format(host_policy['max']))
            return False

        # No policy has been exceeded -> Continue

        # Calculate system load and find executing policy function
        ## Get Circular Pool address pool stats
        ap_cpool = self.pooltable.get('circularpool')
        pool_size, pool_allocated, pool_available = ap_cpool.get_stats()
        ## Calculate current load in 100%
        sysload = (pool_allocated / pool_size) * 100

        ## Get executing function
        ### Execute best-effort policy if DNS Load Policing is disabled
        if PBRA_DNS_LOAD_POLICING is False:
            allocated_ipv4 = self._policy_circularpool_low()
            return allocated_ipv4
        else:
            cb_f = self._get_policy_load_function(sysload)
            allocated_ipv4 = cb_f(query, addr, host_obj, service_data, host_ipv4)
            return allocated_ipv4


    def _cb_connection_expired(self, conn):
        # Get Circular Pool address pool
        ap_cpool = self.pooltable.get('circularpool')
        ipaddr = conn.outbound_ip

        if conn.hasexpired():
            # Connection expired
            self._logger.info('Connection expired: {} in {:.3f} msec '.format(conn, conn.age*1000))
            # Blame attribution to DNS resolver and requestor
            self._logger.info('  >> Blame attribution!')
            # Register a nok event
            if conn.query.reputation_resolver is not None:
                conn.query.reputation_resolver.event_nok()
            if conn.query.reputation_requestor is not None:
                conn.query.reputation_requestor.event_nok()
        else:
            # Connection was used
            ## Register a ok event
            if conn.query.reputation_resolver is not None:
                conn.query.reputation_resolver.event_ok()
            if conn.query.reputation_requestor is not None:
                conn.query.reputation_requestor.event_ok()

        # Get RealmGateway connections
        if self.connectiontable.has((connection.KEY_RGW, ipaddr)):
            self._logger.info('Cannot release IP address to Circular Pool: {} @ {} still in use for {:.3f} msec'.format(conn.fqdn, ipaddr, conn.age*1000))
            return

        ap_cpool.release(ipaddr)
        self._logger.info('Released IP address to Circular Pool: {} @ {} in {:.3f} msec'.format(ipaddr, conn.fqdn, conn.age*1000))


    def _get_policy_load_function(self, sysload):
        """ Based on current load, return callback function for policy processing """
        # We define up to 4 different levels of system load

        if SYSTEM_LOAD_ENABLED(SYSTEM_LOAD_VERY_HIGH[0]) and \
          sysload >= SYSTEM_LOAD_VERY_HIGH[0]:
            self._logger.warning('SYSTEM_LOAD_VERY_HIGH ({:.2f}%%)'.format(sysload))
            return self._policy_circularpool_veryhigh

        elif SYSTEM_LOAD_ENABLED(SYSTEM_LOAD_HIGH[0]) and \
          sysload >= SYSTEM_LOAD_HIGH[0]:
            self._logger.warning('SYSTEM_LOAD_HIGH ({:.2f}%%)'.format(sysload))
            return self._policy_circularpool_high

        elif SYSTEM_LOAD_ENABLED(SYSTEM_LOAD_MEDIUM[0]) and \
          sysload >= SYSTEM_LOAD_MEDIUM[0]:
            self._logger.warning('SYSTEM_LOAD_MEDIUM ({:.2f}%%)'.format(sysload))
            return self._policy_circularpool_medium

        elif SYSTEM_LOAD_ENABLED(SYSTEM_LOAD_LOW[0]) and \
          sysload >= SYSTEM_LOAD_LOW[0]:
            self._logger.warning('SYSTEM_LOAD_LOW ({:.2f}%%)'.format(sysload))
            return self._policy_circularpool_low

    def _policy_get_max_reputation(self, query):
        """ Return the maximum reputation value among DNS resolver and requestor """
        r_resolver = 0
        r_requestor = 0
        if query.reputation_resolver:
            r_resolver = query.reputation_resolver.reputation
        if query.reputation_requestor:
            r_resolver = query.reputation_requestor.reputation
        return max(r_resolver, r_requestor)

    def _policy_get_min_reputation(self, query):
        """ Return the minimum reputation value among DNS resolver and requestor """
        r_resolver = 0
        r_requestor = 0
        if query.reputation_resolver:
            r_resolver = query.reputation_resolver.reputation
        if query.reputation_requestor:
            r_resolver = query.reputation_requestor.reputation
        return min(r_resolver, r_requestor)

    def _policy_circularpool_veryhigh(self, query, addr, host_obj, service_data, host_ipv4):
        """ The following restrictions apply
        1. Minimum reputation is required for allocating new IP address only if service can be overloaded, i.e. port and protocol are not zero
        """
        self._logger.warning('_policy_circularpool_veryhigh')

        _reputation = self._policy_get_max_reputation(query)
        _overload   = self._service_is_overloadable(service_data, partial_overload=False)

        # 1. Minimum reputation is required for allocating new IP address only if service can be overloaded, i.e. port and protocol are not zero
        if _reputation >= SYSTEM_LOAD_VERY_HIGH[2] and _overload is True:
            self._logger.info('Policy match @ SYSTEM_LOAD_VERY_HIGH: reputation={:.2f}/{:.2f} overload={}/{}'.format(_reputation, SYSTEM_LOAD_VERY_HIGH[2], _overload, True))
            return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)

        # Log error violation
        self._logger.info('Policy violation @ SYSTEM_LOAD_VERY_HIGH')
        self._logger.info('Policy violation: required reputation={:.2f} overload={}'.format(SYSTEM_LOAD_VERY_HIGH[2], True))
        self._logger.info('Policy violation: offered  reputation={:.2f} overload={}'.format(_reputation, _overload))
        return None

    def _policy_circularpool_high(self, query, addr, host_obj, service_data, host_ipv4):
        """ The following restrictions apply
        1. Minimum reputation1 is required for allocating new IP address regardless of the service
        2. Minimum reputation2 is required for allocating new IP address only if service can be overloaded, i.e. port and protocol are not zero
        #3. Minimum reputation3 is required for allocating new IP address only if service can be overloaded, supposed there are multiple overloadable IP addresses.
        Note: reputation1 > reputation2 > reputation3
        """
        self._logger.warning('_policy_circularpool_high')

        _reputation = self._policy_get_max_reputation(query)
        _overload   = self._service_is_overloadable(service_data, partial_overload=False)

        # 1. Minimum reputation is required for allocating new IP address regardless of the service
        if _reputation >= SYSTEM_LOAD_HIGH[1]:
            self._logger.info('Policy match @ SYSTEM_LOAD_HIGH: reputation={:.2f}/{:.2f}'.format(_reputation, SYSTEM_LOAD_HIGH[1]))
            return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)

        # 2. Minimum reputation is required for allocating new IP address only if service can be overloaded, i.e. port and protocol are not zero
        if _reputation >= SYSTEM_LOAD_HIGH[2] and _overload is True:
            self._logger.info('Policy match @ SYSTEM_LOAD_HIGH: reputation={:.2f}/{:.2f} overload={}/{}'.format(_reputation, SYSTEM_LOAD_HIGH[2], _overload, True))
            return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)

        # Log error violation
        self._logger.info('Policy violation @ SYSTEM_LOAD_HIGH')
        self._logger.info('Policy violation: required reputation={:.2f} overload={}'.format(SYSTEM_LOAD_HIGH[1], False))
        self._logger.info('Policy violation: required reputation={:.2f} overload={}'.format(SYSTEM_LOAD_HIGH[2], True))
        self._logger.info('Policy violation: offered  reputation={:.2f} overload={}'.format(_reputation, _overload))
        return None

    def _policy_circularpool_medium(self, query, addr, host_obj, service_data, host_ipv4):
        """ The following restrictions apply
        1. Minimum reputation1 is required for allocating new IP address regardless of the service
        2. Minimum reputation2 is required for allocating new IP address only if service can be overloaded, i.e. port or protocol are not zero
        #3. Minimum reputation3 is required for allocating new IP address only if service can be overloaded, supposed there are multiple overloadable IP addresses.
        Note: reputation1 > reputation2 > reputation3
        """
        self._logger.warning('_policy_circularpool_medium')

        _reputation = self._policy_get_max_reputation(query)
        _overload   = self._service_is_overloadable(service_data, partial_overload=True)

        # 1. Minimum reputation is required for allocating new IP address regardless of the service
        if _reputation >= SYSTEM_LOAD_MEDIUM[1]:
            self._logger.info('Policy match @ SYSTEM_LOAD_MEDIUM: reputation={:.2f}/{:.2f}'.format(_reputation, SYSTEM_LOAD_MEDIUM[1]))
            return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)

        # 2. Minimum reputation is required for allocating new IP address only if service can be overloaded, i.e. port or protocol are not zero
        if _reputation >= SYSTEM_LOAD_MEDIUM[2] and _overload is True:
            self._logger.info('Policy match @ SYSTEM_LOAD_MEDIUM: reputation={:.2f}/{:.2f} overload={}/{}'.format(_reputation, SYSTEM_LOAD_MEDIUM[2], _overload, True))
            return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)

        # Log error violation
        self._logger.info('Policy violation @ SYSTEM_LOAD_MEDIUM')
        self._logger.info('Policy violation: required reputation={:.2f} overload={}'.format(SYSTEM_LOAD_MEDIUM[1], False))
        self._logger.info('Policy violation: required reputation={:.2f} overload={}'.format(SYSTEM_LOAD_MEDIUM[2], True))
        self._logger.info('Policy violation: offered  reputation={:.2f} overload={}'.format(_reputation, _overload))
        return None

    def _policy_circularpool_low(self, query, addr, host_obj, service_data, host_ipv4):
        """ No restrictions apply
        Note: Gambling stage
        """
        self._logger.warning('_policy_circularpool_low')
        return self._best_effort_allocate(query, addr, host_obj, service_data, host_ipv4)


    def _best_effort_allocate(self, query, addr, host_obj, service_data, host_ipv4):
        # TODO: Improve connection creation to include DNS metadata
        self._logger.debug('_best_effort_allocate')

        # Obtain FQDN from query
        fqdn = format(query.question[0].name)

        # Get Circular Pool address pool stats
        ap_cpool = self.pooltable.get('circularpool')
        pool_size, pool_allocated, pool_available = ap_cpool.get_stats()

        # Get list of reusable addresses
        reuse_ipaddr_l = self._connection_circularpool_get_overloadable(service_data)
        if len(reuse_ipaddr_l) > 0:
            # Use first available address from the pool
            allocated_ipv4 = reuse_ipaddr_l[0]
            self._logger.debug('Found {} IP(s) for reuse: {}'.format(len(reuse_ipaddr_l), reuse_ipaddr_l))
            self._logger.info('Overloading reserved address: {} @ {}'.format(fqdn, allocated_ipv4))
        elif pool_available > 0:
            # Allocate a new address from the pool
            allocated_ipv4 = ap_cpool.allocate()
            self._logger.info('Allocating new address from CircularPool: {} @ {}'.format(fqdn, allocated_ipv4))
        else:
            self._logger.warning('Failed to allocate a new address from CircularPool: {} @ N/A'.format(fqdn))
            return None

        # Continue to creating the connection
        # Create RealmGateway connection
        conn_param = {'private_ip': host_ipv4,
                      'private_port': service_data['port'],
                      'outbound_ip': allocated_ipv4,
                      'outbound_port': service_data['port'],
                      #'remote_ip': remote_ip,
                      #'remote_port': remote_port,
                      'protocol': service_data['protocol'],
                      'fqdn': fqdn,
                      'host_fqdn': host_obj.fqdn,
                      #'resolver_ip': None,
                      #'requestor_ip': None,
                      'loose_packet': service_data.setdefault('loose_packet', 0),
                      'autobind': service_data.setdefault('autobind', True),
                      'timeout': service_data.setdefault('timeout', 0),
                      'query': query,
                      }

        connection_obj = ConnectionLegacy(**conn_param)
        # Monkey patch delete function for connection object
        connection_obj.delete = partial(self._cb_connection_expired, connection_obj)
        # Add connection to table
        self.connectiontable.add(connection_obj)
        # Log
        self._logger.info('Allocated IP address from Circular Pool: {} @ {} for {:.3f} msec'.format(fqdn, allocated_ipv4, connection_obj.timeout*1000))
        self._logger.info('New Circular Pool connection: {}'.format(connection_obj))
        return allocated_ipv4


    def _service_is_overloadable(self, service_data, partial_overload=True):
        """ Return True if service is overloadable """
        if partial_overload:
            return (service_data['port'] != 0 or service_data['protocol'] != 0)
        else:
            return (service_data['port'] != 0 and service_data['protocol'] != 0)

    def _connection_circularpool_get_overloadable(self, service_data):
        """ Returns a list of IPv4 address that can be overloaded """
        port, protocol = service_data['port'], service_data['protocol']
        self._logger.debug('Attempt to overload connection for {}:{}'.format(port, protocol))
        # List of available addresses for reuse
        available = []

        if not self.connectiontable.has(connection.KEY_RGW):
            return available

        # Iterate all RealmGateway connections and try to reuse existing allocated IP addresses
        rgw_conns = self.connectiontable.get(connection.KEY_RGW)
        for conn in rgw_conns:
            ipaddr = conn.outbound_ip
            c_port, c_proto = conn.outbound_port, conn.protocol
            s_port, s_proto = port, protocol

            # Do not iterate already available addresses
            if ipaddr in available:
                continue

            self._logger.warning('Comparing {} vs {} @{}'.format((c_port, c_proto),(s_port, s_proto), ipaddr))
            # The following statements match when IP overloading cannot be performed
            if (c_port == 0 and c_proto == 0) or (s_port == 0 and s_proto == 0):
                self._logger.debug('0. Port & Protocol blocked')
                continue
            elif (c_port == s_port) and (c_proto == s_proto or c_proto == 0 or s_proto == 0):
                self._logger.debug('1. Port blocked')
                continue
            elif (c_proto == s_proto) and (c_port == 0 or s_port == 0):
                self._logger.debug('2. Port blocked')
                continue

            available.append(ipaddr)
        # Return list of available IP addresses for overload
        return available

    def _connection_circularpool_create(self, host_obj, host_ipaddr, dns_server_ip, dns_client_ip, fqdn, service_data):
        """ Return the created connection or None """
        allocated_ipv4 = None
        # Get Circular Pool address pool
        ap_cpool = self.pooltable.get('circularpool')
        # Check if existing connections can be overloaded
        self._logger.debug('Overload connection for {} @ {}:{}'.format(fqdn, service_data['port'], service_data['protocol']))
        available_overload = self._get_overload_ipaddrs(service_data['port'], service_data['protocol'])

        if len(available_overload) > 0:
            # Use first available address from the pool
            allocated_ipv4 = available_overload[0]
            self._logger.info('Overloading reserved address: {} @ {}'.format(fqdn, allocated_ipv4))
        else:
            # Attempt to allocate new address from the pool and return if not available
            allocated_ipv4 = ap_cpool.allocate()
            if allocated_ipv4 is None:
                return None

        # Create RealmGateway connection
        conn_param = {'private_ip': host_ipaddr, 'private_port': service_data['port'],
                      'outbound_ip': allocated_ipv4, 'outbound_port': service_data['port'],
                      'protocol': service_data['protocol'], 'fqdn': fqdn, 'dns_server': dns_server_ip,
                      'loose_packet': service_data.setdefault('loose_packet', 0), 'host_fqdn':host_obj.fqdn,
                      'autobind': service_data.setdefault('autobind', True),
                      'timeout': service_data.setdefault('timeout', 0)}
        connection = ConnectionLegacy(**conn_param)
        # Monkey patch delete function
        connection.delete = partial(self._cb_delete_rgw_connection, connection)
        # Add connection to table
        self.connectiontable.add(connection)
        # Log
        self._logger.info('Allocated IP address from Circular Pool: {} @ {} for {:.3f} msec'.format(fqdn, allocated_ipv4, connection.timeout*1000))
        self._logger.info('New Circular Pool connection: {}'.format(connection))
        return connection


    def _register_host_alias(self, host_obj, service_data, fqdn):
        # Add alias as SFQDN host service
        #service_data = {'fqdn':'foo.', 'port':0, 'protocol':0, 'proxy_required':False, 'carriergrade':False}
        _service_data = dict(service_data)
        _service_data['fqdn'] = fqdn
        _service_data['alias'] = True
        # Add alias service to host_obj
        host_obj.add_service(KEY_SERVICE_SFQDN, _service_data)
        # Update lookup keys in host table
        self.hosttable.updatekeys(host_obj)

    def _remove_host_alias(self, host_obj, fqdn, dnsgroup_obj):
        # Update reputation values
        ## Log OK event
        dnsgroup_obj.event_nok()
        # Remove alias FQDN service from host
        service_data = host_obj.get_service_sfqdn(fqdn)
        host_obj.remove_service(KEY_SERVICE_SFQDN, service_data)
        # Update lookup keys in host table
        self.hosttable.updatekeys(host_obj)

    def _cb_dnstimer_expired(self, timer_obj, host_obj, fqdn):
        # Log expiration
        if timer_obj.hasexpired():
            self._logger.info('Timer expired {}'.format(timer_obj))
            # Update reputation values. DNS group must exists
            dnsgroup_obj = self.get((KEY_DNSGROUP_IPADDR, timer_obj.ipaddr))
            ## Log NOK event
            dnsgroup_obj.event_nok()
        # Remove alias FQDN service from host
        service_data = host_obj.get_service_sfqdn(fqdn)
        host_obj.remove_service(KEY_SERVICE_SFQDN, service_data)
        # Update lookup keys in host table
        self.hosttable.updatekeys(host_obj)


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
    pbra = PolicyBasedResourceAllocation()

    ipaddr1 = '1.1.1.1'

    assert(not pbra.has((KEY_DNSGROUP_IPADDR, ipaddr1)))

    # Create new DNS node
    node1 = uStateDNSResolver(ipaddr=ipaddr1)
    # Create new DNS group with single DNS node
    group1 = uStateDNSGroup(population=[node1])

    pbra.add(node1)
    pbra.add(group1)

    assert(pbra.has((KEY_DNSGROUP_IPADDR, ipaddr1)))



    ipaddr2 = '1.1.1.2'
    # Create new DNS node
    node2 = uStateDNSResolver(ipaddr=ipaddr2)
    pbra.add(node2)

    _group = pbra.get((KEY_DNSGROUP_IPADDR, ipaddr1))
    _group.population.append(node2)
    pbra.updatekeys(_group)


    ipaddr3 = '1.1.1.3'
    # Create new DNS node
    node3 = uStateDNSResolver(ipaddr=ipaddr3)
    # Create new DNS group with single DNS node
    group2 = uStateDNSGroup(population=[node3])

    pbra.add(node3)
    pbra.add(group2)

    group1.merge(group2)
    pbra.remove(group2)


    print(group1.show_reputation())

