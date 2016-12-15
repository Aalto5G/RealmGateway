import asyncio
import aiohttp
import json
import logging
import socket, struct
import os, subprocess

from aalto_helpers import container3
from aalto_helpers import utils3
from aalto_helpers import iptc_helper3
from async_nfqueue import AsyncNFQueue
from loglevel import LOGLEVEL_NETWORK

DEFAULT_HOST_POLICY = 'ACCEPT'
#DEFAULT_HOST_POLICY = 'DROP'

class Network(object):
    def __init__(self, name='Network', **kwargs):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_NETWORK)
        utils3.set_attributes(self, **kwargs)
        # Initialize nfqueue object to None
        self._nfqueue = None
        # Zero Circular Pool chain for counters
        self.ipt_zero_chain('nat', self.iptables['circularpool']['chain'])
        # Flush critical chains
        self.ipt_flush_chain('nat', self.iptables['circularpool']['chain'])
        self.ipt_flush_chain('filter', self.iptables['hostpolicy']['chain'])
        # Test if MARKDNAT is available in the system
        self.MARKDNAT = iptc_helper3.test_target('MARKDNAT', {'or-mark':'0'})
        if self.MARKDNAT:
            self._add_MARKDNAT('nat', self.iptables['circularpool']['chain'])

    def ipt_flush_chain(self, table, chain):
        iptc_helper3.flush_chain(table, chain)

    def ipt_zero_chain(self, table, chain):
        iptc_helper3.zero_chain(table, chain)

    def ipt_add_user(self, hostname, ipaddr):
        self._logger.debug('Add user {}/{}'.format(hostname, ipaddr))
        # Remove previous user data
        self.ipt_remove_user(hostname, ipaddr)
        # Add user to Circular Pool ipt_chain
        self._add_circularpool(hostname, ipaddr)
        # Add user's firewall rules and register in global host policy chain
        self._add_basic_hostpolicy(hostname, ipaddr)

    def ipt_remove_user(self, hostname, ipaddr):
        self._logger.debug('Remove user {}/{}'.format(hostname, ipaddr))
        # Remove user from Circular Pool ipt_chain
        self._remove_circularpool(hostname, ipaddr)
        # Remove user's firewall rules and deregister in global host policy chain
        self._remove_basic_hostpolicy(hostname, ipaddr)

    def ipt_add_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Add carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Add carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Add carriergrade user to Circular Pool ipt_chain
            self._add_circularpool(hostname, ipaddr)
            # Add user's firewall rules and register in global host policy chain
            self._add_basic_hostpolicy_carriergrade(hostname, ipaddr)

    def ipt_remove_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Remove carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Remove carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Remove carriergrade user to Circular Pool ipt_chain
            self._remove_circularpool(hostname, ipaddr)
            # Remove user's firewall rules and register in global host policy chain
            self._remove_basic_hostpolicy_carriergrade(hostname, ipaddr)

    def ipt_add_user_fwrules(self, hostname, ipaddr, chain, fwrules):
        host_chain = 'HOST_{}_{}'.format(hostname, chain.upper())
        self._logger.debug('Add fwrules for user {}/{} to chain <{}> ({})'.format(hostname, ipaddr, host_chain, len(fwrules)))
        # Sort list by priority of the rules
        sorted_fwrules = sorted(fwrules, key=lambda rule: rule['priority'])
        for rule in sorted_fwrules:
            xlat_rule = self._ipt_xlat_rule(host_chain, rule)
            iptc_helper3.add_rule('filter', host_chain, xlat_rule)

    def ipt_register_nfqueue(self, queue, cb):
        assert (self._nfqueue is None)
        self._nfqueue = AsyncNFQueue(queue, cb)

    def ipt_deregister_nfqueue(self):
        assert (self._nfqueue is not None)
        self._nfqueue.terminate()

    def ipt_nfpacket_dnat(self, packet, ipaddr):
        mark = self._gen_pktmark_cpool(ipaddr)
        packet.set_mark(mark)
        packet.accept()

    def ipt_nfpacket_accept(self, packet):
        packet.accept()

    def ipt_nfpacket_drop(self, packet):
        packet.drop()

    def ipt_nfpacket_payload(self, packet):
        return packet.get_payload()

    def _add_MARKDNAT(self, table, chain):
        # Insert rule on the top of the chain
        rule = {'target':{'MARKDNAT': {'or-mark':'0'}},
                'comment':{'comment':'Realm Gateway NAT Traversal'}}
        iptc_helper3.add_rule(table, chain, rule, 0)

    def _add_circularpool(self, hostname, ipaddr):
        # Do not add specific rule if MARKDNAT is enabled
        if self.MARKDNAT:
            return
        # Add rule to iptables
        table = 'nat'
        chain = self.iptables['circularpool']['chain']
        mark = self._gen_pktmark_cpool(ipaddr)
        rule = {'mark':{'mark':hex(mark)}, 'target':{'DNAT':{'to-destination':ipaddr}}}
        iptc_helper3.add_rule(table, chain, rule)

    def _remove_circularpool(self, hostname, ipaddr):
        # Do not delete specific rule if MARKDNAT is enabled
        if self.MARKDNAT:
            return
        # Remove rule from iptables
        table = 'nat'
        chain = self.iptables['circularpool']['chain']
        mark = self._gen_pktmark_cpool(ipaddr)
        rule = {'mark':{'mark':hex(mark)}, 'target':{'DNAT':{'to-destination':ipaddr}}}
        iptc_helper3.delete_rule(table, chain, rule, True)

    def _add_basic_hostpolicy(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        host_chain_admin    = 'HOST_{}_ADMIN'.format(hostname)
        host_chain_parental = 'HOST_{}_PARENTAL'.format(hostname)
        host_chain_legacy   = 'HOST_{}_LEGACY'.format(hostname)
        host_chain_ces      = 'HOST_{}_CES'.format(hostname)

        # Create basic chains for host policy
        for chain in [host_chain, host_chain_admin, host_chain_parental, host_chain_legacy, host_chain_ces]:
            self._ipt_create_chain('filter', chain)

        # 1. Register triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':mark_in}, 'dst':ipaddr, 'target':host_chain})
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':mark_eg}, 'src':ipaddr, 'target':host_chain})

        # 2. Register triggers in host chain
        ## Get packet marks based on traffic direction
        mark_legacy = self.iptables['pktmark']['MASK_HOST_LEGACY']
        mark_ces = self.iptables['pktmark']['MASK_HOST_CES']
        ## Add rules to iptables
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_admin})
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_parental})
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_legacy, 'mark':{'mark':mark_legacy}})
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_ces, 'mark':{'mark':mark_ces}})
        # Add a variable for default host policy
        iptc_helper3.add_rule('filter', host_chain, {'target':DEFAULT_HOST_POLICY})

    def _remove_basic_hostpolicy(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        host_chain_admin    = 'HOST_{}_ADMIN'.format(hostname)
        host_chain_parental = 'HOST_{}_PARENTAL'.format(hostname)
        host_chain_legacy   = 'HOST_{}_LEGACY'.format(hostname)
        host_chain_ces      = 'HOST_{}_CES'.format(hostname)

        # 1. Remove triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':mark_in}, 'dst':ipaddr, 'target':host_chain}, True)
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':mark_eg}, 'src':ipaddr, 'target':host_chain}, True)

        # 2. Remove host chains
        for chain in [host_chain, host_chain_admin, host_chain_parental, host_chain_legacy, host_chain_ces]:
            self._ipt_remove_chain('filter', chain)

    def _add_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        # 1. Register triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':mark_in}, 'dst':ipaddr, 'target':host_chain})
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':mark_eg}, 'src':ipaddr, 'target':host_chain})

    def _remove_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        # 1. Register triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':mark_in}, 'dst':ipaddr, 'target':host_chain}, True)
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':mark_eg}, 'src':ipaddr, 'target':host_chain}, True)

    def _ipt_create_chain(self, table, chain, flush = False):
        # Create and flush to ensure an empty table
        iptc_helper3.add_chain(table, chain)
        if flush:
            iptc_helper3.flush_chain(table, chain, silent=True)

    def _ipt_remove_chain(self, table, chain):
        # Flush and delete to ensure the table is removed
        iptc_helper3.flush_chain(table, chain, silent=True)
        iptc_helper3.delete_chain(table, chain, silent=True)

    def _ipt_xlat_rule(self, chain, rule):
        ret = dict(rule)
        # Translate direction value into packet mark
        if ret['direction'] == 'EGRESS':
            ret['mark'] = {'mark':self.iptables['pktmark']['MASK_HOST_EGRESS']}
        elif ret['direction'] == 'INGRESS':
            ret['mark'] = {'mark':self.iptables['pktmark']['MASK_HOST_INGRESS']}
        elif ret['direction'] == 'ANY':
            pass
        else:
            raise AttributeError('Unknown direction: {}'.format(ret['direction']))
        return ret

    def _gen_pktmark_cpool(self, ipaddr):
        """ Return the integer representation of an IPv4 address """
        return struct.unpack("!I", socket.inet_aton(ipaddr))[0]

    '''
    def _ipt_chain_trigger(self, table, chain, action, mark, source, destination, jump_table, goto_table):
        #TOBEUSED
        ret = ''
        ret += 'iptables -t {} -{} {}'.format(table, action, chain)
        if mark:
            ret += ' -m mark --mark {}'.format(mark)
        if source:
            ret += ' -s {}'.format(source)
        if destination:
            ret += ' -d {}'.format(destination)
        if jump_table:
            ret += ' -j {}'.format(jump_table)
        if goto_table:
            ret += ' -g {}'.format(goto_table)
        return ret


    def _do_subprocess_call(self, command, raise_exc = False, supress_stdout = True):
        try:
            self._logger.debug('System call: {}'.format(command))
            if supress_stdout:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f, stderr=f)
            else:
                subprocess.check_call(command, shell=True)
        except Exception as e:
            self._logger.info(e)
            if raise_exc:
                raise e

    # This is for CES

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
    '''
