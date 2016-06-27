import dnsutils
import utils
import logging

class DNSCallbacks(object):
    def __init__(self, **kwargs):
        self._logger = logging.getLogger('DNSCallbacks')
        self._logger.setLevel(logging.INFO)
        utils.set_attributes(self, **kwargs)
        self.state = {}
        self.soa = []
        self.objects = {}
    
    def register_object(self, name, value)
        self.objects[name] = value
    
    def dns_register_soa(self, name):
        if name not in self.soa:
            self.soa.append(name)
    
    def dns_get_soa(self, name):
        return list(self.soa)
    
    def ddns_register_user(self, name, rdtype, ipaddr):
        # TO BE COMPLETED
        '''
        self._logger.warning('Register new user {} @{}'.format(name, ipaddr))
        # Add node to the DNS Zone
        zone = self._dns['zone']
        mydns.add_node(zone, name, rdtype, ipaddr)
        # Initialize address pool for user
        ap = self._poolcontainer.get('proxypool')
        ap.create_pool(ipaddr)
        # Download user data
        '''
        pass

    def ddns_deregister_user(self, name, rdtype, ipaddr):
        # TO BE COMPLETED
        '''
        self._logger.warning('Deregister user {} @{}'.format(name, ipaddr))
        # Delete node from the DNS Zone
        zone = self._dns['zone']
        mydns.delete_node(zone, name)
        # Delete all active connections
        pass
        # Destroy address pool for user
        ap = self._poolcontainer.get('proxypool')
        ap.destroy_pool(ipaddr)
        '''
        pass
    
    def ddns_process(self, query, addr, cback):
        """ Process DDNS query from DHCP server """
        self._logger.debug('process_update')
        try:
            rr_a = None
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A:
                    rr_a = rr
                    break

            if not rr_a:
                # isc-dhcp-server uses additional TXT records -> don't process
                self._logger.debug('Failed to find an A record')
                return

            name_str = rr_a.name.to_text()
            if rr_a.ttl:
                self.ddns_register_user(name_str, rr_a.rdtype, rr_a[0].address)
            else:
                self.ddns_deregister_user(name_str, rr_a.rdtype, rr_a[0].address)
            
            # Send generic DDNS Response NOERROR
            response = dnsutils.make_response_rcode(query, RetCodes.DNS_NOERROR)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, response, addr)
        except Exception as e:
            self._logger.error('Failed to process UPDATE DNS message')
        
    def dns_process_rgw_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        # Resolve locally
        pass
    
    def dns_process_rgw_lan_nosoa(self, query, addr, cback):
        """ Process DNS query from private network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        # Forward to resolver
        pass
    
    def dns_process_ces_lan_soa(self, query, addr, cback):
        """ Process DNS query from private network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass
    
    def dns_process_ces_lan_nosoa(self, query, addr, cback):
        """ Process DNS query from private network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass
    
    def dns_process_rgw_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        # Resolve locally
        pass
    
    def dns_process_rgw_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        # Discard
        pass
    
    def dns_process_ces_wan_soa(self, query, addr, cback):
        """ Process DNS query from public network of a name in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass
    
    def dns_process_ces_wan_nosoa(self, query, addr, cback):
        """ Process DNS query from public network of a name not in a SOA zone """
        fqdn = query.question[0].name.to_text()
        pass