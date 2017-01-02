from aalto_helpers import iptc_helper3
from aalto_helpers import iproute2_helper3
import yaml

### DUMP FUNCTIONS ###
def dump_all():
    d = {}
    for table in ['security', 'raw', 'mangle', 'nat', 'filter']:
        d[table] = dump_table(table)
    return d

def dump_table(table):
    d = {}
    iptc_table = iptc_helper3.get_table(table)
    for iptc_chain in iptc_table.chains:
        d[iptc_chain.name] = dump_chain(iptc_table.name, iptc_chain.name)
    return d

def dump_chain(table, chain):
    """Print a chain of a table
    @param table: The table
    @type table: string
    @param chain: The chain
    @type chain: string
    """
    l = []
    iptc_chain = iptc_helper3.get_chain(table, chain)
    for i, iptc_rule in enumerate(iptc_chain.rules):
        l.append(decode_custom_iptc_rule(iptc_rule))
    return l
### /DUMP FUNCTIONS ###

### DECODE FUNCTIONS ###
def decode_custom_iptc_rule(iptc_rule):
    """Generate list representation of an iptc.Rule
    @param iptc_rule: The iptc.Rule object
    @type iptc_rule: iptc.Rule
    @returns: The list representation of a rule
    @rtype: list
    """
    l = []
    if iptc_rule.src != '0.0.0.0/0.0.0.0':
        l.append(['src', iptc_rule.src])
    if iptc_rule.dst != '0.0.0.0/0.0.0.0':
        l.append(['dst', iptc_rule.dst])
    if iptc_rule.protocol != 'ip':
        l.append(['protocol', iptc_rule.protocol])
    if iptc_rule.in_interface is not None:
        l.append(['in-interface', iptc_rule.in_interface])
    if iptc_rule.out_interface is not None:
        l.append(['out-interface', iptc_rule.out_interface])
    for iptc_match in iptc_rule.matches:
        l.append([iptc_match.name, decode_custom_iptc_match(iptc_match)])
    if iptc_rule.target.name:
        l.append(['target', decode_custom_iptc_target(iptc_rule.target)])
    return l

def decode_custom_iptc_match(iptc_match):
    data_d = {}
    params_d = iptc_match.get_all_parameters()
    # Reduce value lists of 1 element to the element itself
    for key, value in params_d.items():
        if len(value) == 1:
            data_d[key] = value[0]
        else:
            data_d[key] = value
    # Library bugs & hacks
    if iptc_match.name == 'hashlimit':
        # Set default value 1 sec (expressed in ms)
        ## Reported issue here: https://github.com/ldx/python-iptables/issues/201
        data_d.setdefault('hashlimit-htable-expire', '1000')
    return data_d

def decode_custom_iptc_target(iptc_target):
    data_d = {}
    params_d = iptc_target.get_all_parameters()
    name = iptc_target.name.replace('-', '_')
    if not len(params_d):
        return name
    # Reduce value lists of 1 element to the element itself
    for key, value in params_d.items():
        if len(value) == 1:
            data_d[key] = value[0]
        else:
            data_d[key] = value
    return {name:data_d}
### /DECODE FUNCTIONS ###

### FORMATTED OUTPUT FUNCTIONS ###
def print_all_rules():
    for table in ['security', 'raw', 'mangle', 'nat', 'filter']:
        print_table_rules(table)

def print_table_rules(table):
    iptc_table = iptc_helper3.get_table(table)
    for iptc_chain in iptc_table.chains:
        print_chain_rules(iptc_table.name, iptc_chain.name)

def print_chain_rules(table, chain):
    rules = dump_chain(table, chain)
    for rule in rules:
        print("{{'table': '{}', 'chain': '{}', 'rule': {}}}".format(table, chain, rule))
### /FORMATTED OUTPUT FUNCTIONS ###

### RULE PROCESSING FUNCTIONS ###
def process_ips_group(data_d):
    print('Requires: {} elements'.format(len(data_d['requires'])))
    for i, entry in enumerate(data_d['requires']):
        print('#{}\t{}'.format(i+1, entry))
        name = entry['name']
        stype = entry['type']
        if entry['create'] and not iproute2_helper3.ipset_exists(name):
            print('Creating new ipset <{} {}>'.format(name, stype))
            iproute2_helper3.ipset_create(name, stype)
        if entry['flush']:
            print('Flushing ipset <{}>'.format(name))
            iproute2_helper3.ipset_flush(name)

    print('Rules: {} elements'.format(len(data_d['rules'])))
    for i, entry in enumerate(data_d['rules']):
        name = entry['name']
        etype = entry['type']
        items = entry['items']
        print('#{}\t{}@{}\t{}'.format(i+1, name, etype, items))
        for i in items:
            iproute2_helper3.ipset_add(name, i, etype=etype)

def process_ipt_group(data_d):
    print('Requires: {} elements'.format(len(data_d['requires'])))
    for i, entry in enumerate(data_d['requires']):
        print('#{}\t{}'.format(i+1, entry))
        table = entry['table']
        chain = entry['chain']
        if entry['create'] and not iptc_helper3.has_chain(table, chain):
            print('Creating new chain <{}@{}>'.format(table,chain))
            iptc_helper3.add_chain(table, chain, silent=True)
        if entry['flush']:
            print('Flushing chain <{}@{}>'.format(table,chain))
            iptc_helper3.flush_chain(table, chain)

    print('Rules: {} elements'.format(len(data_d['rules'])))
    for i, entry in enumerate(data_d['rules']):
        table = entry['table']
        chain = entry['chain']
        rule  = entry['rule']
        print('#{}\t{}@{}\t{}'.format(i+1, table, chain, rule))
        iptc_helper3.add_rule(table, chain, rule)

### /RULE PROCESSING FUNCTIONS ###

#print_all_rules()
#exit()

filename = 'gwa.dataplane.yaml'
data_all = yaml.load(open(filename,'r'))

# Iterate over IPSET data
ips_data = data_all['IPSET']
process_ips_group(ips_data)

# Iterate over IPTABLES data
ipt_data = data_all['IPTABLES']

# Install rules PACKET_MARKING
process_ipt_group(ipt_data['PACKET_MARKING'])

# Install rules CIRCULAR_POOL
process_ipt_group(ipt_data['NAT'])

# Install rules mREJECT
process_ipt_group(ipt_data['mREJECT'])

# Install rules ADMIN_PREEMPTIVE
process_ipt_group(ipt_data['ADMIN_PREEMPTIVE'])

# Install rules CUSTOMER_POLICY
process_ipt_group(ipt_data['CUSTOMER_POLICY'])

# Install rules ADMIN_POLICY & ADMIN_POLICY_xyz
process_ipt_group(ipt_data['ADMIN_POLICY'])
process_ipt_group(ipt_data['ADMIN_POLICY_DHCP'])
process_ipt_group(ipt_data['ADMIN_POLICY_HTTP'])
process_ipt_group(ipt_data['ADMIN_POLICY_DNS'])
