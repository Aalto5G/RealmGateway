
# Packet marks per interface
hMARK_EGRESS_to_CES='0x4'       #0b00100
hMARK_EGRESS_to_WAN='0x6'       #0b00110
hMARK_EGRESS_to_PROXY='0x7'     #0b00111
hMARK_INGRESS_from_CES='0x18'   #0b11000
hMARK_INGRESS_from_WAN='0x19'   #0b11001
hMARK_INGRESS_from_PROXY='0x1d' #0b11101
hMARK_MASK='0x10'               #0b10000
hMARK_EGRESS_MASK='0x00'        #0b00000
hMARK_INGRESS_MASK='0x10'       #0b10000

def _direction_xlat(d):
    if d == 'ANY':
        return '{}/{}'.format('0x00', '0x00')
    elif d == 'EGRESS':
        return '{}/{}'.format(hMARK_EGRESS_MASK, hMARK_MASK)
    elif d == 'INGRESS':
        return '{}/{}'.format(hMARK_INGRESS_MASK, hMARK_MASK)
    elif d == 'EGRESS_to_CES':
        return '{}'.format(hMARK_EGRESS_to_CES)
    elif d == 'EGRESS_to_WAN':
        return '{}'.format(hMARK_EGRESS_to_WAN)
    elif d == 'EGRESS_to_PROXY':
        return '{}'.format(hMARK_EGRESS_to_PROXY)
    elif d == 'INGRESS_from_CES':
        return '{}'.format(hMARK_INGRESS_from_CES)
    elif d == 'INGRESS_from_WAN':
        return '{}'.format(hMARK_INGRESS_from_WAN)
    elif d == 'INGRESS_from_PROXY':
        return '{}'.format(hMARK_INGRESS_from_PROXY)
    else:
        raise Exception('direction not supported: {}'.format(d))

def _check_direction(direction, source, destination):
    if direction == 'ANY':
        assert(source      == '0.0.0.0/0')
        assert(destination == '0.0.0.0/0')
    elif 'EGRESS' in direction:
        assert(source == '0.0.0.0/0')
    elif 'INGRESS' in direction:
        assert(destination == '0.0.0.0/0')
    return True

def _check_proto(proto):
    assert(proto >= 0) and (proto <= 255)
    return True

def _check_port(port, proto):
    assert(proto in [6,17])
    if isinstance(port, int):
        assert(port >= 1) and (port <= 65535)
    elif isinstance(port, str):
        [a, b] = port.split(':')
        assert(not(a is '' and b is ''))
        if a is '': a = 1
        if b is '': b = 65535
        assert(int(a) < int(b))
        assert(int(a) >= 1) and (int(a) <= 65534)
        assert(int(b) >= 2) and (int(b) <= 65535)
    return True

def _check_icmpcode(port, proto):
    assert(proto in [1])
    if isinstance(port, int):
        assert(port >= 0) and (port <= 255)
    elif isinstance(port, str):
        [a, b] = port.split('/')
        assert(not(a is '' or b is ''))
        assert(int(a) >= 0) and (int(a) <= 255)
        assert(int(b) >= 0) and (int(b) <= 255)
    return True 
            
def _check_extra(extra, action):
    if 'ratelimit' in extra:
        assert(extra['ratelimit'] >= 0)
        assert(action == 'ACCEPT')
    elif 'ratelimit' in extra and 'rateburst' in extra:
        # Matching only in rateburst is not recommended
        assert(extra['rateburst'] >= 0)
        assert(action == 'ACCEPT')
    return True

def check_rule(kwrule):
    # Set default priority value to 0
    assert(kwrule.setdefault('priority', 0) >= 0)
    # Set default source to ANY
    assert(kwrule.setdefault('source', '0.0.0.0/0'))
    # Set default destination to ANY
    assert(kwrule.setdefault('destination', '0.0.0.0/0'))
    # Set default direction to ANY
    assert(kwrule.setdefault('direction','ANY'))
    # Validate and translate direction
    assert(_check_direction(kwrule['direction'], kwrule['source'], kwrule['destination']))
    kwrule['direction'] = _direction_xlat(kwrule['direction'])
    # Set default protocol to ANY
    assert(kwrule.setdefault('protocol', 0) >= 0)
    assert(_check_proto(kwrule['protocol']))
    # Validate source and destination ports
    if 'source-port' in kwrule:
        assert(_check_port(kwrule['source-port'], kwrule['protocol']))
    if 'destination-port' in kwrule:
        assert(_check_port(kwrule['destination-port'], kwrule['protocol']))
    # Validate type and code for ICMP
    if 'icmp-type' in kwrule:
        assert(_check_icmp-type(kwrule['icmp-type'], kwrule['protocol']))
    # Validate action
    assert(kwrule['action'] in ['ACCEPT', 'DROP'])
    # Validate extra
    if 'extra' in kwrule:
        assert(_check_extra(kwrule['extra'], kwrule['action']))
    
    # For assert checks
    return True


# Create rule for DNS over UDP
rule1={'priority': 10, 'direction': 'EGRESS', 'source': '0.0.0.0/0', 'protocol': 17, 'destination-port': 53, 'action': 'ACCEPT', 'extra': {'ratelimit': 3, 'rateburst': 5}}
check_rule(rule1)
# Create rule for DNS over TCP
rule2={'priority': 20, 'direction': 'EGRESS', 'source': '0.0.0.0/0', 'protocol': 6,  'destination-port': 53, 'action': 'DROP'}
check_rule(rule2)
# Create service for DNS with above rules

group1 = {'priority': 10, 'name': 'DNS', 'uuid': 'uuid0001', 'rules': [rule1, rule2]}

###

# Create rule for ICMP
rule3={'priority': 10, 'direction': 'EGRESS' , 'destination': '0.0.0.0/0', 'protocol': 1, 'action': 'DROP'}
rule4={'priority': 10, 'direction': 'INGRESS', 'destination': '0.0.0.0/0', 'protocol': 1, 'action': 'DROP'}
rule4={'priority': 10, 'destination': '0.0.0.0/0', 'protocol': 1, 'action': 'DROP'}
check_rule(rule3)
check_rule(rule4)
# Create service for ICMP with above rules
group2 = {'priority': 10, 'name': 'ICMP', 'uuid': 'uuid0002', 'rules': [rule3, rule4]}

###

# Create rule for SSH
rule5={'priority': 10, 'protocol': 6, 'destination-port':22, 'action': 'ACCEPT'}
check_rule(rule5)
# Create service for SSH with above rules
group3 = {'priority': 10, 'name': 'SSH', 'uuid': 'uuid0003', 'rules': [rule5]}

###

# Create rule for mySQL
rule6={'priority': 10, 'protocol': 6, 'destination-port':3306, 'action': 'DROP'}
check_rule(rule6)

# Create service for mySQL with above rules
group4 = {'priority': 10, 'name': 'mySQL', 'uuid': 'uuid0004', 'rules': [rule6]}


# Create dictionary to aggregate all security groups
secgroups = {'uuid0001': group1,
             'uuid0002': group2,
             'uuid0003': group3,
             'uuid0004': group4,
             }
