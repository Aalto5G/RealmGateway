#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

# Restart OpenvSwitch service
systemctl restart openvswitch-switch

## Create OVS bridges
ovs-vsctl del-br br-synproxy
ovs-vsctl add-br br-synproxy
ovs-vsctl add-port br-synproxy wan0  -- set interface wan0  ofport_request=1
ovs-vsctl add-port br-synproxy wan0p -- set interface wan0p ofport_request=4

# Bring up the interfaces
ip link set dev wan0 up
ip link set dev wan0p up

# Configure txqueuelen of interfaces / default is 1000
MAX_QLEN=10000
ip link set dev wan0  qlen $MAX_QLEN
ip link set dev wan0p qlen $MAX_QLEN
ip link set dev br-synproxy qlen $MAX_QLEN

# Flush iptables configuration
flushIptables
