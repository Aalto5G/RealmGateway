#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "# Initializting flows for $@"
## Flush table and create basic flows
ovs-ofctl --protocols=OpenFlow13 del-flows $@
ovs-ofctl --protocols=OpenFlow13 add-flow  $@ table=0,in_port=1,actions=output:3
ovs-ofctl --protocols=OpenFlow13 add-flow  $@ table=0,in_port=3,actions=output:1
ovs-ofctl --protocols=OpenFlow13 add-flow  $@ table=0,in_port=2,actions=output:4
ovs-ofctl --protocols=OpenFlow13 add-flow  $@ table=0,in_port=4,actions=output:2
