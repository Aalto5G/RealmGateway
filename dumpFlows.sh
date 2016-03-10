#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "# Dumping flows from $@"
ovs-ofctl --protocols=OpenFlow13 dump-flows $@
