#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "# Deleting all flows from $@"
ovs-ofctl --protocols=OpenFlow13 del-flows $@
