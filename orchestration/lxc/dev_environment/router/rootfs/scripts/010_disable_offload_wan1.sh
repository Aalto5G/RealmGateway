#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

# Disable offload in specific interfaces
for nic in wan1; do
    /sbin/disableOffload $nic 2> /dev/null
done
