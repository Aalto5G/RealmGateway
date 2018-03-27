#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

# Get list of all network interfaces
NICS="$(tail -n+3 /proc/net/dev | cut --delimiter=: -f 1 | awk '{ print $1}')"
for nic in $NICS; do
    /sbin/disableOffload $nic 2> /dev/null
done
