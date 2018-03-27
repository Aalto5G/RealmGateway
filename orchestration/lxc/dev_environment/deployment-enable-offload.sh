#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi


echo "Disabling offload in LXC containers of deployment"
while read ctname; do
    echo "Analyzing container $ctname..."
    # Get list of all network interfaces
    CT_NICS="$(lxc-attach -n $ctname -- tail -n+3 /proc/net/dev | cut --delimiter=: -f 1 | awk '{ print $1}')"
    for nic in $CT_NICS; do
        echo "    > Disabling offload $nic@$ctname"
        lxc-attach -n $ctname -- /sbin/enableOffload $nic 2> /dev/null
    done
done <CONTAINERS
