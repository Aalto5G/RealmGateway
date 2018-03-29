#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo -E $0 $*"
    exit 1
fi

echo "Mounting customer_edge_switching_v2 folder @host for synchronous work"

# https://github.com/lxc/lxc/issues/80
mknod -m 666 /dev/fuse c 10 229

mkdir /customer_edge_switching_v2 -p
sshfs -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o allow_other ubuntu@172.31.255.1:/home/ubuntu/customer_edge_switching_v2/ /customer_edge_switching_v2
