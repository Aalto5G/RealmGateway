#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo -E $0 $*"
    exit 1
fi

echo "Unmounting customer_edge_switching_v2 folder @host for synchronous work"
umount /customer_edge_switching_v2
rmdir /customer_edge_switching_v2
