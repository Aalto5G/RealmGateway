#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo -E $0 $*"
    exit 1
fi

echo "Disabling Internet access via mgt0 interface"
ip route del default via 172.31.255.1
