#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

# Enable test network addressing for traffic generation
## Add 4 test networks with 10 host IP addresses
ip address add 1.1.1.1/32 dev wan0
ip address add 1.1.1.2/32 dev wan0
ip address add 1.1.1.3/32 dev wan0
ip address add 1.1.1.4/32 dev wan0
ip address add 1.1.1.5/32 dev wan0
ip address add 1.1.1.6/32 dev wan0
ip address add 1.1.1.7/32 dev wan0
ip address add 1.1.1.8/32 dev wan0
ip address add 1.1.1.9/32 dev wan0
ip address add 1.1.1.10/32 dev wan0

ip address add 1.1.2.1/32 dev wan0
ip address add 1.1.2.2/32 dev wan0
ip address add 1.1.2.3/32 dev wan0
ip address add 1.1.2.4/32 dev wan0
ip address add 1.1.2.5/32 dev wan0
ip address add 1.1.2.6/32 dev wan0
ip address add 1.1.2.7/32 dev wan0
ip address add 1.1.2.8/32 dev wan0
ip address add 1.1.2.9/32 dev wan0
ip address add 1.1.2.10/32 dev wan0

ip address add 1.1.3.1/32 dev wan0
ip address add 1.1.3.2/32 dev wan0
ip address add 1.1.3.3/32 dev wan0
ip address add 1.1.3.4/32 dev wan0
ip address add 1.1.3.5/32 dev wan0
ip address add 1.1.3.6/32 dev wan0
ip address add 1.1.3.7/32 dev wan0
ip address add 1.1.3.8/32 dev wan0
ip address add 1.1.3.9/32 dev wan0
ip address add 1.1.3.10/32 dev wan0

ip address add 1.1.4.1/32 dev wan0
ip address add 1.1.4.2/32 dev wan0
ip address add 1.1.4.3/32 dev wan0
ip address add 1.1.4.4/32 dev wan0
ip address add 1.1.4.5/32 dev wan0
ip address add 1.1.4.6/32 dev wan0
ip address add 1.1.4.7/32 dev wan0
ip address add 1.1.4.8/32 dev wan0
ip address add 1.1.4.9/32 dev wan0
ip address add 1.1.4.10/32 dev wan0

