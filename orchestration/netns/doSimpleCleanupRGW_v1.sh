#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

###############################################################################
# Remove supporting infrastructure for single instance of Realm Gateway
###############################################################################

# [COMMON]
## WAN side
ip link set dev ns-wan0 down
ip link del dev ns-wan0
ip link set dev ns-wan1 down
ip link del dev ns-wan1
# [RealmGateway-A]
## LAN side
ip link set dev ns-lan0a down
ip link del dev ns-lan0a


###############################################################################
# Create network namespace configuration
###############################################################################

#Create the default namespace
ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in test_gwa gwa router public; do
    #Remove namespaces
    ip netns del $i > /dev/null 2> /dev/null
done
