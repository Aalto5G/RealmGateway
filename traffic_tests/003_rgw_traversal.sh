#!/bin/bash

# Usage: ./script.sh FQDN numberOfPackets sleep(sec)

echo "Initiation of new connections traversing the Realm Gateway"
echo ""
echo "Connecting to <$1>"
echo ""
echo "Press [CTRL+C] to stop.."
while :
do
	ipaddr=$(dig $1 +short | head -1)
	echo "Obtained IP address: $ipaddr"
	ping $ipaddr -c $2 -n
	sleep 1
done
