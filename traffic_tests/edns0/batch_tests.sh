#!/bin/bash

# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi


###
# Create network namespaces for packet testing
###

PHY_NIC1="ens2f0"
PHY_NIC2="ens2f1"

# Create namespaces
ip netns add ns_send
ip netns add ns_recv
# Add links to namespaces
ip link set dev $PHY_NIC1 netns ns_send
ip link set dev $PHY_NIC2 netns ns_recv
# Configure network in namespaces
ip netns exec ns_send ip link set dev lo up
ip netns exec ns_send ip link set dev $PHY_NIC1 up
ip netns exec ns_send ip address add 10.10.10.1/30 dev $PHY_NIC1
ip netns exec ns_send ip route add default via 10.10.10.2

ip netns exec ns_recv ip link set dev lo up
ip netns exec ns_recv ip link set dev $PHY_NIC2 up
ip netns exec ns_recv ip address add 10.10.10.2/30 dev $PHY_NIC2
ip netns exec ns_recv ip route add default via 10.10.10.1

# Add sink0 interface to enable forwarding
ip netns exec ns_recv ip link add sink0 type dummy
ip netns exec ns_recv ip link set dev sink0 up
ip netns exec ns_recv ip route add 1.1.1.0/24 dev sink0
ip netns exec ns_recv sysctl -w net.ipv4.ip_forward=1


TCPREPLAY_EXEC="ip netns exec ns_send tcpreplay -i ens2f0 --rdtsc-clicks=2300 --pps=230000 --preload-pcap -K --loop=100000"
TCPREPLAY_BACKOFF=60
TCPREPLAY_PID=0

EDNS0TEST_EXEC="ip netns exec ns_recv ./edns0_tests.py --nic ens2f1 --test-iteration 5 --test-duration 10 --test-backoff 2 "
EDNS0TEST_DATAPOINTS1=" --datapoints 0 5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100 105 110 115 120 125 130 135 140 145 150"
EDNS0TEST_DATAPOINTS2=" --datapoints 0 10 20 30 40 50 60 70 80 90 100 110 120 130 140 150 160 170 180 190 200 210 220 230 240 250 260 270 280 290 300"

#PCAP_FILE="edns0.ens2f1.1dst.8M.pcap"
#$TCPREPLAY_EXEC $PCAP_FILE & export TCPREPLAY_PID=$!
#sleep $TCPREPLAY_BACKOFF
#$EDNS0TEST_EXEC $EDNS0TEST_DATAPOINTS1 > $PCAP_FILE.detailed.csv
#kill -9 $TCPREPLAY_PID
#sleep 5

#PCAP_FILES=( "edns0.ens2f1.1dst.8M.pcap" "edns0.ens2f1.8dst.8M.pcap" "edns0.ens2f1.16dst.8M.pcap" "edns0.ens2f1.24dst.8M.pcap" "edns0.ens2f1.32dst.8M.pcap" "edns0.ens2f1.64dst.8M.pcap" "edns0.ens2f1.128dst.8M.pcap" )
PCAP_FILES=( "edns0.ens2f1.8dst.8M.pcap" "edns0.ens2f1.16dst.8M.pcap" )
for PCAP_FILE in "${PCAP_FILES[@]}"
do
    echo "Iterating $PCAP_FILE file"
    $TCPREPLAY_EXEC $PCAP_FILE & export TCPREPLAY_PID=$!
    sleep $TCPREPLAY_BACKOFF
    $EDNS0TEST_EXEC $EDNS0TEST_DATAPOINTS2 > $PCAP_FILE.csv
    kill -9 $TCPREPLAY_PID
    sleep 5
done


# Cleanup namespaces
ip netns del ns_send
ip netns del ns_recv
