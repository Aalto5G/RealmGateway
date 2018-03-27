#!/bin/bash

echo "Adding lxc-start profile to Apparmor"
rm /etc/apparmor.d/disabled/usr.bin.lxc-start
apparmor_parser --add /etc/apparmor.d/usr.bin.lxc-start

for NIC in br-wan0 br-wan1 br-wan2 br-wan1p br-wan2p br-lan0a br-lan0b br-lan1a br-lan1b
do
  echo "Removing $NIC"
  ip link del dev $NIC 2> /dev/null
done


echo "Removing lxcmgt0"
ip link del dev lxcmgt0 2> /dev/null

echo "Removing public interface"
ip link set dev ens19 nomaster
