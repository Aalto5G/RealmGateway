#!/bin/bash


echo "Enabling necesary kernel modules for CES/RealGateway"
for MODULE in sctp nf_conntrack_proto_sctp xt_sctp xt_MARKDNAT netmap openvswitch
do
  echo "> modprobe $MODULE"
  modprobe $MODULE
done
echo ""

echo "Remove lxc-start profile from Apparmor"
apparmor_parser --remove /etc/apparmor.d/usr.bin.lxc-start
ln -s /etc/apparmor.d/usr.bin.lxc-start /etc/apparmor.d/disabled/

echo ""
for NIC in br-wan0 br-wan1 br-wan2 br-wan1p br-wan2p br-lan0a br-lan0b br-lan1a br-lan1b
do
  echo "Setting up $NIC"
  ip link del dev $NIC 2> /dev/null
  ip link add dev $NIC type bridge forward_delay 0
  ip link set dev $NIC up
done


echo "Setting up lxcmgt0"
ip link del dev lxcmgt0 2> /dev/null
ip link add dev lxcmgt0 type bridge forward_delay 0
ip link set dev lxcmgt0 up
ip address add 172.31.255.1/24 dev lxcmgt0

echo "Setting up public interface"
ip link set dev ens19 master br-wan1
