# Customer Edge Switching

## Requirements

This version of Customer Edge Switching v2.0 has been developed under 
Ubuntu 16.04 and python3 for asynchronous calls.


## Install package dependencies

The following dependencies are required:

```
# apt-get install build-essential python3-dev libnetfilter-queue-dev python3-pip
# apt-get install ipset libipset3 iptables ipset ebtables bridge-utils
# apt-get install ipsec-tools openvswitch-common openvswitch-ipsec openvswitch-switch python-openvswitch racoon
```


The following python dependencies are required:

```
$ pip3 install --upgrade pip setuptools 
$ pip3 install --upgrade ipython dnspython aiohttp scapy-python3 pyyaml NetfilterQueue ryu python-iptables --user
```

## Build & install the iptables modules

The Realm Gateway uses a tailor made module for an iptables extension target, MARKDNAT, which requires both a user space and a kernel module.
This extension can only be used in table nat and PREROUTING chain. The target implements the normal actions
of MARK, regarding the skb->mark mangling and DNAT --to-destination A.B.C.D with the resulting mark.

This extension allows performing the DNAT operation based on the packet mark. 
The packet mark can be controlled as well from a user space application via NFQUEUE target.

Installing the kernel module

```
$ cd ./iptables_devel/kernel
$ make
# make install_MARKDNAT 
```

Installing the user space module

```
# cp ./iptables_devel/userspace/libxt_MARKDNAT.so /lib/xtables/
$ iptables -j MARKDNAT --help
```


## Useful information

### Create python virtual environment

If you don't want to populute your system with extra libraries and modules, you can can create a python virtual environment using the following guide:

http://askubuntu.com/questions/244641/how-to-set-up-and-use-a-virtual-python-environment-in-ubuntu

Remember that the virtual environment shortcuts are not available when doing ```sudo``` per se, but you can achieve admin rights for your python interpreter with the following:

```
$ sudo /root/to/.virtualenvs/your_virtual_environment/bin/python
```

### Linux bridged & iptables

It is very common to deploy Linux bridges to trigger iptables packet processing to that traffic.
However, additional kernel modules need to be loaded.

```
# modprobe br_netfilter
# modprobe xt_physdev
```

In order to send traffic from the linux bridge to iptables modify your ```/etc/sysctl.conf``` to include the following:

```
net.bridge.bridge-nf-call-arptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-filter-pppoe-tagged=0
net.bridge.bridge-nf-filter-vlan-tagged=1
net.bridge.bridge-nf-pass-vlan-input-dev=1
```
