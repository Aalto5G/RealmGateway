# Customer Edge Switching

## Requirements

Customer Edge Switching v.0.2 requires Ubuntu 16.04 and Python3


## Package dependencies

Install the following packages with apt-get install under Ubuntu 16.04:

ipset libipset3 ebtables bridge-utils
ipsec-tools openvswitch-common openvswitch-ipsec openvswitch-switch python-openvswitch racoon
python-pip python3-pip

### Create python virtual environment

Create a virtualenv for python3 using the following guide: 
http://askubuntu.com/questions/244641/how-to-set-up-and-use-a-virtual-python-environment-in-ubuntu


Install the packages for python3 within the virtualenv
pip install --upgrade PyYAML
pip install --upgrade dnspython3
pip install --upgrade pycrypto
pip install --upgrade python-iptables
pip install --upgrade aiohttp


Install python-netfilterqueue in virtualenv from github repository
URL: https://github.com/kti/python-netfilterqueue
Applied patch 12 for Python3 support
Requires: libnetfilter-queue-dev
python3 setup.py install

Install python-scapy in virtualenv from github repository
URL: https://github.com/phaethon/scapy
python3 setup.py install



## How to load the iptables kernel modules
sudo modprobe br_netfilter
sudo modprobe xt_physdev

## Modifying sysctl.conf configuration for bridge
net.bridge.bridge-nf-call-arptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-filter-pppoe-tagged=0
net.bridge.bridge-nf-filter-vlan-tagged=0
net.bridge.bridge-nf-pass-vlan-input-dev=0

