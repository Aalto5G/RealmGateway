# Customer Edge Switching

## Requirements
iptables
ebtables
bridge-utils
libnfnetlink-dev
libnetfilter-queue-dev

python3.4 is required. Any lower version won't be supported.

## Package dependencies
### Install pip for python3
apt-get install python3-pip

### Install yaml
sudo pip3 install PyYAML --upgrade

#### Install dnspython
sudo pip3 install dnspython3 --upgrade

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



### How to install Python 3.5 under Ubuntu 14.04
sudo apt-get install software-properties-common python-software-properties
sudo add-apt-repository ppa:fkrull/deadsnakes
sudo apt-get update
sudo apt-get install python3.5

