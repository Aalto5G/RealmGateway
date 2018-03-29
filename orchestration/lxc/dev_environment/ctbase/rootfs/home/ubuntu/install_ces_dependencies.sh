#!/bin/bash

# Steps required to install CES/RGW in a Linux Container

## Install CES/RGW dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git build-essential python3-dev libnetfilter-queue-dev

pip3 install --upgrade pip setuptools
pip3 install pip-review ipython dnspython aiohttp scapy-python3 pyyaml NetfilterQueue ryu python-iptables pyroute2
### Update all pip packages
pip-review --auto -v
