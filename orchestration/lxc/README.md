This project orchestrates a number of LXC containers to quickly define and deploy different networking setups.

# Installation of basic packages

The following packages are needed at the host level:


## Install python dependencies

```
# apt-get install python3-pip lxc
# pip3 install --upgrade pip setuptools
$ pip3 install pyyaml --user
```


# Configuration of supporting network

The deployment folder features a pre-up.sh script that is run prior to instantiating any containers.
This script should provide the necessary network architecture to deploy the virtual environment.
Beware of enabling internet access to the containers via NAT.
```
#iptables -t nat -I POSTROUTING -o nicName -j MASQUERADE
```


# Spawning a virtual environment

The script ```lxc-environment.py``` is configured to deploy the scenario indicated by the ```resources``` file.
This file is a symbolic link to any of the configured deployment folders.

The following command sets deployment2 folder as the target for deployment.

```
~/lxc-environment$ ln -snf deployment2 resources
```

The following command initiates the deployment.

```
~/lxc-environment# ./lxc-environment.py
```


## Understanding the file structure

Inside the folder of the deployment, there is a ```config``` file that defines the containers that will be created, software to be installed, services to enable/disable
and what scripts to run at boot. By default, there is a base container defined, in where we will install all the necesary software.
Then, for all the other containers defined, we will created linked copies of the base container to quickly spawn an environment.

Example of base container ```ctbase``` and ```router```

```
$ less config
ctbase:
  config: ctbase/config
  rootfs: ctbase/rootfs
  disabled_services: [bind9, vsftpd, nginx]
  enabled_services: [runatstartup]
  packages: [sudo, iptables, ipset, ulogd2, conntrack, openssh-server, nano, tmux, dnsutils, bind9, isc-dhcp-server, nginx-core]

router:
  config: router/config
  rootfs: router/rootfs
  packages: []
  disabled_services: []
  enabled_services: [bind9, vsftpd, nginx]
```

For each container, it is possible to define an lxc configuration file that modifies the base container.
In addition, it is also possible to create a diff root filesystem ```rootfs```, with new files that will be added to the container.


The following illustrates the file structure of an example base container ```ctbase```:

```
$ tree ctbase
ctbase/
├── config
└── rootfs
    ├── etc
    │   ├── network
    │   │   └── interfaces
    │   ├── resolv.conf
    │   └── systemd
    │       └── system
    │           └── runatstartup.service
    ├── home
    │   └── ubuntu
    │       ├── async_echoclient_v3.py
    │       ├── async_echoserver_v3.py
    │       └── dummyfile
    ├── lib
    │   └── xtables
    │       └── libxt_MARKDNAT.so
    ├── runatstartup
    └── sbin
        ├── flushEbtables
        ├── flushIp6tables
        ├── flushIpset
        └── flushIptables
```

The following illustrates the ```config``` file of a ```router``` container with several network interfaces:

```
$ cat router/config
# Network configuration
##
lxc.network.type = veth
lxc.network.veth.pair = router_eth0
lxc.network.link = lxcbr0
lxc.network.flags = up
##
lxc.network.type = veth
lxc.network.veth.pair = router_eth1
lxc.network.link = br-wan0
lxc.network.flags = up
lxc.network.ipv4 = 100.64.0.1/24
##
lxc.network.type = veth
lxc.network.veth.pair = router_eth2
lxc.network.link = br-wan1
lxc.network.flags = up
lxc.network.ipv4 = 100.64.1.1/24
##
lxc.network.type = veth
lxc.network.veth.pair = router_eth3
lxc.network.link = br-wan2
lxc.network.flags = up
lxc.network.ipv4 = 100.64.2.1/24
##
```
