# Iptables target modules

## Compilation of userpace module

Get souce package for iptables.

```
$ mkdir temp && cd temp
$ apt-get source iptables
```

Add both libxt_YOURMODULE.c and libxt_YOURMODULE.man to the ./extensions folder of the iptables source package.

```
$ cd iptables-X.Y.Z
$ cp /path/to/libxt_YOURMODULE.c ./extensions
$ cp /path/to/libxt_YOURMODULE.man ./extensions
```

## Installation of userpace module

### Installation of userpace module

Build and install the iptables module only by copying the shared library into the appropriate folder.

```
$ ./configure
$ make
# cp ./extensions/libxt_YOURMODULE.so /lib/xtables/libxt_YOURMODULE.so
# ldconfig
```

### Installation of full iptables with userpace module

Build and install the iptables package manually

```
$ ./configure
$ make
# make install
```

### Create redistributable deb package of iptables with userpace module

Build and create *deb* iptables package using automated tools

```
$ dpkg-buildpackage -B # To build redistributable deb package
$ cd ..
# dpkg -i iptables_X.Y.Z.deb iptables-dev_X.Y.Z.deb libxtables11_X.Y.Z.deb
```

## Verification

Verify the userspace module has been correctly installed

```
$ iptables -j libxt_YOURMODULE --help
```
