# Iptables module for Realm Gateway - MARKDNAT

## Installation of userpace MARKDNAT target

Get souce package for iptables.

```
$ mkdir temp && cd temp
$ apt-get source iptables
```

Add both xt_MARKDNAT.c and xt_MARKDNAT.man to the ./extensions folder of the iptables source package.

```
$ cd iptables-X.Y.Z
$ cp /path/to/xt_MARKDNAT.c ./extensions
$ cp /path/to/xt_MARKDNAT.man ./extensions
```

Build and install the package using automated tools

```
$ dpkg-buildpackage -B # To build redistributable deb package
$ cd ..
# dpkg -i iptables_X.Y.Z.deb iptables-dev_X.Y.Z.deb libxtables11_X.Y.Z.deb
```

Build and install the package manually

```
$ ./configure
$ make
# make install
```

Verify the userspace extension has been installed

```
$ iptables -j MARKDNAT --help
```


## How to use it

Remember you need to have the xt_MARKDNAT kernel module installed!

```
# iptables -t nat -A PREROUTING -m mark ! --mark 0 -j MARKDNAT --or-mark 0 --m comment --comment "DNAT to packet mark"
```
