# Iptables target module for Realm Gateway - MARKDNAT

The module can be compiled and installed following the general indications of the README file

## Verification

Verify the userspace module has been correctly installed

```
$ iptables -j MARKDNAT --help
```


## How to use it

Remember you need to have the xt_MARKDNAT kernel module installed!

```
# iptables -t nat -A PREROUTING -m mark ! --mark 0 -j MARKDNAT --or-mark 0 --m comment --comment "DNAT to packet mark"
```
