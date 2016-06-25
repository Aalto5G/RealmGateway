#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "This script uses functionality which requires root privileges"
    exit 1
fi

IPSET="/sbin/ipset"

$IPSET -F
$IPSET -X
