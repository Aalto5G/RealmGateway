#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "This script uses functionality which requires root privileges"
    exit 1
fi

IPT="/sbin/ebtables"

$IPT -F
$IPT -X
$IPT -t filter -F
$IPT -t filter -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t broute -F
$IPT -t broute -X
