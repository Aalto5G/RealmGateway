#!/bin/bash

export RYU_PATH="/usr/local/lib/python3.5/dist-packages/ryu"

ryu-manager --ofp-listen-host 127.0.0.1 \
            --ofp-tcp-listen-port 6653  \
            --wsapi-host 127.0.0.1      \
            --wsapi-port 8081           \
            --verbose                   \
            $RYU_PATH/app/ofctl_rest.py
