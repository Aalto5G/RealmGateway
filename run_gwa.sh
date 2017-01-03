#!/bin/bash

echo "Starting Realm Gateway as gwa.demo"

./rgw.py  --name gwa.demo                                                    \
          --dns-soa gwa.demo. 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.1.130 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.1 53                                    \
          --dns-timeout      0.010 0.100 0.200                               \
          --pool-serviceip   100.64.1.130/32                                 \
          --pool-cpoolip     100.64.1.133/32 100.64.1.134/32 100.64.1.135/32 \
          --ipt-cpool-queue  1 2 3                                           \
          --ipt-cpool-chain  PREROUTING                                      \
          --ipt-host-chain   CUSTOMER_POLICY                                 \
          --ipt-host-unknown CUSTOMER_POLICY_ACCEPT                          \
          --ipt-policy-order PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE     \
                             CUSTOMER_POLICY ADMIN_POLICY ADMIN_POLICY_DHCP  \
                             ADMIN_POLICY_HTTP ADMIN_POLICY_DNS              \
          --repository-subscriber-file   gwa.subscriber.yaml                 \
          --repository-subscriber-folder gwa.subscriber.d/                   \
          --repository-policy-file       gwa.policy.yaml
