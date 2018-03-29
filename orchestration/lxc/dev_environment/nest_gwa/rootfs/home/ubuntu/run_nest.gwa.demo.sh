#!/bin/bash

echo "Starting Realm Gateway as nest.gwa.demo"
export LOG_LEVEL=WARNING
cd /customer_edge_switching_v2/src
./rgw.py  --name             nest.gwa.demo                                   \
          --dns-soa          nest.gwa.demo.                                  \
                             10.168.192.in-addr.arpa. 0.168.192.in-addr.arpa.\
          --dns-cname-soa    nest.gwa.demo.                                  \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.10.1 53                                 \
          --dns-server-wan   192.168.0.10 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.25 0.25 0.25                                  \
          --pool-serviceip   192.168.0.10/32                                 \
          --pool-cpoolip     192.168.0.11/32 192.168.0.12/32 192.168.0.13/32 192.168.0.14/32 \
          --ipt-cpool-queue  1                                               \
          --ipt-cpool-chain  CIRCULAR_POOL                                   \
          --ipt-host-chain   CUSTOMER_POLICY                                 \
          --ipt-host-unknown CUSTOMER_POLICY_ACCEPT                          \
          --ipt-policy-order PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE     \
                             GROUP_POLICY CUSTOMER_POLICY                    \
                             ADMIN_POLICY ADMIN_POLICY_DHCP                  \
                             ADMIN_POLICY_HTTP ADMIN_POLICY_DNS              \
                             GUEST_SERVICES                                  \
          --ips-hosts        IPS_SUBSCRIBERS                                 \
          --ipt-markdnat                                                     \
          --ipt-flush                                                        \
          --repository-subscriber-folder /customer_edge_switching_v2/config.d/nest.gwa.demo.subscriber.d/ \
          --repository-policy-folder     /customer_edge_switching_v2/config.d/nest.gwa.demo.policy.d/     \
          --repository-api-url  http://127.0.0.1:8082/                       \
          --network-api-url     http://127.0.0.1:8081/
