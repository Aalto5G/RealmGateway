#!/bin/bash

echo "Starting Realm Gateway as gwb.demo"
export LOG_LEVEL=WARNING
cd /customer_edge_switching_v2/src
./rgw.py  --name             gwb.demo                                        \
          --dns-soa          gwb.demo. cname-gwb.demo.                       \
                             0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa.  \
          --dns-cname-soa    cname-gwb.demo.                                 \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.2.130 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.25 0.25 0.25                                  \
          --pool-serviceip   100.64.2.130/32                                 \
          --pool-cpoolip     100.64.2.131/32 100.64.2.132/32 100.64.2.133/32 \
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
          --repository-subscriber-folder /customer_edge_switching_v2/config.d/gwb.demo.subscriber.d/ \
          --repository-policy-folder     /customer_edge_switching_v2/config.d/gwb.demo.policy.d/     \
          --repository-api-url  http://127.0.0.1:8082/                       \
          --network-api-url     http://127.0.0.1:8081/                       \
          --synproxy         172.31.255.15 12345
