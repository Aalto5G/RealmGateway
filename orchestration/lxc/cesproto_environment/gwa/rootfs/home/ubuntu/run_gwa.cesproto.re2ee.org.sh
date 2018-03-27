#!/bin/bash

# Add route to UE network via vepc node
ip route add 192.168.145.0/24 via 192.168.0.2 > /dev/null

echo "Starting Realm Gateway as gwa.cesproto.re2ee.org"
export LOG_LEVEL=WARNING
cd /customer_edge_switching_v2/src
./rgw.py  --name             gwa.cesproto.re2ee.org                          \
          --dns-soa          gwa.cesproto.re2ee.org.                         \
                             cname-gwa.cesproto.re2ee.org.                   \
                             0.168.192.in-addr.arpa.                         \
                             125.148.195.in-addr.arpa.                       \
          --dns-cname-soa    gwa.cesproto.re2ee.org.                         \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   195.148.125.201 53                              \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.25 0.25 0.25                                  \
          --pool-serviceip   195.148.125.201/32                              \
          --pool-cpoolip     195.148.125.202/32 195.148.125.203/32 195.148.125.204/32 \
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
          --repository-subscriber-folder /customer_edge_switching_v2/config.d/gwa.cesproto.re2ee.org.subscriber.d/ \
          --repository-policy-folder     /customer_edge_switching_v2/config.d/gwa.cesproto.re2ee.org.policy.d/     \
          --repository-api-url  http://127.0.0.1:8082/                       \
          --network-api-url     http://127.0.0.1:8081/                       \
          --synproxy         172.31.255.14 12345
