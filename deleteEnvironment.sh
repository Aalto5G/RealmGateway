###############################################################################
# Remove supporting infrastructure for CES-A & CES-B
###############################################################################

# [CES-A]
## LAN side
sudo ip link set dev qbr-int-lana    down
sudo ip link set dev qve-phy-lana    down
sudo ip link set dev qve-l2-lana     down
sudo ip link del qve-phy-lana
sudo brctl delbr qbr-int-lana

## WAN side
sudo ip link set dev qbr-int-wan     down
sudo ip link set dev qve-phy-wana    down
sudo ip link set dev qve-l2-wana     down
sudo ip link del qve-phy-wana
sudo brctl delbr qbr-int-wan

## TUN side
sudo ip link set dev qve-phy-tuna    down
sudo ip link set dev qve-l2-tuna     down
sudo ip link del qve-phy-tuna
sudo ovs-vsctl --if-exists del-br qbr-int-tuna

# [CES-B]
## LAN side
sudo ip link set dev qbr-int-lanb    down
sudo ip link set dev qve-phy-lanb    down
sudo ip link set dev qve-l2-lanb     down
sudo ip link del qve-phy-lanb
sudo brctl delbr qbr-int-lanb

## WAN side
sudo ip link set dev qbr-int-wan     down
sudo ip link set dev qve-phy-wanb    down
sudo ip link set dev qve-l2-wanb     down
sudo ip link del qve-phy-wanb
sudo brctl delbr qbr-int-wan

## TUN side
sudo ip link set dev qve-phy-tunb    down
sudo ip link set dev qve-l2-tunb     down
sudo ip link del qve-phy-tunb
sudo ovs-vsctl --if-exists del-br qbr-int-tunb


###############################################################################
# Remove CES-A configuration
###############################################################################

## LAN side
sudo ip link set dev qbr-filter-lana down
sudo ip link set dev qve-l3-lana     down
sudo ip link set dev l3-lana         down
sudo ip link del qve-l3-lana
sudo brctl delbr qbr-filter-lana

## WAN side
sudo ip link set dev qbr-filter-wana down
sudo ip link set dev qve-l3-wana     down
sudo ip link set dev l3-wana         down
sudo ip link del qve-l3-wana 
sudo brctl delbr qbr-filter-wana

## TUN side
sudo ip link set dev qbr-filter-tuna down
sudo ip link set dev qve-l3-tuna     down
sudo ip link set dev l3-tuna         down
sudo ip link del qve-l3-tuna
sudo brctl delbr qbr-filter-tuna

###############################################################################
# Remove CES-B configuration
###############################################################################

## LAN side
sudo ip link set dev qbr-filter-lanb down
sudo ip link set dev qve-l3-lanb     down
sudo ip link set dev l3-lanb         down
sudo ip link del qve-l3-lanb
sudo brctl delbr qbr-filter-lanb

## WAN side
sudo ip link set dev qbr-filter-wanb down
sudo ip link set dev qve-l3-wanb     down
sudo ip link set dev l3-wanb         down
sudo ip link del qve-l3-wanb 
sudo brctl delbr qbr-filter-wanb

## TUN side
sudo ip link set dev qbr-filter-tunb down
sudo ip link set dev qve-l3-tunb     down
sudo ip link set dev l3-tunb         down
sudo ip link del qve-l3-tunb
sudo brctl delbr qbr-filter-tunb


###############################################################################
# Remove network namespace configuration
###############################################################################

#Create the default namespace
sudo ln -s /proc/1/ns/net /var/run/netns/default > /dev/null 2> /dev/null

for i in nslana nslanb nswan; do
    ##Remove and create new namespaces
    sudo ip netns del $i > /dev/null 2> /dev/null
done
