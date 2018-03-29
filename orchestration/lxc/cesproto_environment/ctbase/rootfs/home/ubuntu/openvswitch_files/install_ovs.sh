# Add this at the beginning of the script to assure you run it with sudo
if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "Installing OpenvSwitch"
dpkg -i libopenvswitch_*.deb  openvswitch-switch_*.deb openvswitch-common_*.deb
