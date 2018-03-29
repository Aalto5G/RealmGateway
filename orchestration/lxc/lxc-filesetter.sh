#!/bin/bash

# Use: ./lxc-filesetter.sh containerName sourceFile destinationFile_absolutePath

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "$0 $*"
    exit 1
fi

LXC_NAME=$1
SRC_FILE=$2
DST_FILE=$3
SRC_FILE_ABS="$(realpath $SRC_FILE)"
DST_FILE_ABS="$(realpath $DST_FILE)"

echo "Copying file to container: $HOSTNAME#$SRC_FILE_ABS  $LXC_NAME#$DST_FILE_ABS"
sudo /bin/cat $SRC_FILE_ABS | sudo /usr/bin/lxc-attach -n $LXC_NAME -- /bin/bash -c "/bin/cat > $DST_FILE_ABS"

# Adjust file permissions in destination
SRC_STATS="$(stat --format '%a' $SRC_FILE_ABS)"
#echo "Stats $SRC_STATS"
sudo /usr/bin/lxc-attach -n $LXC_NAME -- /bin/chmod $SRC_STATS $DST_FILE_ABS
