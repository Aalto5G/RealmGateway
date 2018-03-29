#!/bin/bash

# Use: ./lxc-filegetter.sh containerName sourceFile_absolutePath destinationFile

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

echo "Copying file from container: $LXC_NAME#$SRC_FILE_ABS  $HOSTNAME#$DST_FILE_ABS"
sudo /usr/bin/lxc-attach -n $LXC_NAME -- /bin/bash -c "cat $SRC_FILE_ABS" > $DST_FILE_ABS

# Adjust file permissions in destination
SRC_STATS="$(sudo /usr/bin/lxc-attach -n $LXC_NAME -- /usr/bin/stat --format '%a' $SRC_FILE_ABS)"
#echo "Stats $SRC_STATS"
sudo /bin/chmod $SRC_STATS $DST_FILE_ABS
