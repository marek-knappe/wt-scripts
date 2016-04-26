#!/bin/env bash

############################################################################
# <+Heading+>
############################################################################


for i in $(cat /root/clamscans/scan.last | grep "FOUND" | cut -d":" -f1);
  do 
    new_dir="/root/abuse${i%/*}";
    mkdir -p "$new_dir";
    mv -v "$i" "$new_dir";
done

exit


