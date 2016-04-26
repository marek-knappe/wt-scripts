#!/bin/env bash

############################################################################
# <+Heading+>
############################################################################

# echo "ssh -t $1 'screen -S qlamscan /usr/local/cpanel/3rdparty/bin/clamscan -ri | mail -s \"scan results\" ahodzic@wiredtree.com'"

# echo "ssh -t $1 'screen -S qlamscan /usr/local/cpanel/3rdparty/bin/clamscan -ri | mail -s \"scan results\" ahodzic@wiredtree.com'"
# ssh -t $1 'screen -S qlamscan /usr/local/cpanel/3rdparty/bin/clamscan -ri | mail -s \"scan results\" ahodzic@wiredtree.com'
ssh -t $1 'screen -S qlamscan /bin/clamscan -ri | mail -s \"scan results\" ahodzic@wiredtree.com'


