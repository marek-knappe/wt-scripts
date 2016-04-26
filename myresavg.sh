#!/bin/env bash

############################################################################
# <+Heading+>
############################################################################

#debugging?
set -xv

# total=`/bin/ls -1 /var/log/sa/sa[0-3]*`
Count=`/bin/ls -Alh /var/log/sa/sa[0-3]* |wc -l`
# echo $Count

# echo $total



exit


