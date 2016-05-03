#!/bin/sh
pwgen () { openssl rand -base64 12 ; }
getip () { ip a | grep inet\  | grep -v 127.0.0.1 | head -n 1 | cut -f 1 -d / | awk '{print $2}' ; }

PASSPHRASE=$(pwgen)
PASSWORD=$(pwgen)

# create user
useradd sshuser --gid 10  -m
echo "$PASSWORD" | passwd sshuser --stdin
# setup ssh
ssh-keygen -C "wiredtree login" -f sshuser -q -P "$PASSPHRASE" -t rsa
mkdir -pv /home/sshuser/.ssh/
cp -v sshuser.pub /home/sshuser/.ssh/authorized_keys
chmod 600 /home/sshuser/.ssh/authorized_keys
chown sshuser:wheel /home/sshuser/.ssh -R

# get needed info on screen
cat sshuser
echo Passphrase $PASSPHRASE
echo Password $PASSWORD
grep ^Port /etc/ssh/sshd_config
hostname
getip

