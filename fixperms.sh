#! /bin/bash

unset ls

all_users=false
backupdir="/root/fixperms_backups_`date +%s`"
mkdir -p $backupdir

function fixperms
{
	local user=$1
	local home_dir=$2
	echo "Backing up permissions for $user"
	find $home_dir -printf 'chmod %#m "%p"\n' > ${backupdir}/${user}-perms_backup_`date +%s`.sh
	echo "Backing up ownerships for $user"
	find $home_dir -printf 'chown %u:%g "%p"\n' > ${backupdir}/${user}-owners_backup_`date +%s`.sh
	echo "Setting ownership for user $user"
	chown -R $user:$user $home_dir
	chmod 711 $home_dir
	chown $user:nobody $home_dir/public_html $home_dir/.htpasswds
	chown $user:mail $home_dir/etc $home_dir/etc/*/shadow $home_dir/etc/*/passwd
	echo "Setting permissions for all users"
	find $home_dir -type f -exec chmod 644 {} \; -print
	find $home_dir -type d -exec chmod 755 {} \; -print
	chmod 750 $home_dir/public_html
	find $home_dir -type d -name cgi-bin -exec chmod 755 {} \; -print
	find $home_dir -type f \( -name "*.pl" -o -name "*.perl" -o -name "*.cgi" \) -exec chmod 755 {} \; -print
}
	

if [ "$#" -lt "1" ]; then
	printf "Fix permissions for all cPanel users? Not a good idea! [Y/n]: "
	read
	case $REPLY in
		Y*|y*|"")
			all_users=true ;;
		N*|n*|*)
			echo 'No users specified!'
			exit 1 ;;
	esac
fi

if "$all_users"; then
	users=$(ls /var/cpanel/users)
else
	users=$@
fi

for user in $users; do
	domain=$(awk -F: '/ '$user'$/ { print $1 }' /etc/trueuserdomains)
	home_dir=$(awk -F: '/^homedir:/ { print $2 }' /var/cpanel/userdata/${user}/${domain})
	if [ "$home_dir" == "" ]; then
		echo "Couldn't determine home directory for $user" >&2
	elif ! (echo $home_dir | grep '^/home'); then
		printf "Home directory looks wrong: $home_dir. Skip this user? You really should! [Y/n]: " >&2
		read
		case $REPLY in 
			Y*|y*|"" ) echo Yes >&2 ;;
			N*|n* ) fixperms $user $home_dir ;;
		esac
	else
		fixperms $user $home_dir
	fi
done
