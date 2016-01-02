#!/bin/bash
#Fetch messages from mute msgdb

username=$(cat ~/.config/mute/MuttUser)

mkdir -p ~/.config/mute/MailDir/.Sent/{new,cur,tmp}
mkdir -p ~/.config/mute/MailDir/{new,cur,tmp}

exec 3<~/.config/mute/passphrase.f ; mutectrl msg fetch --id "${username}"
exec 3<~/.config/mute/passphrase.f ; mutectrl msg list --id "${username}" 2> /dev/null | while read entry; do 
	n=$(echo ${entry} | tr -s "<>\t\ /." "io...." )
	id=$(echo ${entry} | cut -d$'\t'  -f1 | cut -d\  -f2)
	if [ "${entry:0:2}" == "<S" ]; then
		# ToDo: Test that message has already been sent and not just queued for sending
		exec 3<~/.config/mute/passphrase.f ; mutectrl msg read --id "${username}" --msgid ${id} 2> /dev/null > ~/.config/mute/MailDir/.Sent/new/${n}
		exec 3<~/.config/mute/passphrase.f ; mutectrl msg delete --id "${username}" --msgid ${id}
	elif [ "${entry:0:2}" == ">N" ]; then
		exec 3<~/.config/mute/passphrase.f ; mutectrl msg read --id "${username}" --msgid ${id} 2> /dev/null > ~/.config/mute/MailDir/new/${n}
	else
		echo Error...Undirected message
	fi
done

