#!/bin/bash

if [ "${1}" != "" ]; then
	echo "${1}" >  ~/.config/mute/MuttUser
fi

if [ ! -f ~/.config/mute/MuttUser ]; then
  echo "No username set. Call ${0} with username argument." >&2
  exit 1
fi

echo "WARNING: Usage of MuteMutt is insecure since the passphrase is chached on disk."
read -p "Passphrase: " -s passphrase
echo
echo "${passphrase}" > ~/.config/mute/passphrase.f

# check passphrase and fetch newest config
exec 3<~/.config/mute/passphrase.f ; mutectrl upkeep fetchconf
if [ ${?} -ne 0 ]; then
  exit 1
fi

echo Fetching messages...
MuteFetch.sh 2> /dev/null > /dev/null

# start Mutt
mutt -F ~/.config/mute/muttrc

rm ~/.config/mute/passphrase.f

