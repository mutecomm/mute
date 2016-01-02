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
echo Fetching....
MuteFetch.sh 2> /dev/null > /dev/null

# start Mutt
mutt -F ~/.config/mute/muttrc

rm ~/.config/mute/passphrase.f

