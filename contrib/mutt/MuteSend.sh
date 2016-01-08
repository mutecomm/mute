#!/bin/bash
echo $* >> /tmp/sendlog
username=$(cat ~/.config/mute/MuttUser)

tonym=${2}
msgfile=$(mktemp)
cat - > ${msgfile}
exec 3<~/.config/mute/passphrase.f ; mutectrl contact add --id "${username}" --contact "${tonym}" 2>> /tmp/sendlog >> /tmp/sendlog
exec 3<~/.config/mute/passphrase.f ; mutectrl msg add --from "${username}" --to "${tonym}" --file ${msgfile} 2>> /tmp/sendlog >> /tmp/sendlog
echo "mutectrl msg add --from "${username}" --mail-input --file ${msgfile}" 2>> /tmp/sendlog >> /tmp/sendlog
rm ${msgfile}
exec 3<~/.config/mute/passphrase.f ; mutectrl msg send --id "${username}" 2>> /tmp/sendlog >> /tmp/sendlog
exit 0
