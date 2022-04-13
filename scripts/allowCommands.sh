#!/bin/bash

# debug
#/home/rafal/rport-e2e-test/scripts/rport.conf

# comment out [remote-scripts]
sed -i 's/\[remote-scripts\]/  \#\[remote-scripts\]/g' /etc/rport/rport.conf

# replace  #order = ['allow','deny'] in [remote-commands]
# with   allow = ['.*']
sed -i "s/\#order = \['allow','deny'\]/allow = \['.*'\]/g" /etc/rport/rport.conf

# add [remote-scripts] and enable it
echo "  # now allow script execution" >> /etc/rport/rport.conf
echo "[remote-scripts]" >> /etc/rport/rport.conf
echo "  enabled = true" >> /etc/rport/rport.conf

# print config altered
cat /etc/rport/rport.conf