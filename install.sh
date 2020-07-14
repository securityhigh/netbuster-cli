#!/bin/bash

sudo -s

# install arpspoof, python3 and xterm
apt-get -y install xterm dsniff
apt-get -y install python3 python3-dev python3-pip

pip3 install -r requirements.txt
# if not working, replace 'pip3' on the 'pip'
