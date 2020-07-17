#!/bin/bash

# Check root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
    exit 1
fi

# Installation
sudo pip install -r requirements.txt
sudo cp netbuster.py /usr/local/bin/netbuster
sudo chmod +x /usr/local/bin/netbuster
