# netbuster 1.0.3
#### Description
The program requires root privileges.

The program is adapted for work only in Linux environment.

It works on the basis of ARP spoofing, done without the use of third-party programs.

#### Install
```
> git clone https://github.com/securityhigh/netbuster-cli
> cd netbuster
> pip install -r requirements.txt
```

#### Run
```
// For help.
> sudo python3 netbuster.py --help

// Disconnect the entire local network from the Internet.
// Run until all devices are detected.
> sudo python3 netbuster.py -i wlan0

// Disable individual users.
> sudo python3 netbuster.py -i wlan0 -t target.txt
```

**-i** or **--interface** - your network interface.

**-t** or **--target** - file with ip addresses, so as not to kill the entire subnet.

**-p** or **--ping** - set custom delay for ping scanner. (default: 2s)


## Install on the system
```
> sudo chmod +x ./install.sh
> sudo ./install.sh
```

#### Run
```
> sudo netbuster [*arguments]
```

