# netbuster 1.0.3
#### Description
The program requires root privileges.

The program is adapted for work in Linux environment. (Windows, Termux not tested)

It works on the basis of ARP spoofing, done without the use of third-party programs.

#### Install
```
> git clone https://github.com/securityhigh/netbuster
> cd netbuster
> pip install -r requirements.txt
```

#### Run
```
// For help.
> python3 netbuster.py --help

// Disconnect the entire local network from the Internet.
// Run until all devices are detected.
> python3 netbuster.py -i wlan0

// Disable individual users.
> python3 netbuster.py -i wlan0 -t target.txt
```

**-i** or **--interface** [required] - your network interface.

**-t** or **--target** - file with ip addresses, so as not to kill the entire subnet.



## Install on the system
```
> sudo chmod +x ./install.sh
> sudo ./install.sh
```

#### Run
```
> sudo netbuster [*arguments]
```

