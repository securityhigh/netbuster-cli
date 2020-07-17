# netbuster
#### Description
The program requires root privileges.

The program is adapted only for work in Linux environment.

It works on the basis of ARP spoofing, done without the use of third-party programs.

The program cannot be detected by **arpwatch** and similar software that controls the change of the ARP table on the GATEWAY side.

#### Install
```
> git clone https://github.com/secwayz/netbuster
> cd netbuster
> pip install -r requirements.txt
```

#### Run
```
// For help.
> python3 netbuster.py --help

// Disconnect the entire local network from the Internet.
// With scanning.
> python3 netbuster.py -i wlan0 -g 192.168.1.1

// Disable individual users.
> python3 netbuster.py -i wlan0 -g 192.168.1.1 -t target.txt
```

**-i** or **--interface** [required] - your network interface.

**-g** or **--gateway** [required] - the gateway to which you are connected via the interface.

**-t** or **--target** - file with ip addresses, so as not to kill the entire subnet.

**-a** or **--attack-gateway** - flag, without value; increases attack efficiency, is not resistant to arpwatch from the GATEWAY side.




## Install on the system
```
> sudo chmod +x ./install.sh
> sudo ./install.sh
```

#### Run
```
> sudo netbuster [*arguments]
```

