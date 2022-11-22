# hostUpdater

hostUpdater is used to associate domains whit devices on a LAN. If the IP address of a device changes, the program will update the hosts file, assigning it the new IP. The program can also be used to add new domains to the hosts file or list them

## Requirements

- npcap (Not a python library)
- scapy
- requests

## Usage

Update the hosts file with new IPs 

`python.exe ./hostUpdate.py -u`

Lists hosts from the hosts file and the network

`python.exe ./hostUpdater.py -l`

Ads a new host to be auto updated

`python.exe ./hostUpdate.py -add [domain] [MAC]`

## Configuration

To make it work on your device, you probably would have to change the configuration of the `HOST_PATH` and `LAN_ADDRESS` variables

```
HOSTS_PATH = "C:\Windows\System32\drivers\etc\hosts"
LAN_ADDRESS = "192.168.1.0/24"
```

