![alt tag](https://raw.githubusercontent.com/lateralblast/blockheads/master/blockheads.jpg)

BLOCKHEADS
==========

A script to generate UFW /16 deny rules based on log file entries and disconnect TCP sessions

Introduction
------------

This tools is designed to easy the process of creating UFW deny rules.
It looks at entries in netstat and auth.log to determine suspicious connections.

Requirements
------------

Standard Python modules:
- argparse
- sys
- os
- re

Standard UNIX tools:
- netstat
- ss

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Usage
-----

```
usage: blockheads.py [-h] [--ports PORTS] [--version] [--check] [--block]

optional arguments:
  -h, --help     show this help message and exit
  --ports PORTS
  --whitelist WHITELIST
  --whitelistfile WHITELISTFILE
  --version
  --check
  --list
  --verbose
  --block
```

Examples
--------

```
./blockheads.py --check
sudo ufw insert 1 deny from XXX.XX.0.0/16 to any
sudo ufw insert 1 deny from XXX.XXX.0.0/16 to any
sudo /bin/ss -K dst XX.XX.XXX.249 dport = 64712
sudo /bin/ss -K dst XXX.XXX.XX.101 dport = 41444
```