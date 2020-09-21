![Blockheads image](/blockheads.jpg?raw=true)

# BLOCKHEADS

A script to:
- Generate UFW /16 deny rules based on log file entries and disconnect TCP sessions
- Import an allow/deny list and apply rules

## Introduction

This script is designed to ease the process of creating UFW
([Uncomplicated Firewall](https://wiki.ubuntu.com/UncomplicatedFirewall)) deny
rules. It looks at entries in netstat and auth.log to determine suspicious
connections.

## Notes

The script will look for a allowlist file in the same directory of the script if
a allowlist or allowlist file is not specified.

If a allowlist is not given it will exit.

## Requirements

Standard Python modules:

- argparse
- sys
- os
- re

Standard UNIX tools:

- netstat
- ss

## License

This software is licensed as
[CC-BA (Creative Commons By Attribution)](http://creativecommons.org/licenses/by/4.0/legalcode)

## Usage

```bash
usage: blockheads.py [-h] [--ports PORTS] [--delete DELETE] [--add ADD] [--allowlist ALLOWLIST] [--denylist DENYLIST] [--allowlistfile ALLOWLISTFILE]
                     [--denylistfile DENYLISTFILE] [--version] [--check] [--list] [--deny] [--allow] [--verbose] [--block] [--yes] [--import]

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS
  --delete DELETE
  --add ADD
  --allowlist ALLOWLIST
  --denylist DENYLIST
  --allowlistfile ALLOWLISTFILE
  --denylistfile DENYLISTFILE
  --version
  --check
  --list
  --deny
  --allow
  --verbose
  --block
  --yes
  --import
```

## Examples

```bash
./blockheads.py --check
sudo ufw insert 1 deny from XXX.XX.0.0/16 to any
sudo ufw insert 1 deny from XXX.XXX.0.0/16 to any
sudo /bin/ss -K dst XX.XX.XXX.249 dport = 64712
sudo /bin/ss -K dst XXX.XXX.XX.101 dport = 41444
```
