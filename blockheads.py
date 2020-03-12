#!/usr/bin/env python3

# Name:         blockheads
# Version:      0.0.1
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: UNIX
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A script to generate UFW /16 deny rules based on log file entries and disconnect TCP sessions

# Import modules

import os
import re

# Create whitelist

white_list = []

# Get current DENY list

command  = "sudo ufw status |grep DENY |awk '{print $3}'"
ufw_list = os.popen(command).read()
ufw_list = ufw_list.split("\n")

# Set up block list

block_list = []

# Get invalid user attempts from auth log

if os.path.exists("/var/log/auth.log"):
    commands = []
    commands.append("sudo cat /var/log/auth.log |egrep 'Invalid user|no matching MAC|Unable to negotiate' |awk '{print $10}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |egrep 'Bad protocol|Did not receive identification string' |awk '{print $12}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Disconnected from authenticating user root' |awk '{print $11}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Connection closed by' |awk '{print $9}' |uniq |grep '^[0-9]'")
    commands.append("sudo netstat -tn 2>/dev/null | egrep '8080|22|443' | awk '{print $5}' | cut -d: -f1 | sort | uniq")
    for command in commands:
        ip_list = os.popen(command).read()
        ip_list = ip_list.split("\n")
        for ip in ip_list:
            if not ip in ufw_list:
                if not ip in white_list:
                    octets   = ip.split(".")
                    block_ip = octets[0:2] 
                    block_ip = ".".join(block_ip)
                    block_range = "%s.0.0/16" % (block_ip)
                    if not block_range in ufw_list:
                        if not block_range in block_list:
                            if not block_range in white_list:
                                block_list.append(block_range)
# Create UFW block commands

for block_range in block_list:
    block_command = "sudo ufw insert 1 deny from %s to any" % (block_range) 
    print(block_command)

# Get TCP connections list

command = "sudo netstat -tn |egrep '8080|22' |awk '{print $5}' |grep ':[0-9]' |grep '^[0-9]'"
ns_list = os.popen(command).read()
ns_list = ns_list.split("\n")

# Create TCP disconnect commands

for ns_item in ns_list:
    if re.search(r":",ns_item):
        (ns_ip,ns_port) = ns_item.split(":")
        if not ns_ip in white_list:
            octets   = ns_ip.split(".")
            block_ip = octets[0:2] 
            block_ip = ".".join(block_ip)
            block_range = "%s.0.0/16" % (block_ip)
            if not block_range in white_list:
                block_command = "sudo /bin/ss -K dst %s dport = %s" % (ns_ip,ns_port)
                print(block_command)
