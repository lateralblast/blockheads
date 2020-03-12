#!/usr/bin/env python3

# Name:         blockheads
# Version:      0.0.4
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

import argparse
import sys
import os
import re

# Environment information

script_exe  = sys.argv[0]

# Default ports to check

default_ports = "8080,22,443"

# Create UFW and netstat list

ufw_list = []
ns_list  = []

# Create whitelist

white_list = []

# Get current DENY list

def get_ufw_deny_list(ufw_list):
  command  = "sudo ufw status |grep DENY |awk '{print $3}'"
  ufw_list = os.popen(command).read()
  ufw_list = ufw_list.split("\n")
  return ufw_list

# Set up block list and commands

block_list     = []
block_commands = []

# Get invalid user attempts from auth log

def do_invalid_auth_checks(block_list,ufw_list,white_list,netstat_ports):
  if os.path.exists("/var/log/auth.log"):
    commands = []
    commands.append("sudo cat /var/log/auth.log |egrep 'Invalid user|no matching MAC|Unable to negotiate' |awk '{print $10}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |egrep 'Bad protocol|Did not receive identification string' |awk '{print $12}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Disconnected from authenticating user root' |awk '{print $11}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Connection closed by' |awk '{print $9}' |uniq |grep '^[0-9]'")
    command = "sudo netstat -tn 2>/dev/null | egrep '%s' | awk '{print $5}' | cut -d: -f1 | sort | uniq" % (netstat_ports)
    commands.append("sudo netstat -tn 2>/dev/null | egrep '8080|22|443' | awk '{print $5}' | cut -d: -f1 | sort | uniq")
    for command in commands:
      ip_list = os.popen(command).read()
      ip_list = ip_list.split("\n")
      for ip in ip_list:
        if re.search(r"[0-9]",ip):
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
  return block_list

# Create UFW block commands

def create_ufw_block_commands(block_list,block_command):
  for block_range in block_list:
    block_command = "sudo ufw insert 1 deny from %s to any" % (block_range) 
    block_commands.append(block_command)
  return block_commands

# Get TCP connections list

def get_netstat_tcp_connections(ns_list,netstat_ports):
  command = "sudo netstat -tn |egrep '%s' |awk '{print $5}' |grep ':[0-9]' |grep '^[0-9]'" % (netstat_ports)
  ns_list = os.popen(command).read()
  ns_list = ns_list.split("\n")
  return ns_list

# Create TCP disconnect commands

def create_tcp_disconnect_commands(ns_list,white_list,block_commands):
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
          block_commands.append(block_command)
  return block_commands

# Print help

def print_help(script_exe):
  print("\n")
  command = "%s -h" % (script_exe)
  os.system(command)
  print("\n")

# Read a file into an array

def file_to_array(file_name):
  file_data  = open(file_name)
  file_array = file_data.readlines()
  return file_array

# If we have no command line arguments print help

if sys.argv[-1] == sys.argv[0]:
  print_help(script_exe)
  exit()

parser = argparse.ArgumentParser()
parser.add_argument("--ports",required=False)               # Specify comma delimited ports for netstat to look at
parser.add_argument("--whitelist",required=False)           # Specify comma delimited whitelist on command line
parser.add_argument("--whitelistfile",required=False)       # Specify whitelist file to read
parser.add_argument("--version",action='store_true')        # Display version
parser.add_argument("--check",action='store_true')          # Do checks
parser.add_argument("--list",action='store_true')           # Do list
parser.add_argument("--verbose",action='store_true')           # Verbose mode
parser.add_argument("--block",action='store_true')          # Do blocks

option = vars(parser.parse_args())

# Print version

def print_version(script_exe):
  file_array = file_to_array(script_exe)
  version    = list(filter(lambda x: re.search(r"^# Version", x), file_array))[0].split(":")[1]
  version    = re.sub(r"\s+","",version)
  print(version)

# Print options

def print_options(script_exe):
  file_array = file_to_array(script_exe)
  opts_array = list(filter(lambda x:re.search(r"add_argument", x), file_array))
  print("\nOptions:\n")
  for line in opts_array:
    line = line.rstrip()
    if re.search(r"#",line):
      option = line.split('"')[1]
      info   = line.split("# ")[1]
      if len(option) < 8:
        string = "%s\t\t\t%s" % (option,info)
      else:
        if len(option) < 16:
          string = "%s\t\t%s" % (option,info)
        else:
          string = "%s\t%s" % (option,info)
      print(string)
  print("\n")

if option["version"]:
  print_version(script_exe)

if option["verbose"]:
  verbose_mode = True
else:
  verbose_mode = False

if option["whitelist"]:
  white_list = option["whitelist"]
  if re.search(r"\,",white_list):
    white_list = white_list.split(",")
  else:
    white_list[0] = white_list

if option["whitelistfile"]:
  white_list_file = option["whitelistfile"]
  if os.path.exists(white_list_file):
    white_list = file_to_array(white_list_file)
  else:
    string = "Whitelist file %s does not exist" % (white_list_file)
    exit
  if option["list"]:
    for ip in white_list:
      ip = ip.rstrip()
      print(ip)
    exit
else:
  if len(white_list) == 0:
    white_list_file = "./whitelist"
    if os.path.exists(white_list_file):
      white_list = file_to_array(white_list_file)
    else:
      print("No whitelist specified")
      exit

if option["list"]:
  for ip in white_list:
    ip = ip.rstrip()
    print(ip)
  exit
else:
  if verbose_mode == True:
    print("Adding White list:")
    for ip in white_list:
      ip = ip.rstrip()
      print(ip)

if option["ports"]:
  netstat_ports = option["ports"]
  netstat_ports = re.sub(r"\,","|",netstat_ports)
else:
  netstat_ports = default_ports
  netstat_ports = re.sub(r"\,","|",netstat_ports)

if verbose_mode == True:
  print("Adding ports:")
  ports = netstat_ports.split("|")
  for port in ports:
    print(port)

if option["check"]:
  ufw_list   = get_ufw_deny_list(ufw_list)
  block_list = do_invalid_auth_checks(block_list,ufw_list,white_list,netstat_ports)
  block_commands = create_ufw_block_commands(block_list,block_commands)
  ns_list = get_netstat_tcp_connections(ns_list,netstat_ports)
  block_commands = create_tcp_disconnect_commands(ns_list,white_list,block_commands)
  print("Block commands:")
  for block_command in block_commands:
    print(block_command)

if option["block"]:
  for block_command in block_commands:
    command = "%s | sh -x"
    output = os.popen(command).read()
    print(output)
