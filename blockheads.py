#!/usr/bin/env python3

# Name:         blockheads
# Version:      0.1.0
# Release:      1
# License:      CC-BA (Creative Commons By Attribution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: UNIX
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  A script to generate UFW /16 deny rules based on log file
#               entries and disconnect TCP sessions


# Import modules
import argparse
import sys
import os
import re


# Environment information
script_exe = sys.argv[0]
script_dir = os.path.dirname(script_exe)


# Default ports to check
default_ports = "22,443"


# Create UFW and netstat list
ufw_list = []
ns_list  = []


# Create allow list and set default allow list file
allow_list = []
allow_list_file = "/etc/allowlist"
if not os.path.exists(allow_list_file):
  allow_list_file = "%s/allowlist" % (script_dir)


# Create deny list and get get default deny list
deny_list = []
deny_list_file = "/etc/denylist"
if not os.path.exists(deny_list_file):
  deny_list_file = "%s/denylist" % (script_dir)


# Get current DENY list
def get_ufw_deny_list(ufw_list):
  command  = "sudo ufw status |grep DENY |awk '{print $3}'"
  ufw_list = os.popen(command).read()
  ufw_list = ufw_list.split("\n")
  return ufw_list


# Set up block list and commands
deny_list   = []
ufw_commands = []


# Get invalid user attempts from auth log
def do_invalid_auth_checks(deny_list, ufw_list, allow_list, netstat_ports):
  if os.path.exists("/var/log/auth.log"):
    commands = []
    commands.append("sudo cat /var/log/auth.log |egrep 'Invalid user|no matching MAC|Unable to negotiate' |awk '{print $10}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |egrep 'Bad protocol|Did not receive identification string' |awk '{print $12}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Disconnected from authenticating user root' |awk '{print $11}' |uniq |grep '^[0-9]'")
    commands.append("sudo cat /var/log/auth.log |grep 'Connection closed by' |awk '{print $9}' |uniq |grep '^[0-9]'")
    command = "sudo netstat -tn 2>/dev/null | egrep '%s' | awk '{print $5}' | cut -d: -f1 | sort | uniq" % (netstat_ports)
    commands.append("sudo netstat -tn 2>/dev/null | egrep '8080|22|443' | awk '{print $5}' | cut -d: -f1 | sort | uniq")
    for command in commands:
      test_list = os.popen(command).read()
      test_list = test_list.split("\n")
      for test_ip in test_list:
        if re.search(r"[0-9]", test_ip):
          if test_ip not in ufw_list:
            if test_ip not in allow_list:
              block_oc = test_ip.split(".")
              block_08 = block_oc[0:1]
              block_08 = ".".join(block_08)
              check_08 = block_08
              block_08 = "%s.0.0.0/8" % (block_08)
              block_16 = block_oc[0:2]
              block_16 = ".".join(block_16)
              check_16 = block_16
              block_16 = "%s.0.0/16" % (block_16)
              block_24 = block_oc[0:3]
              block_24 = ".".join(block_24)
              check_24 = block_24
              block_24 = "%s.0/24" % (block_24)
              found_08 = False
              found_16 = False
              found_24 = False
              found_it = False
              for white_ip in allow_list:
                white_oc = white_ip.split(".")
                white_08 = white_oc[0:1]
                white_08 = ".".join(white_08)
                white_16 = white_oc[0:2]
                white_16 = ".".join(white_16)
                white_24 = white_oc[0:3]
                white_24 = ".".join(white_24)
                if white_08 == check_08:
                  found_08 = True
                if white_16 == check_16:
                  found_16 = True
                if white_24 == check_24:
                  found_24 = True
              if found_08 is True and found_16 is True and found_24 is True:
                found_it = True
              else:
                if found_08 is False and found_16 is False and found_24 is False:
                  block_range = block_08
                else:
                  if found_08 is True and found_16 is False and found_24 is False:
                    block_range = block_16
                  else:
                    found_it = True
              if found_it is False:
                if block_range not in ufw_list:
                  if block_range not in deny_list:
                    if block_range not in allow_list:
                      deny_list.append(block_range)
  return deny_list


# Create UFW block commands
def create_ufw_block_commands(deny_list, allow_list, ufw_commands, netstat_ports):
  for deny_range in deny_list:
    port_nos = []
    if not re.search(r"^#",deny_range):
      if re.search(r"\d",netstat_ports):
        if re.search(r"\s+",deny_range):
          check_range = deny_range.split()[0]
        else:
          check_range = deny_range
          if re.search(r"\|",netstat_ports):
            port_nos = netstat_ports.split("|")
          else:
            port_nos[0] = netstat_ports
      else:
        if re.search(r"\s+",deny_range):
          port_nos = allow_list.split()[1]
          if re.search(r",",port_nos):
            port_nos = port_nos.split(",")
          else:
            port_nos[0] = port_nos
      if not check_range in allow_list:
        if len(port_nos) > 0:
          for port_no in port_nos:
            ufw_command = "sudo ufw insert 1 deny from %s to any port %s" % (deny_range, port_no)
            ufw_commands.append(ufw_command)
        else: 
          ufw_command = "sudo ufw insert 1 deny from %s to any" % (deny_range)
          ufw_commands.append(ufw_command)
  return ufw_commands


# Create ufw allow commands
def create_ufw_allow_commands(deny_list, allow_list, ufw_commands, netstat_ports):
  for allow_range in allow_list:
    port_nos = []
    if not re.search(r"^#",allow_range):
      if re.search(r"\d",netstat_ports):
        if re.search(r"\s+",allow_range):
          check_range = allow_range.split()[0]
        else:
          check_range = allow_range
          if re.search(r"\|",netstat_ports):
            port_nos = netstat_ports.split("|")
          else:
            port_nos[0] = netstat_ports
      else:
        if re.search(r"\s+",allow_range):
          port_nos = allow_list.split()[1]
          if re.search(r",",port_nos):
            port_nos = port_nos.split(",")
          else:
            port_nos[0] = port_nos
      if not check_range in deny_list:
        if len(port_nos) > 0:
          for port_no in port_nos:
            ufw_command = "sudo ufw insert 1 allow from %s to any port %s" % (allow_range, port_no)
            ufw_commands.append(ufw_command)
        else: 
          ufw_command = "sudo ufw insert 1 allow from %s to any" % (allow_range)
          ufw_commands.append(ufw_command)
  return ufw_commands


# Get TCP connections list
def get_netstat_tcp_connections(ns_list, netstat_ports):
  command = "sudo netstat -tn |egrep '%s' |awk '{print $5}' |grep ':[0-9]' |grep '^[0-9]'" % (netstat_ports)
  ns_list = os.popen(command).read()
  ns_list = ns_list.split("\n")
  return ns_list


# Create TCP disconnect commands
def create_tcp_disconnect_commands(ns_list, allow_list, ufw_commands):
  for ns_item in ns_list:
    if re.search(r":", ns_item):
      (test_ip, ns_port) = ns_item.split(":")
      if test_ip not in ufw_list:
        if test_ip not in allow_list:
          block_oc = test_ip.split(".")
          block_08 = block_oc[0:1]
          block_08 = ".".join(block_08)
          check_08 = block_08
          block_08 = "%s.0.0.0/8" % (block_08)
          block_16 = block_oc[0:2]
          block_16 = ".".join(block_16)
          check_16 = block_16
          block_16 = "%s.0.0/16" % (block_16)
          block_24 = block_oc[0:3]
          block_24 = ".".join(block_24)
          check_24 = block_24
          block_24 = "%s.0/24" % (block_24)
          found_08 = False
          found_16 = False
          found_24 = False
          found_it = False
          for white_ip in allow_list:
            white_oc = white_ip.split(".")
            white_08 = white_oc[0:1]
            white_08 = ".".join(white_08)
            white_16 = white_oc[0:2]
            white_16 = ".".join(white_16)
            white_24 = white_oc[0:3]
            white_24 = ".".join(white_24)
            if white_08 == check_08:
              found_08 = True
            if white_16 == check_16:
              found_16 = True
            if white_24 == check_24:
              found_24 = True
          if found_08 is True and found_16 is True and found_24 is True:
            found_it = True
          else:
            if found_08 is False and found_16 is False and found_24 is False:
              block_range = block_08
            else:
              if found_08 is True and found_16 is False and found_24 is False:
                block_range = block_16
              else:
                found_it = True
          if found_it is False:
            if block_range not in ufw_list:
              if block_range not in deny_list:
                if block_range not in allow_list:
                  block_command = "sudo /bin/ss -K dst %s dport = %s" % (test_ip, ns_port)
                  if block_command not in ufw_commands:
                    ufw_commands.append(block_command)
  return ufw_commands


# Add IP to allowlist
def add_to_allow_list(allow_list_file, force_mode, add_ip):
  if add_ip not in allow_list:
    if allow_list_file == "/etc/allowlist":
      command = "sudo echo '%s' >> %s " % (add_ip, allow_list_file)
    else:
      command = "echo '%s' >> %s " % (add_ip, allow_list_file)
    if force_mode is True:
      output  = os.popen(command).read()
      print(output)
    else:
      print("Command:")
  else:
    string = "Entry '%s' already in white list file '%s'" % (add_ip, allow_list_file)
    print(string)
  return


# Delete deny rule
def delete_ufw_deny_rule(delete_rule, force_mode, verbose_mode):
  if verbose_mode is True:
    command = "sudo ufw status numbered |grep '%s'" % (delete_rule)
    output  = os.popen(command).read()
    print("Found Rule:")
    print(output)
  command = "sudo ufw status numbered |grep '%s' |awk '{print $1}' |cut -f2 -d[ |cut -f1 -d]" % (delete_rule)
  rule_no = os.popen(command).read()
  rule_no = rule_no.split("\n")
  rule_no = rule_no[0]
  if re.search(r"[0-9]", rule_no):
    if force_mode is True:
      command = "echo y |sudo ufw delete %s" % (rule_no)
      output  = os.popen(command).read()
      print(output)
    else:
      if verbose_mode is True:
        print("Command:")
      command = "sudo ufw delete %s" % (rule_no)
      print(command)
  return


# Print help
def print_help(script_exe):
  print("\n")
  command = "%s -h" % (script_exe)
  os.system(command)
  print("\n")
  return


# Read a file into an array
def file_to_array(file_name):
  with open(file_name) as temp_file:
    file_array = [line.rstrip('\n') for line in temp_file]
  return file_array


# If we have no command line arguments print help
if sys.argv[-1] == sys.argv[0]:
  print_help(script_exe)
  exit()


# Handle command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--ports", required=False)               # Specify comma delimited ports for netstat to look at
parser.add_argument("--delete", required=False)              # Delete a deny rule associate with an IP
parser.add_argument("--add", required=False)                 # Add a new rule to allowlist
parser.add_argument("--allowlist", required=False)           # Specify comma delimited allowlist on command line
parser.add_argument("--denylist", required=False)            # Specify comma delimited denylist on command line
parser.add_argument("--allowlistfile", required=False)       # Specify allowlist file to read
parser.add_argument("--denylistfile", required=False)        # Specify denylist file to read
parser.add_argument("--version", action='store_true')        # Display version
parser.add_argument("--check", action='store_true')          # Do checks
parser.add_argument("--list", action='store_true')           # Do list
parser.add_argument("--deny", action='store_true')           # Used with list to list UFW deny rules
parser.add_argument("--allow", action='store_true')          # Used with allowlist to specify allow as default
parser.add_argument("--verbose", action='store_true')        # Verbose mode
parser.add_argument("--block", action='store_true')          # Do blocks
parser.add_argument("--yes", action='store_true')            # Do delete
parser.add_argument("--import", action='store_true')         # Import rules from allowlist

option = vars(parser.parse_args())


# Print version
def print_version(script_exe):
  file_array = file_to_array(script_exe)
  version    = list(filter(lambda x: re.search(r"^# Version", x), file_array))[0].split(":")[1]
  version    = re.sub(r"\s+", "", version)
  print(version)


# Print options
def print_options(script_exe):
  file_array = file_to_array(script_exe)
  opts_array = list(filter(lambda x: re.search(r"add_argument", x), file_array))
  print("\nOptions:\n")
  for line in opts_array:
    line = line.rstrip()
    if re.search(r"#", line):
      option = line.split('"')[1]
      info   = line.split("# ")[1]
      if len(option) < 8:
        string = "%s\t\t\t%s" % (option, info)
      else:
        if len(option) < 16:
          string = "%s\t\t%s" % (option, info)
        else:
          string = "%s\t%s" % (option, info)
      print(string)
  print("\n")


# Handle allow option
if option["allow"]:
  allow_mode = True
  deny_mode  = False
else:
  allow_mode = False
  deny_mode  = True


# Handle versions option
if option["version"]:
  print_version(script_exe)


# Handle yes switch
if option["yes"]:
  force_mode = True
else:
  force_mode = False


# Handle verbose option
if option["verbose"]:
  verbose_mode = True
else:
  verbose_mode = False


# Handle delete option
if option["delete"]:
  delete_rule = option["delete"]
  delete_ufw_deny_rule(delete_rule, force_mode, verbose_mode)


# Handle allowlist option
if option["allowlist"]:
  allow_list = option["allowlist"]
  if re.search(r"\,", allow_list):
    allow_list = allow_list.split(",")
  else:
    allow_list[0] = allow_list


# Handle allowlistfile option
if option["allowlistfile"]:
  allow_list_file = option["allowlistfile"]
  if os.path.exists(allow_list_file):
    allow_list = file_to_array(allow_list_file)
  else:
    string = "allowlist file %s does not exist" % (allow_list_file)
    print(string)
    exit()
  if option["list"]:
    for ip in allow_list:
      ip = ip.rstrip()
      print(ip)
    exit()
else:
  if len(allow_list) == 0:
    if os.path.exists(allow_list_file):
      allow_list = file_to_array(allow_list_file)
    else:
      print("No allowlist specified")
      allow_list = []


# Handle allowlistfile option
if option["denylistfile"]:
  deny_list_file = option["denylistfile"]
  if os.path.exists(deny_list_file):
    deny_list = file_to_array(deny_list_file)
  else:
    string = "allowlist file %s does not exist" % (deny_list_file)
    print(string)
    exit()
  if option["list"]:
    for ip in deny_list:
      ip = ip.rstrip()
      print(ip)
    exit()
else:
  if len(deny_list) == 0:
    if os.path.exists(deny_list_file):
      deny_list = file_to_array(deny_list_file)
    else:
      print("No denylist specified")
      deny_list = []


# Handle allowlistfile option
if option["allowlistfile"]:
  allow_list_file = option["allowlistfile"]
  if os.path.exists(allow_list_file):
    allow_list = file_to_array(allow_list_file)
  else:
    string = "allowlist file %s does not exist" % (allow_list_file)
    exit()
  if option["list"]:
    for ip in allow_list:
      ip = ip.rstrip()
      print(ip)
    exit()
else:
  if len(allow_list) == 0:
    if os.path.exists(allow_list_file):
      allow_list = file_to_array(allow_list_file)
    else:
      print("No allowlist specified")
      exit()

# Handle list option
if option["list"]:
  if option["deny"]:
    ufw_list = get_ufw_deny_list(ufw_list)
    for ip in ufw_list:
      print(ip)
  else:
    for ip in allow_list:
      print(ip)
  exit()
else:
  if verbose_mode is True:
    print("Adding White list:")
    for ip in allow_list:
      print(ip)


# Handle ports option
if option["ports"]:
  netstat_ports = option["ports"]
  netstat_ports = re.sub(r"\,", "|", netstat_ports)
else:
  if option["allow"] or option["deny"]:
    netstat_ports = ""
  else:
    netstat_ports = default_ports
    netstat_ports = re.sub(r"\,", "|", netstat_ports)


# Print ports
if verbose_mode is True:
  print("Adding ports:")
  ports = netstat_ports.split("|")
  for port in ports:
    print(port)


# Handle import option

if option['import']:
  if allow_mode == True:
    ufw_commands = create_ufw_allow_commands(deny_list, allow_list, ufw_commands, netstat_ports)
  else:
    ufw_commands = create_ufw_block_commands(deny_list, allow_list, ufw_commands, netstat_ports)
  if verbose_mode is True:
    print("Commands:")
  for block_command in ufw_commands:
    print(block_command)


# Handle add option
if option["add"]:
  add_ip = option["add"]
  while_list = file_to_array(allow_list_file)
  add_to_allow_list(allow_list_file, force_mode, add_ip)
  delete_ufw_deny_rule(add_ip, force_mode, verbose_mode)


# Handle check option
if option["check"]:
  ufw_list   = get_ufw_deny_list(ufw_list)
  deny_list = do_invalid_auth_checks(deny_list, ufw_list, allow_list, netstat_ports)
  ufw_commands = create_ufw_block_commands(deny_list, allow_list, ufw_commands, netstat_ports)
  ns_list = get_netstat_tcp_connections(ns_list, netstat_ports)
  ufw_commands = create_tcp_disconnect_commands(ns_list, allow_list, ufw_commands)
  if verbose_mode is True:
    print("Block commands:")
  for block_command in ufw_commands:
    print(block_command)


# Handle block option
if option["block"]:
  for block_command in ufw_commands:
    command = "%s | sh -x"
    output = os.popen(command).read()
    print(output)
