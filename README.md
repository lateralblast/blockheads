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
- os
- re

Standard UNIX tools:
- netstat
- ss

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode
