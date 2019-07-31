#!/usr/bin/env python3

'''
The Enumerator
@author: Simon 'Maglok' Kort
@source: https://www.github.com/saekort/the_enumerator

Script for automating enumeration of a target IP. There are many like it, but this one is mine.
'''

class Service:
    def __init__(self, target, name, port, protocol):
        self.target = target
        self.port = port
        self.protocol = protocol
        self.name = name

import multiprocessing
import os
import subprocess
import sys
import time

# Function for port scanning
def portscan(target, type):

    # Create scans directory if not exists
    if os.path.isdir('./scans') == 0:
        subprocess.check_call(['mkdir', 'scans'])

    # Create IP directory if not exists
    if os.path.isdir('./scans/' + target) == 0:
        subprocess.check_call(['mkdir', 'scans/' + target])

    if type == 'tcp':
        print("Starting basic TCP portscan")
        # Define nmap scan command
	scan = "nmap -vv -sC -sV -n " + target + " -oX scans/" + target + "/tcp_" + target + ".xml"

    if type == 'udp':
        print("Starting basic UDP portscan")
        scan = "nmap -vv -sC -sV -n -O " + target + " -oX scans/" + target + "/udp_" + target + ".xml"
    if type == 'full':
        print("Starting full TCP/UDP portscan")
        scan = "nmap -vv -sC -sV -n -O -p-" + target + " -oX scans/" + target + "/full_" + target + ".xml"
    
    print("Command: " + scan)
    # Start running the nmap scan as a subprocess, save the result
    result = subprocess.check_output(scan, shell=True)

    services = []
    resultlines = result.split('\n')

    # Cut up the results and create Service class instances
    for resultline in resultlines:
        if ("tcp" in resultline) and ("open" in resultline) and not ("Discovered" in resultline):
            while "  " in resultline:
                resultline = resultline.replace("  ", " ")

            resultline = resultline.split(" ")
            servicename = resultline[2]
            port = resultline[0].split("/")[0]
            protocol = resultline[0].split("/")[1]
            service = Service(target, servicename, port, protocol)            
            services.append(service)
    for service in services:
        #print(service.port, service.protocol, service.name)
        if service.name == 'http':
            enumHttp(service)
        elif service.name == 'ftp':
            enumFtp(service)
        elif service.name == 'smb':
            enumSmb(service)
        elif service.name == 'ssh':
            enumSsh(service)
        else:
            print("No support for " + service.port + " (" + service.protocol + ") " + service.name)
            
def enumHttp(service):
    print("HTTP enum: Running for service " + service.port + " (" + service.protocol + ") " + service.name)

    # Run gobuster small list
    command = "gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u " + service.target + ":" + service.port + " > " + "./scans/" + service.target + "/gobuster-" + service.port + ".txt"
    result = subprocess.check_output(command, shell=True)

def enumFtp(service):
    print("FTP enum: Running for service " + service.port + " (" + service.protocol + ") " + service.name)

def enumSmb(service):
    print("SMB enum: Running for service " + service.port + " (" + service.protocol + ") " + service.name)

def enumSsh(service):
    print("SSH enum: Running for service " + service.port + " (" + service.protocol + ") " + service.name)

# Check for input parameters
if len (sys.argv) != 2:
    print "Usage: python3 the_enumerator.py <TARGET IP>"
    sys.exit(1)

version = "0.1"
target = sys.argv[1].strip()
ports = []
hostname = 'UNKNOWN'

print(" _______ _           ______                                      _             ")
print("|__   __| |         |  ____|                                    | |            ")
print("   | |  | |__   ___ | |__   _ __  _   _ _ __ ___   ___ _ __ __ _| |_ ___  _ __ ")
print("   | |  | '_ \ / _ \|  __| | '_ \| | | | '_ ` _ \ / _ \ '__/ _` | __/ _ \| '__|")
print("   | |  | | | |  __/| |____| | | | |_| | | | | | |  __/ | | (_| | || (_) | |   ")
print("   |_|  |_| |_|\___||______|_| |_|\__,_|_| |_| |_|\___|_|  \__,_|\__\___/|_|   ")
print("")
print("Version: " + version)
print("Target: " + target)
print("---------------------------------------")

# Setup multiprocessing
tasks = []
scan = multiprocessing.Process(target=portscan, args=(target,'tcp'))
tasks.append(scan)
scan.start()
