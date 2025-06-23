#!/usr/bin/env python3

import argparse
import signal
import sys
import re
import socket
import os
import scapy.all as scapy
from termcolor import colored

def def_handler(sig, frame):
    print(colored("\n[!] Quitting the program...\n", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # CTRL + C

# Menu Arguments
def get_arguments():
    argparser = argparse.ArgumentParser(description="ARP Scanner")
    argparser.add_argument("-t", "--target", required=True, dest="target", help="Host / IP Range to scan. (Ex: 192.168.100.1 / 192.168.100.0/21)")
    argparser.add_argument("-i", "--interface", required=True, dest="interface", help="Network Interface. (Ex: wlan0)")

    args = argparser.parse_args()

    return args.target, args.interface

# Verify the correct arguments format and if it's running by root.
def verify(target, interface):

    if os.getuid() != 0:
        print(colored("\n[!] Root privilege required.\n", "yellow"))
        sys.exit(1)

    match_uniq = re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", target) # Verify correct format for a uniq host
    match_range = re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$", target) # Verify correct format for range of hosts
    
    try:
        ip, bitmask = target.split('/') # get bitmask
        bitmask = int(bitmask) # Convert to int
        match_range = True if bitmask < 33 else False # Verify if a correct bitmask (< 33)
    except ValueError:
        pass
    
    interfaces = [i[1] for i in socket.if_nameindex()] # Get all Network Interfaces Names on the computer.
    interface = True if interface in interfaces else False # Verify if the Interface Name given by the user is correct.

    return match_uniq or match_range, interface # return if is a correct format and if exist the interface name

# Create an arp packet and starts the scan.
def scan(ip, interface):
    arp_packet = scapy.ARP(pdst=ip) # Create arp frame
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Create Ether frame

    packet = broadcast_packet/arp_packet # Create the packet with ether and arp frame union.

    print(colored("\n[-] Sanning...\n", "blue"))

    answered, unanswered = scapy.srp(packet, timeout=1, verbose=False, iface=interface) # starts the scan

    answers = [[ans.answer.psrc, ans.answer.src] for ans in answered] # get only ip and mac address of each hosts
   
    return answers 

# Print each hosts with green color
def printed(li):
    print(colored(f"\t+) {li[0]} -> {li[1]}", "green"))

# Print banne
def print_banner():
    print(colored("""

▄▀█ █▀█ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█▀█ █▀▄ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄\n""", 'white'))

    print(colored("""Mᴀᴅᴇ ʙʏ sᴀᴍᴍʏ-ᴜʟғʜ\n""", 'yellow'))

# Main logic
def main():
    print_banner()
    target, interface = get_arguments()
    isValid, isValidInt = verify(target, interface)

    if isValid and isValidInt:
        answers = scan(target, interface)
        for ans in answers:
            printed(ans)
    elif not isValid:
        print(colored("\n[!] Not valid target format.\n", "red"))
    elif not isValidInt:
        print(colored("\n[!] Not valid interface.\n", "red"))

if __name__ == "__main__":
    main()
