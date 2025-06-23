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

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    argparser = argparse.ArgumentParser(description="ARP Scanner")
    argparser.add_argument("-t", "--target", required=True, dest="target", help="Host / IP Range to scan. (Ex: 192.168.100.1 / 192.168.100.0/21)")
    argparser.add_argument("-i", "--interface", required=True, dest="interface", help="Network Interface. (Ex: wlan0)")

    args = argparser.parse_args()

    return args.target, args.interface

def verify(target, interface):

    if os.getuid() != 0:
        print(colored("\n[!] Root privilege required.\n", "yellow"))
        sys.exit(1)

    match_uniq = re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", target)
    match_range = re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$", target)
    
    try:
        ip, bitmask = target.split('/')
        bitmask = int(bitmask)
        match_range = True if bitmask < 33 else False
    except ValueError:
        pass
    
    interfaces = [i[1] for i in socket.if_nameindex()]
    interface = True if interface in interfaces else False

    return match_uniq or match_range, interface

def scan(ip, interface):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast_packet/arp_packet

    print(colored("\n[-] Sanning...\n", "blue"))

    answered, unanswered = scapy.srp(packet, timeout=1, verbose=False, iface=interface)

    answers = [[ans.answer.psrc, ans.answer.src] for ans in answered]
   
    return answers 

def printed(li):
    print(colored(f"\t+) {li[0]} -> {li[1]}", "green"))

def print_banner():
    print(colored("""

▄▀█ █▀█ █▀█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█▀█ █▀▄ █▀▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄\n""", 'white'))

    print(colored("""Mᴀᴅᴇ ʙʏ sᴀᴍᴍʏ-ᴜʟғʜ\n""", 'yellow'))

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
