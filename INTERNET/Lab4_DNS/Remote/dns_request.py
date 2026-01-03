#!/usr/bin/env python3
from scapy.all import *


"""IP dst - this should be the IP address of the local DNS server, which is '10.9.0.53'.
   IP src - this should be the IP address of the attacker, which is '10.9.0.1'.
   UDP dport - this should be the destination port of the packet, any UDP port should do, so 53 was chosen.
   UDP sport - this should be the source port of the packet, any UDP port should do, so 52055 was chosen."""

Qdsec = DNSQR(qname='www.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
ip = IP(dst='10.9.0.53', src='10.9.0.1')
udp = UDP(dport=53, sport=52055, chksum=0)
request = ip/udp/dns

send(request)      
