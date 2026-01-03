#!/usr/bin/env python3
import fcntl
import struct
import os
import socket
import select
import sys
from scapy.all import Ether, ARP


TUN_DEVICE = "/dev/net/tun"
TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

IFNAME = "tap0"
TAP_IP    = "192.168.53.99"
FAKE_MAC = "aa:bb:cc:dd:ee:ff"

# Create the tap interface
tap = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tap%d', IFF_TAP | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tap, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

os.system("ip addr add {}/24 dev {}".format(TAP_IP, ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
    # Get a packet from the tap interface
    packet = os.read(tap, 65535)
    ether = Ether(packet)
    
    print("---- Frame ----")
    print(ether.summary())
    if ARP in ether and ether[ARP].op == 1:
        arp = ether[ARP]
        newether = Ether(dst=ether.src, src=FAKE_MAC)
        newarp = ARP(op=2, 
                     hwsrc=FAKE_MAC, 
                     psrc=arp.pdst, 
                     hwdst=ether.src, 
                     pdst=arp.psrc)                     
        newpkt = newether / newarp
        
        print("Sending fake ARP reply:", newpkt.summary())
        os.write(tap, bytes(newpkt))

     
