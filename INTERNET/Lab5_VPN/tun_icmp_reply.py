#!/usr/bin/env python3
import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

def check_icmp_req(bytes_in):
    pkt_in = IP(bytes_in)
    if ICMP in pkt_in: # checks for ICMP packet
        if pkt_in[ICMP].type == 8: # checks for echo-request type
            return True
    return False
    
def create_icmp_reply(bytes_in):
    pkt_in = IP(bytes_in)
    ip_out = IP(src=pkt_in.dst, dst=pkt_in.src)
    pkt_out = ip_out / pkt_in.payload
    pkt_out[ICMP].type = 0 # set ICMP packet type as echo-reply
    return bytes(pkt_out)

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if check_icmp_req(packet):
        reply_bytes = create_icmp_reply(packet)
        os.write(tun, reply_bytes) # os.write(tun, bytes("arbitrary data", encoding="utf-8"))

