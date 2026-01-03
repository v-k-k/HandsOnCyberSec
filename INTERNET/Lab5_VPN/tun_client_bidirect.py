#!/usr/bin/env python3
import fcntl
import struct
import os
import socket
import select
import sys
from scapy.all import IP


TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

TUN_IP    = "192.168.53.99"
ROUTE_IP  = "192.168.60.0"

SRV_NAT_IP = "10.9.0.11"
SRV_PORT   = 9090

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.system("ip addr add {}/24 dev {}".format(TUN_IP, ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add {}/24 dev {}".format(ROUTE_IP, ifname))

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, bytes(pkt))

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (SRV_NAT_IP, SRV_PORT))
     
