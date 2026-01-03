#!/usr/bin/env python3
import os
import fcntl
import struct
import subprocess
import socket
import select
import sys
from scapy.all import IP

TUN_DEVICE = "/dev/net/tun"
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

TUN_NAME = "tun0"
TUN_IP = "192.168.53.1" # Our ARTIFFICIAL interface 

IP_A = "10.9.0.11"
PORT = 9090

VPN_CLIENT_IP = "10.9.0.5" # NAT Network IP for VPN Client
DUMMY_PORT    = 10000 # dummy port to be replaced when values are read from socket

tun = os.open(TUN_DEVICE, os.O_RDWR)
ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun, TUNSETIFF, ifr)

os.system("ip addr add {}/24 dev {}".format(TUN_IP, TUN_NAME))
os.system("ip link set dev {} up".format(TUN_NAME))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
print(f"VPN -- {IP_A}:{PORT} waiting for packets...")

while True:    
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (VPN_CLIENT_IP, DUMMY_PORT) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)

        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (VPN_CLIENT_IP, DUMMY_PORT))
    
sock.close()
os.close(tun)
