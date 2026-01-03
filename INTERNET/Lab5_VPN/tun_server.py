#!/usr/bin/env python3
import os
import fcntl
import struct
import subprocess
import socket
import sys
from scapy.all import IP

TUN_DEVICE = "/dev/net/tun"
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

TUN_NAME = "tun0"
TUN_IP = "192.168.53.1/24" # Our ARTIFFICIAL interface 
IP_A = "0.0.0.0"
PORT = 9090

def create_tun(name=TUN_NAME):
    tun = os.open(TUN_DEVICE, os.O_RDWR)
    ifr = struct.pack('16sH', name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def configure_tun(name=TUN_NAME, ip=TUN_IP):
    subprocess.check_call(["ip", "addr", "flush", "dev", name])
    subprocess.check_call(["ip", "addr", "add", ip, "dev", name])
    subprocess.check_call(["ip", "link", "set", "dev", name, "up"])

tun_fd = create_tun(TUN_NAME)
configure_tun(TUN_NAME, TUN_IP)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
print(f"UDP -- {IP_A}:{PORT} waiting for packets...")

while True:
    data, (ip, port) = sock.recvfrom(65535)
    print(f"RECV: {ip}:{port}::{data}")
    pkt = IP(data)
    os.write(tun_fd, data)
    
sock.close()
os.close(tun_fd)
