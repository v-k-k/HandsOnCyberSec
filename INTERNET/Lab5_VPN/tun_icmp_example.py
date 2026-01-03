#!/usr/bin/env python3
import fcntl
import struct
import os
import time
from scapy.all import IP, ICMP, raw

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Open /dev/net/tun
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Configure interface (requires iproute2 tools and root)
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

print("Ready. Listening for packets on {}".format(ifname))

while True:
    packet = os.read(tun, 2048)
    if not packet:
        continue

    try:
        ip = IP(packet)
    except Exception as e:
        print("Not an IP packet or parse error:", e)
        continue

    print("Got:", ip.summary())

    # If ICMP and echo request (type 8), craft echo reply (type 0)
    if ip.haslayer(ICMP):
        icmp = ip[ICMP]
        if icmp.type == 8:  # Echo request
            print("ICMP Echo Request from {} -> {}".format(ip.src, ip.dst))

            # Build reply: swap src/dst, set ICMP type to 0, preserve id/seq and payload
            reply = IP(src=ip.dst, dst=ip.src)/ICMP(type=0, id=icmp.id, seq=icmp.seq)/icmp.payload

            # Force recalculation of checksums/lengths
            if hasattr(reply, 'chksum'):
                try:
                    del reply.chksum
                except Exception:
                    pass
            if hasattr(reply[ICMP], 'chksum'):
                try:
                    del reply[ICMP].chksum
                except Exception:
                    pass

            raw_bytes = bytes(reply)
            os.write(tun, raw_bytes)
            print("Wrote ICMP Echo Reply to TUN ({} bytes)".format(len(raw_bytes)))
            