#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
#cadir = '/etc/ssl/certs'
cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM
# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)      # For Ubuntu 16.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
# context.check_hostname = False

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=True)
# ssock = context.wrap_socket(sock, server_hostname='www.example.com', do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
# print("Cipher used:", ssock.cipher())
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

path = "/favicon.ico" 
request = (
    f"GET {path} HTTP/1.0\r\n"
    f"Host: {hostname}\r\n"
    f"User-Agent: Mozilla/5.0\r\n"
    f"Connection: close\r\n"
    f"\r\n"
).encode('utf-8')

ssock.sendall(request)

print("--- Receiving HTTP Response ---")
response = ssock.recv(2048)
while response:
    pprint.pprint(response.split(b"\r\n"))
    response = ssock.recv(2048)

# Close the TLS Connection
print("\n--- Closing connection ---")
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
