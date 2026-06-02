#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

# Construct the guess with padding
YES   = b"Yes" + bytes("\x0d" * 13, 'utf-8')
NO    = b"No" + bytes("\x0e" * 14, 'utf-8')

# Calculate the plain text you want to give to the oracle
r = xor(b"A Message", bytearray.fromhex("aabbccdd"))

print(r.hex())
