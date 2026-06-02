#!/usr/bin/python3

import socket
from binascii import hexlify, unhexlify

# Helper function to XOR two bytearrays
def xor(first, second):
   return bytearray(x ^ y for x, y in zip(first, second))

class PaddingOracle:
    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        
        # Upon connection, the server sends the IV + Ciphertext in hex
        ciphertext_hex = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext_hex)
        print(f"[+] Connected. Initial Ciphertext (Hex): {ciphertext_hex}")

    def decrypt(self, ctext: bytes) -> str:
        """Sends a modified ciphertext to the oracle and returns the status."""
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        return self.s.recv(4096).decode().strip()

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()

if __name__ == "__main__":
    # Level-2 server listens on port 6000
    oracle = PaddingOracle('10.9.0.80', 6000)

    # Convert the full ciphertext into a list of 16-byte blocks
    # Block[0] is IV, Block[1] is C1, Block[2] is C2, etc.
    full_ctext = bytearray(oracle.ctext)
    blocks = [full_ctext[i:i+16] for i in range(0, len(full_ctext), 16)]
    num_blocks = len(blocks)
    
    print(f"[*] Total blocks detected: {num_blocks} (including IV)")
    
    final_plaintext = bytearray()

    # We iterate through each ciphertext block starting from index 1 (C1)
    # To decrypt block C[b], we manipulate the block preceding it, C[b-1]
    for b in range(1, num_blocks):
        print(f"\n--- Decrypting Block {b} of {num_blocks-1} ---")
        
        C_prev = blocks[b-1]  # The original previous block (IV or previous Ciphertext)
        C_curr = blocks[b]    # The current target block we want to decrypt
        
        D = bytearray(16)     # To store the Intermediate State (D = Decrypt(Key, C_curr))
        CC = bytearray(16)    # Our modified block to send to the oracle
        
        # We crack each block byte-by-byte from right to left (index 15 down to 0)
        for K in range(1, 17):
            target_idx = 16 - K
            
            # 1. Prepare CC for the current padding value K
            # We must adjust all bytes we've already found so they result in value K
            for j in range(1, K):
                CC[16 - j] = D[16 - j] ^ K
            
            found = False
            # 2. Brute-force the current byte CC[target_idx]
            for i in range(256):
                CC[target_idx] = i
                
                # We only need to send the modified block CC followed by the target block C_curr
                status = oracle.decrypt(CC + C_curr)
                
                if status == "Valid":
                    # 3. Calculate D byte: Since CC ^ D = K, then D = CC ^ K
                    D[target_idx] = i ^ K
                    print(f"[Byte {target_idx}] Found Valid CC byte: 0x{i:02x} -> D[{target_idx}] = 0x{D[target_idx]:02x}")
                    found = True
                    break
            
            if not found:
                print(f"[-] Critical Error: Could not find valid padding for block {b}, byte {target_idx}")
                exit(1)

        # 4. Final step for the block: Plaintext P = D ^ Original_C_prev
        block_plaintext = xor(C_prev, D)
        final_plaintext += block_plaintext
        
        print(f"[+] Block {b} decrypted (Hex): {block_plaintext.hex()}")
        print(f"[+] Block {b} decrypted (Text): {repr(block_plaintext.decode(errors='ignore'))}")

    # Display the final results
    print("\n" + "="*60)
    print("FULL RECOVERED SECRET MESSAGE:")
    # Using errors='ignore' to strip potential PKCS#7 padding bytes from the final output
    print(final_plaintext.decode(errors='ignore'))
    print("="*60)   
