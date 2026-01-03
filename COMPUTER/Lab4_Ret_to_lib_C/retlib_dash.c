#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

/* Buffer size in the vulnerable function */
#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];
    unsigned int *framep;

    /* Save the frame pointer for debugging purposes */
    asm("movl %%ebp, %0" : "=r" (framep));

    printf("--- Internal bof() information ---\n");
    printf("Address of buffer[]:      0x%.8x\n", (unsigned int)buffer);
    printf("Frame Pointer (EBP):      0x%.8x\n", (unsigned int)framep);
    
    /* Calculate the offset between EBP and the start of the buffer */
    printf("Offset (EBP - buffer):    %d bytes\n", (char*)framep - buffer);

    /* Buffer overflow vulnerability occurs here */
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char input[1000];
    FILE *badfile;
    size_t length;

    /* Helper: printing addresses of libc functions */
    void *execv_addr = dlsym(RTLD_NEXT, "execv");
    void *exit_addr  = dlsym(RTLD_NEXT, "exit");

    printf("--- Useful Addresses ---\n");
    printf("execv address:            %p\n", execv_addr);
    printf("exit address:             %p\n", exit_addr);

    badfile = fopen("badfile", "rb");
    if (!badfile) {
        printf("Error: 'badfile' not found.\n");
        return 1;
    }

    /* 1. Read the ENTIRE file into memory (including null bytes!) */
    length = fread(input, 1, sizeof(input) - 1, badfile);
    fclose(badfile);
    input[length] = '\0';

    printf("--- main() Information ---\n");
    printf("Address of input[]:       0x%.8x  <-- THIS IS YOUR BASE FOR DATA\n", (unsigned int)input);
    printf("Input size:               %zu bytes\n", length);

    /* 2. Invoke the vulnerable function */
    bof(input);

    printf("(^_^) Returned safely (^_^)\n");
    return 0;
}