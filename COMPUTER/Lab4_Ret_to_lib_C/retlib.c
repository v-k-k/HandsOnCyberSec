#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

/* This program is intended for an educational stack overflow experiment.
   It intentionally uses the unsafe function strcpy for demonstration.
   Use only in a controlled environment. */

int bof(char *str)
{
    char buffer[BUF_SIZE];
    unsigned int *framep;

    /* Copy ebp into framep */
    asm("movl %%ebp, %0" : "=r" (framep));

    /* print out information for experiment purpose */
    printf("Address of buffer[] inside bof():  0x%.8x\n", (unsigned)buffer);
    printf("Frame Pointer value inside bof():  0x%.8x\n", (unsigned)framep);

    /* The unsafe copy is intentionally left for the experiment */
    strcpy(buffer, str);

    return 1;
}

void foo(){
    static int i = 1;
    printf("Function foo() is invoked %d times\n", i++);
    return;
}

int main(int argc, char **argv)
{
   char input[1000];
   FILE *badfile;
   size_t length;

   badfile = fopen("badfile", "rb");
   if (!badfile) {
       perror("fopen");
       return 1;
   }

   /* Read at most sizeof(input)-1 bytes to leave space for '\0' */
   length = fread(input, 1, sizeof(input) - 1, badfile);
   if (ferror(badfile)) {
       perror("fread");
       fclose(badfile);
       return 1;
   }
   fclose(badfile);

   /* Ensure a null terminator for safe use of strcpy/printf */
   input[length] = '\0';

   printf("Address of input[] inside main():  0x%.8x\n", (unsigned int) input);
   printf("Input size: %zu\n", length);

   bof(input);

   printf("(^_^)(^_^) Returned Properly (^_^)(^_^)\n");
   return 0;
}