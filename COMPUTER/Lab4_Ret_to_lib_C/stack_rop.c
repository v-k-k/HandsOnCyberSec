#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/* Global pointer to environment variables */
extern char **environ;

void bar(void) {
    static int i = 0;
    printf("The function bar() is invoked %d times!\n", ++i);
}

int foo(char *str) {
    char buffer[100];
    void *ebp; /* 32-bit frame pointer */

    /* Inline asm: move ebp into C variable ebp (x86 32-bit) */
    asm("movl %%ebp, %0" : "=r" (ebp));

    /* Print addresses matches desired output */
    printf("buffer[] address: %p\n", (void *)buffer);
    printf("ebp address: %p\n", ebp);

    /* Difference in bytes between ebp and buffer */
    ptrdiff_t diff = (char *)ebp - (char *)buffer;
    printf("ebp - buffer is: %td\n", diff);

    /* Address of system and exit (via RTLD_NEXT) */
    void *system_addr = dlsym(RTLD_NEXT, "system");
    void *exit_addr = dlsym(RTLD_NEXT, "exit");
    
    printf("system addr: %p\n", system_addr);
    printf("exit addr: %p\n", exit_addr);
    printf("bar function address: %p\n", (void *)bar);

    /* Intentionally unsafe copy for lab demonstration */
    strcpy(buffer, str);
    return 1;
}

int main(void) {
    char input[1000];
    FILE *badfile;
    size_t length;
    char *ptr;
    int i = 0;

    /* Search for "/bin/sh" in environment variables to match output requirement */
    /* Note: In real labs, you might need to export MYSHELL=/bin/sh before running */
    while (environ[i] != NULL) {
        if ((ptr = strstr(environ[i], "/bin/sh")) != NULL) {
            printf("The '/bin/sh' string's address: %p\n", ptr);
            break; 
        }
        i++;
    }
    /* Fallback if not found easily */
    if (environ[i] == NULL) {
        printf("The '/bin/sh' string's address: (not found in env)\n");
    }

    badfile = fopen("badfile", "rb");
    if (!badfile) {
        // If badfile doesn't exist, we just pass an empty string to allow demo to run
        // or create a dummy one. For this code, we'll return error as in original.
        perror("fopen badfile");
        return 1;
    }

    length = fread(input, 1, sizeof(input) - 1, badfile);
    fclose(badfile);

    input[length] = '\0';

    foo(input);

    printf("Returned Properly\n");
    return 0;
}
