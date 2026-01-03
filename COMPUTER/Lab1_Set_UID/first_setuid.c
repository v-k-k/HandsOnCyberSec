// Asssume the program’s name is foo
// sudo chown root foo
// sudo chmod 4755 foo

#include <stdio.h>
#include <stdlib.h>

extern char **environ;

int main()
{
  int i = 0;
  while (environ[i] != NULL) {
     printf("%s\n", environ[i]);
     i++;
  }
}
