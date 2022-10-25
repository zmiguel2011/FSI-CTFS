#include <stdio.h>
#include <stdlib.h>

void old_backdoor() {
  puts("Backdoor activated");
  system("/bin/bash");
  return;
}

int main() {
  char buffer[60];
  
  printf("There is nothing to see here...");
  fflush(stdout);
  scanf("%32s", &buffer);
  printf("You gave me this:");
  printf(buffer);
  fflush(stdout);

  return 0;
}
