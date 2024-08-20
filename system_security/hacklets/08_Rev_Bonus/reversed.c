#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void printFlag(void) {
  puts("Great job here is your flag: ");
  execl("/bin/cat","cat","flag.txt",0);
  return;
}

void encrypt(char *__block,int __edflag) {
  char local_28 [28];
  int local_c;
  
  strcpy((char *)local_28,__block);
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    __block[local_c] = local_28[0xf - local_c] ^ "NO_HARDCODED_KEY"[local_c];
  }
  return;
}

void checkStart(long param_1) {
  int local_c;
  
  for (local_c = 0; local_c < 7; local_c = local_c + 1) {
    if (*(char *)(param_1 + local_c) != "infosec"[local_c]) {
      puts("Error. Start is not infosec.");
    }
  }
  return;
}

int main(void) {
  int iVar1;
  size_t sVar2;
  char local_208 [256];
  char local_108 [256];
  
  puts("Hi, please enter the plain text:");
  fgets(local_108,0x100,stdin);
  puts("Now please enter the corresponding cipher text:");
  iVar1 = 0x100;
  fgets(local_208,0x100,stdin);
  sVar2 = strlen(local_108);
  if ((sVar2 != 0x11) && (sVar2 = strlen(local_208), sVar2 != 0x11)) {
    puts("Error. Wrong size.");
    return 0xffffffff;
  }
  checkStart(local_108);
  encrypt(local_108,iVar1);
  printf("%s",local_108);
  iVar1 = strcmp(local_108,local_208);
  if (iVar1 == 0) {
    printFlag();
  }
  return 0;
}