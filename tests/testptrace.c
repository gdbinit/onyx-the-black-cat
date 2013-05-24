/*
 * test PT_DENY_ATTACH
 */
#include <sys/types.h>
#include <sys/ptrace.h>

int main()
{
  ptrace(PT_DENY_ATTACH, -1, 0, 0);
  sleep(2);
  printf("Buh!\n");
}
