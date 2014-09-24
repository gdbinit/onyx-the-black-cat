/*
 * test PT_DENY_ATTACH and SIGSEGV
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>

unsigned int trap = 1;

void signalHandler(int signal)
{
  trap = 0;
}

int main()
{
  ptrace(PT_DENY_ATTACH, 0, 0, 0);
  signal(11, signalHandler);
  ptrace(PT_ATTACH, getpid(), 0, 0);
  signal(11, 0);
  if(trap)
    ((unsigned int*)0)[0] = 0;
  sleep(2);
  printf("Buh!\n");
}