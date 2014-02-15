/*
 * test if we can task_for_pid(0)
 */
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <mach/mach.h> 

int main(void)
{
    mach_port_t port;
    if (task_for_pid(mach_task_self(), 0, &port))
    {
        printf("[ERRROR] Can't get task_for_pid() for kernel task!\n");
    }
    else
    {
        printf("[INFO] task_for_pid(0) works!\n");
    }
    return 0;
}
