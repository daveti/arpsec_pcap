/*
 * AsKrnProc.c
 * Source file for AsKrnProc
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "AsLog.h"
#include "AsKrnProc.h"


void disable_kernel_arp(void) 
{
  int fd;

   if ((fd = open(MODULE_PATH, O_WRONLY)) == -1)
      asLogMessage("arpseck: Error - can't open proc file");

   if (write(fd, "1", 1) != 1)
      asLogMessage("arpseck: Error - can't enable arpseck");
   else
      asLogMessage("arpseck: Info - arpseck enabled");

   close(fd);

   atexit(enable_kernel_arp);
}

void enable_kernel_arp(void)
{
   int fd;

   if ((fd = open(MODULE_PATH, O_WRONLY)) == -1)
      asLogMessage("arpseck: Error - can't open proc file");

   if (write(fd, "0", 1) != 1)
      asLogMessage("arpseck: Error - can't disable arpseck");
   else
      asLogMessage("arpseck: Info - arpseck disabled");

   close(fd);
}

