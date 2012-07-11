/*
 * lispmanager.c
 *
 * Simple wrapper code to start/stop lispd and
 * install/remove the kernel module. Called
 * via the lisp app or from the command-line.
 *
 * Options:
 *
 * lispmanager [start|stop] stops or starts the lispd process
 * lispmanager [install|remove] installs or removes the kernel module
 *
 * Author: Chris White
 * Copyright 2011, Cisco Systems
 */

//#include "lispmanager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *moduleFilename = "/system/modules/lisp.ko";
const char *moduleName = "lisp";
const char *daemonCommand = "/system/bin/lispd -f /sdcard/lispd.conf";
const char *moduleInstallCommand = "/system/bin/insmod";
const char *moduleRemoveCommand = "/system/bin/rmmod";
const char *killCommand = "/system/bin/kill -15";
const char *lockFilename = "/sdcard/lispd.lock";
const char *moduleCheckFilename = "/proc/modules";
const char *procCheckCommand = "/system/xbin/pgrep -nl lispd";

int startDaemon(void)
{
    int status;
    printf("Starting lisp daemon\n");
    status = system(daemonCommand);
    printf("\n");
    return(status);
}

int stopDaemon(void)
{
    FILE *lockFile = fopen(lockFilename, "r");
    int pid;
    char killstring[128];
    int status;

    fscanf(lockFile, "%d", &pid);
    sprintf(killstring, "%s %d", killCommand, pid);
    status = system(killstring);
    printf("\n");
    return(status);
}

int installKernelMod(void)
{
    char commandstring[128];

    sprintf(commandstring, "%s %s", moduleInstallCommand, moduleFilename);
    return(system(commandstring));
}

int removeKernelMod(void)
{
    char commandstring[128];

    sprintf(commandstring, "%s %s", moduleRemoveCommand, moduleName);
    return(system(commandstring));
}

void getStatus(void)
{
    FILE *procPipe;
    char  statusString[128];

    procPipe = popen(procCheckCommand, "r");

    if (!procPipe) {
        printf("Failed to execute pgrep.\n");
        exit(-1);
    }
    memset(statusString, 0, 128);
    fgets(statusString, 128, procPipe);
    if (strstr(statusString, "lispd")) {
        printf("lispd: running.\n");
        exit(0);
    }

    printf("lispd: not running.\n");
    exit(1);
}

int main(int argc, char **argv)
{

    if (argc != 2) {
        printf("Usage: \n");
        printf("lispmanager [start|stop]: stops or starts the lispd process\n");
        printf("lispmanager [install|remove]: installs or removes the kernel module\n");
        printf("lispmanager status: displays lisp process and module status.\n");
        exit(-1);
    }

    if (!strncmp(argv[1], "start", 5)) {
        exit(startDaemon());
    } else if (!strncmp(argv[1], "stop", 4)) {
        exit(stopDaemon());
    } else if (!strncmp(argv[1], "install", 7)) {
        exit(installKernelMod());
    } else if (!strncmp(argv[1], "remove", 6)) {
       exit(removeKernelMod());
    } else if (!strncmp(argv[1], "status", 6)) {
        getStatus();
    } else {
        exit(-1);
    }
    exit(0);
    return 0;
}
