#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>

#define BUFFER_SIZE 10240
#define MAX_CONNECTION 1020

extern struct epoll_event evs[MAX_CONNECTION + 2], ev;
extern struct sockaddr_in addr;
extern socklen_t addr_len;
extern int efd;

#endif