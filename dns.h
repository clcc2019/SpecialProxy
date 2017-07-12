#ifndef DNS_H
#define DNS_H

#include "main.h"

struct dns {
    char request[512];  //UDP的DNS请求不超512字节
    uint16_t request_len, sent_len;
};

extern void dns_connect(struct sockaddr_in *dnsAddr);
extern struct dns dns_list[MAX_CONNECTION / 2];
extern int dnsFd;

extern int8_t build_dns_req(struct dns *dns, char *domain);
extern void read_dns_rsp();
extern void dns_query();

#endif