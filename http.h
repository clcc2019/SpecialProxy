#ifndef HTTP_H
#define HTTP_H

#include "main.h"

typedef struct tcp_connection {
    char *ready_data, *incomplete_data;
    int fd, ready_data_len, incomplete_data_len, sent_len;
    uint16_t destPort;
    unsigned reread_data :1;
} conn_t;

extern void create_listen(char *ip, int port);
extern void *accept_loop(void *ptr);
extern void close_connection(conn_t *conn);
extern int8_t connectionToServer(char *ip, conn_t *server);
extern void tcp_in(conn_t *ct);
extern void tcp_out(conn_t *ct);

extern conn_t cts[MAX_CONNECTION];
extern char *local_header, *proxy_header, *ssl_proxy;
extern int lisFd, local_header_len, proxy_header_len;
extern uint8_t strict_spilce;

#endif