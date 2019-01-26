#ifndef HTTP_H
#define HTTP_H

#include "main.h"

typedef struct tcp_connection {
    char *ready_data, *incomplete_data;
    int fd, ready_data_len, incomplete_data_len, sent_len, timer;
    uint16_t destPort;
    unsigned reread_data :1;
    unsigned request_type :1;
    unsigned keep_alive :1;
	unsigned is_ssl :1;
} conn_t;

extern void create_listen(char *ip, int port);
extern void accept_client();
extern void close_connection(conn_t *conn);
extern int8_t connectionToServer(in_addr_t ip, conn_t *server);
extern void tcp_in(conn_t *in);
extern void tcp_out(conn_t *to);

extern conn_t cts[MAX_CONNECTION];
extern char *local_header, *proxy_header, *ssl_proxy;
extern int lisFd, local_header_len, proxy_header_len, ignore_host_before_count;
extern uint8_t strict_spilce, sslEncodeCode;

#endif