#include "dns.h"
#include "http.h"

struct dns dns_list[MAX_CONNECTION / 2];  //一个客户端 + 一个服务端 占用一个dns结构体
int dnsFd;

void read_dns_rsp()
{
    static char rsp_data[512], *p, ips[16];
    static unsigned char *_p;
    static struct dns *dns;
    static conn_t *client;
    static int16_t len, dns_flag;

    while ((len = read(dnsFd, rsp_data, BUFFER_SIZE)) > 11)
    {
        memcpy(&dns_flag, rsp_data, 2);
        dns = dns_list + dns_flag;
        client = cts + (dns_flag << 1);
        //判断是否是正常DNS回应，是否已关闭连接
        if (dns_flag > MAX_CONNECTION >> 1 || client->fd < 0)
            continue;
        if (dns->request_len + 12 > len || (unsigned char)rsp_data[3] != 128)  //char只有7位可用，则正数最高为127
        {
            close_connection(client);
            continue;
        }
        
        /* get ips */
        p = rsp_data + dns->request_len + 11;
        ips[0] = '\0';
        while (p - rsp_data + 4 <= len)
        {
            //type
            if (*(p - 8) != 1)
            {
                p += *p + 12;
                continue;
            }
            _p = (unsigned char *)p + 1;
            sprintf(ips, "%d.%d.%d.%d", _p[0], _p[1], _p[2], _p[3]);
            break;
        }
        if (ips[0])
        {
            //printf("ips %s\n", ips);
            if (connectionToServer(ips, client + 1) != 0)
            {
                close_connection(client);
                continue;
            }
        }
        else
        {
            close_connection(client);
            continue;
        }
    }
}

/* 完全发送返回0，发送部分返回1，出错返回-1 */
static int8_t send_dns_req(struct dns *dns)
{
    static int write_len;
    
    write_len = write(dnsFd, dns->request + dns->sent_len, dns->request_len - dns->sent_len);
    if (write_len == dns->request_len - dns->sent_len)
    {
        dns->sent_len = dns->request_len;
        return 0;
    }
    else if (write_len >= 0)
    {
        dns->sent_len += write_len;
        return 1;
    }
    else
    {
        return -1;
    }
}

void dns_query()
{
    static int16_t i, ret;
    
    for (i = 0; i < MAX_CONNECTION >> 1; i++)
    {
        if (dns_list[i].request_len != dns_list[i].sent_len)
        {
            ret = send_dns_req(dns_list + i);
            if (ret == 1)
                break;
            else if (ret == -1)
                close_connection(cts + (i << 1));
        }
    }
    if (i == MAX_CONNECTION >> 1)
        ev.events = EPOLLIN|EPOLLET;
    else
        ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
    ev.data.fd = dnsFd;
    epoll_ctl(efd, EPOLL_CTL_MOD, dnsFd, &ev);
}

int8_t build_dns_req(struct dns *dns, char *domain)
{
    static char *p, *_p;
    static int8_t domain_size;

    domain_size = strlen(domain);
    p = dns->request + 12;
    memcpy(p+1, domain, domain_size);
    *(p+1+domain_size) = 0;
    while ((_p = strchr(p+1, '.')) != NULL)
    {
        *p = _p - p - 1;
        p = _p;
    }
    *p = strlen(p+1);
    p = dns->request + 14 + domain_size;
    *p++ = 0;
    *p++ = 1;
    *p++ = 0;
    *p++ = 1;
    dns->request_len = p - dns->request;
    switch (send_dns_req(dns))
    {
        case 0:
            ev.data.fd = dnsFd;
            ev.events = EPOLLIN|EPOLLET;
            epoll_ctl(efd, EPOLL_CTL_MOD, dnsFd, &ev);
        return 0;
        
        case 1:
            ev.data.fd = dnsFd;
            ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
            epoll_ctl(efd, EPOLL_CTL_MOD, dnsFd, &ev);
        return 1;
        
        default:
            return -1;
    }
}

void dns_connect(struct sockaddr_in *dnsAddr)
{
    dnsFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dnsFd < 0)
    {
        perror("socket");
        exit(1);
    }
    connect(dnsFd, (struct sockaddr *)dnsAddr, sizeof(struct sockaddr_in));
    fcntl(dnsFd, F_SETFL, O_NONBLOCK);
}
