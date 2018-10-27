#include "main.h"
#include "http.h"
#include "dns.h"
#include <pthread.h>

#define VERSION "0.2"
#define DEFAULT_DNS_IP "114.114.114.114"

struct epoll_event evs[MAX_CONNECTION + 1], ev;
struct sockaddr_in addr;
socklen_t addr_len;
int efd;

static void usage()
{
    puts("SpecialProxy(" VERSION "):\n"
    "    -l [listenip:]listenport              \033[35G default ip is 0.0.0.0\n"
    "    -p proxy header                       \033[35G default is 'Host'\n"
    "    -L local proxy header                 \033[35G default is 'Local'\n"
    "    -d dns query address                  \033[35G default is " DEFAULT_DNS_IP "\n"
    "    -s ssl proxy string                   \033[35G default is 'CONNECT'\n"
    "    -a                                    \033[35G all http requests repeat spilce\n"
    "    -h display this infomaction\n"
    "    -w worker process\n");
    exit(0);
}

static void server_loop()
{
    pthread_t thread_id;
    int n;

    //单独进程accept多进程并发环境下不会惊群
    pthread_create(&thread_id, NULL, accept_loop, NULL);
    ev.events = EPOLLIN;
    ev.data.fd = dnsFd;
    epoll_ctl(efd, EPOLL_CTL_ADD, dnsFd, &ev);
    while (1)
    {
        n = epoll_wait(efd, evs, MAX_CONNECTION + 1, -1);
        while (n-- > 0)
        {
            if (evs[n].data.fd == dnsFd)
            {
                if (evs[n].events & EPOLLIN)
                    read_dns_rsp();
                if (evs[n].events & EPOLLOUT)
                    dns_query();
            }
            else
            {
                if ((evs[n].events & EPOLLERR) || (evs[n].events & EPOLLHUP))
                {
                    if (((conn_t *)evs[n].data.ptr)->fd >= 0)
                        close_connection((conn_t *)evs[n].data.ptr);
                }
                if (evs[n].events & EPOLLIN)
                    tcp_in((conn_t *)evs[n].data.ptr);
                if (evs[n].events & EPOLLOUT)
                    tcp_out((conn_t *)evs[n].data.ptr);
            }
        }
    }
}

static void initializate(int argc, char **argv)
{
    struct sockaddr_in dnsAddr;
    char *p;
    int opt, i, workers;
    
	/* 初始化部分变量值 */
    addr_len = sizeof(addr);
    lisFd = -1;
    workers = 1;
    dnsAddr.sin_family = addr.sin_family = AF_INET;
    //默认dns地址
    dnsAddr.sin_addr.s_addr = inet_addr(DEFAULT_DNS_IP);
    dnsAddr.sin_port = htons(53);
    dns_connect(&dnsAddr);  //主进程中的fd
    strict_spilce = 0;
    local_header = NULL;
    ssl_proxy = (char *)"CONNECT";
    local_header = (char *)"\nLocal:";
    proxy_header = (char *)"\nHost:";
    proxy_header_len = strlen(proxy_header);
    local_header_len = strlen(local_header);
    /* 处理命令行参数 */
    while ((opt = getopt(argc, argv, "d:l:p:s:w:u:L:ah")) != -1)
    {
        switch (opt)
        {
            case 'd':
                p = strchr(optarg, ':');
                if (p)
                {
                    *p = '\0';
                    dnsAddr.sin_port = htons(atoi(p+1));
                }
                dnsAddr.sin_addr.s_addr = inet_addr(optarg);
                connect(dnsFd, (struct sockaddr *)&dnsAddr, sizeof(dnsAddr));
            break;
            
            case 'l':
                p = strchr(optarg, ':');
                if (p)
                {
                    *p = '\0';
                    create_listen(optarg, atoi(p+1));
                }
                else
                {
                    create_listen((char *)"0.0.0.0", atoi(optarg));
                }
            break;
            
            case 'p':
                //假如选项值为 "Proxy", proxy_header设置为 "\nProxy:"
                proxy_header_len = strlen(optarg) + 2;
                if (optarg[proxy_header_len] == ':')
                    optarg[proxy_header_len--] = '\0';
                proxy_header = (char *)malloc(proxy_header_len + 1);
                if (proxy_header == NULL)
                {
                    fputs("out of memory.\n", stderr);
                    exit(1);
                }
                sprintf(proxy_header, "\n%s:", optarg);
            break;
            
            case 'L':
                local_header_len = strlen(optarg) + 2;
                if (optarg[local_header_len] == ':')
                    optarg[local_header_len--] = '\0';
                local_header = (char *)malloc(local_header_len + 1);
                if (local_header == NULL)
                {
                    fputs("out of memory.\n", stderr);
                    exit(1);
                }
                sprintf(local_header, "\n%s:", optarg);
            break;
            
            case 's':
                ssl_proxy = optarg;
            break;
            
            case 'a':
                strict_spilce = 1;
            break;
            
            case 'w':
                workers = atoi(optarg);
            break;
            
            case 'u':
                if (setgid(atoi(optarg)) != 0))
                {
                    perror("setgid");
                    exit(1);
                }
                if (setuid(atoi(optarg)) != 0))
                {
                    perror("setuid");
                    exit(1);
                }
            break;
            
            default:
                usage();
            break;
        }
    }
	/* 初始化剩下的变量值 */
    if (lisFd < 0)
    {
        fputs("no listen address\n", stderr);
        exit(1);
    }
    memset(cts, 0, sizeof(cts));
    for (i = MAX_CONNECTION; i--; )
        cts[i].fd = -1;
    //为服务端的结构体分配内存
    for (i = 1; i < MAX_CONNECTION; i += 2)
    {
        cts[i].ready_data = (char *)malloc(BUFFER_SIZE);
        if (cts[i].ready_data == NULL)
        {
            fputs("out of memory.", stderr);
            exit(1);
        }
    }
	//设置dns请求头首部
    memset(dns_list, 0, sizeof(dns_list));
    for (i = MAX_CONNECTION / 2; i--; )
    {
        memcpy(dns_list[i].request, &i, sizeof(uint16_t));
        dns_list[i].request[2] = 1;
        dns_list[i].request[3] = 0;
        dns_list[i].request[4] = 0;
        dns_list[i].request[5] = 1;
        dns_list[i].request[6] = 0;
        dns_list[i].request[7] = 0;
        dns_list[i].request[8] = 0;
        dns_list[i].request[9] = 0;
        dns_list[i].request[10] = 0;
        dns_list[i].request[11] = 0;
    }
    signal(SIGPIPE, SIG_IGN);  //忽略PIPE信号
    //子进程中的dnsFd必须重新申请，不然epoll监听可能读取到其他进程得到的数据
    while (workers-- > 1 && fork() == 0)
        dns_connect(&dnsAddr);
    efd = epoll_create(MAX_CONNECTION + 1);
    if (efd < 0)
    {
        perror("epoll_create");
        exit(1);
    }

}

int main(int argc, char **argv)
{
    initializate(argc, argv);
    if (daemon(1, 0))
    {
        perror("daemon");
        return 1;
    }
    server_loop();
    
    return 0;
}
