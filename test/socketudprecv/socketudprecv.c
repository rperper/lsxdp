#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <basetsd.h>
#define ssize_t SSIZE_T
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define BUF_SZ  4096
char buf[BUF_SZ];

#define TRACE_PRINTF
#include "traceBuffer.h"

void usage(void)
{
    printf("Usage: testxdp [-ips]\n");
    printf("Where:\n");
    printf("   -i <addr> to connect to\n");
    printf("   -p <port> is to set the port to connect to\n");
    printf("   -s <string to send (if you want to send)>");
}


void ReportError(const char *location)
{
#ifdef WIN32
    wchar_t *s = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&s, 0, NULL);
    printf("Error in %s: %S\n", location, s);
    LocalFree(s);
#else
    printf("Error in %s: %s\n", location, strerror(errno));
#endif
}


int main(
    int argc, char **argv)
{
#ifndef WIN32
    int opt;
#endif
    char *addr = NULL;
    char *port = NULL;
    char *send_str = NULL;
    int sock;
    struct sockaddr_in sa;
    struct sockaddr_in sa_in;
    socklen_t sa_in_len = sizeof(sa_in);
    ssize_t sz;
    
    printf("Server to receive UDP connect from remote\n");
    
#ifdef WIN32
    int arg = 1;
    while (arg < argc)
    {
        if (argv[arg][0] != '-')
        {
            printf("Arguments begin with a dash");
            usage();
            return 1;
        }
        switch (argv[arg][1])
        {
        case 'i':
            if (arg + 1 > argc)
            {
                printf("You must specify a parameter for -i\n");
                usage();
                return 1;
            }
            arg++;
            addr = strdup(argv[arg]);
            break;
        case 'p':
            if (arg + 1 > argc)
            {
                printf("You must specify a parameter for -p\n");
                usage();
                return 1;
            }
            arg++;
            port = strdup(argv[arg]);
            break;
        case 's':
            if (arg + 1 > argc)
            {
                printf("You must specify a parameter for -s\n");
                usage();
                return 1;
            }
            arg++;
            send_str = strdup(argv[arg]);
            break;
        default:
            printf("Unknown parameter\n");
            usage();
            return 1;
        }
        arg++;
    }
#else
    while ((opt = getopt(argc, argv, "i:p:s:")) != -1)
    {
        switch (opt)
        {
            case 'i':
                addr = strdup(optarg);
                break;
            case 'p':
                port = strdup(optarg);
                break;
            case 's':
                send_str = strdup(optarg);
                break;
            default:
                usage();
                return 1;
        }
    }
#endif
    if (!addr || !port)
    {
        printf("You must specify a port and address\n");
        usage();
        return 1;
    }
#ifdef WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif
    sock = socket(AF_INET, SOCK_DGRAM,
#ifdef WIN32
        IPPROTO_UDP);
#else
        0);
#endif
    if (sock < 0)
    {
        ReportError("socket");
        return 1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(port));
#ifdef WIN32
    inet_pton(AF_INET, addr, (struct in_addr *)&sa.sin_addr.s_addr);
#else
    inet_aton(addr, (struct in_addr *)&sa.sin_addr.s_addr);
#endif
    if (!send_str)
    {
        printf("Calling BIND\n");
        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
            ReportError("bind");
            return 1;
        }
        printf("Begin recvfrom loop\n");
        while ((sz = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&sa_in,
            &sa_in_len)) > 0)
        {
            printf("Received %ld bytes from %d.%d.%d.%d\n", sz,
                ((char *)&sa_in.sin_addr.s_addr)[0],
                ((char *)&sa_in.sin_addr.s_addr)[1],
                ((char *)&sa_in.sin_addr.s_addr)[2],
                ((char *)&sa_in.sin_addr.s_addr)[3]);
            traceBuffer(buf, sz);
        }
        ReportError("recvfrom");
    }
    else
    {
        sz = sendto(sock, send_str, strlen(send_str), 0, (struct sockaddr *)&sa, sizeof(sa));
        if (sz < 0)
        {
            ReportError("sendto");
        }
        else
            printf("sendto successful, sent %ld bytes\n", sz);
    }
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
}
