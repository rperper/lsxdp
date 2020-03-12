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
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

#define BUF_SZ  4096
char buf[BUF_SZ];

#define TRACE_PRINTF
#include "traceBuffer.h"

#define FILE_BUF_SZ 1048576
char file_buf[FILE_BUF_SZ];

void usage(void)
{
    printf("Usage: socketudprecv [-ipstlg]\n");
    printf("Where:\n");
    printf("   -i <addr> to connect to (optional if just UDP waiting)\n");
    printf("   -p <port> is to set the port to connect to\n");
    printf("   -s <string to send (if you want to send)>\n");
    printf("   -t Just a dumb TCP connect\n");
    printf("   -l TCP/IP file listen (for this program -g)\n");
    printf("   -g <remote file> TCP/IP file get (throws output away) (for this pgm -l)\n");
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


int send_file(int fd, char *filename)
{
    FILE *fh;
    size_t rd;
    int sd;
    int rc = -1;
    size_t total = 0;
    printf("Getting: %s\n", filename);
    fh = fopen(filename, "r");
    if (!fh)
    {
        printf("Error opening: %s: %s\n", filename, strerror(errno));
        return -1;
    }
#ifndef WIN32
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);
#endif
    while ((rd = fread(file_buf, 1, sizeof(file_buf), fh)) > 0)
    {
        total += rd;
        if ((sd = send(fd, file_buf, rd, 0)) < 0)
        {
            ReportError("send failed");
            break;
        }
    }
    if (rd < 0)
        printf("fread failed: %s\n", strerror(errno));
    else if (rd == 0)
    {
#ifndef WIN32
        size_t elapsed_ms;
        gettimeofday(&tv_end, NULL);
        elapsed_ms = (tv_end.tv_sec * 1000 + tv_end.tv_usec / 1000) -
                     (tv_start.tv_sec * 1000 + tv_start.tv_usec / 1000);
        printf("File completely sent, %ld bytes in %ld.%ld secs, %ld chars/sec\n",
               total, elapsed_ms / 1000, elapsed_ms % 1000,
               (elapsed_ms < 1000) ? 0 : (total / (elapsed_ms / 1000)));
#else
        printf("File completely sent, %ld bytes\n", total);
#endif
        rc = 0;
    }
    fclose(fh);
    return rc;
}

int recv_file(int fd)
{
    size_t rd;
    int sd;
    int rc = -1;
    size_t total = 0;
    printf("Receiving...\n");
#ifndef WIN32
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, NULL);
#endif
    while ((rd = recv(fd, file_buf, sizeof(file_buf), 0)) > 0)
        total += rd;
    if (rd < 0)
        ReportError("recv failed");
    else if (rd == 0)
    {
#ifndef WIN32
        size_t elapsed_ms;
        gettimeofday(&tv_end, NULL);
        elapsed_ms = (tv_end.tv_sec * 1000 + tv_end.tv_usec / 1000) -
                     (tv_start.tv_sec * 1000 + tv_start.tv_usec / 1000);
        printf("File completely received, %ld bytes in %ld.%ld secs, %ld chars/sec\n",
               total, elapsed_ms / 1000, elapsed_ms % 1000,
               (elapsed_ms < 1000) ? 0 : (total / (elapsed_ms / 1000)));
#else
        printf("File completely received, %ld bytes\n", total);
#endif
        rc = 0;
    }
    return rc;
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
    int tcp = 0;
    int tcp_file_listen = 0;
    char *tcp_file_get = NULL;
    int sock;
    struct sockaddr_in sa;
    struct sockaddr_in sa_in;
    socklen_t sa_in_len = sizeof(sa_in);
    ssize_t sz;
    
    printf("UDP/TCP test program\n");
    
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
        case 't':
            tcp = 1;
            break;
        case 'l':
            tcp = 1;
            tcp_file_listen = 1;
            break;
        case 'g':
            if (arg + 1 > arc)
            {
                printf("You must specify a parameter for -g\n");
                usage();
                return 1;
            }
            arg++;
            tcp = 1;
            tcp_file_get = strdup(argv[arg]);
            break;
        default:
            printf("Unknown parameter\n");
            usage();
            return 1;
        }
        arg++;
    }
#else
    while ((opt = getopt(argc, argv, "i:p:s:tlg:")) != -1)
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
            case 't':
                tcp = 1;
                break;
            case 'l':
                tcp = 1;
                tcp_file_listen = 1;
                break;
            case 'g':
                tcp = 1;
                tcp_file_get = strdup(optarg);
                break;
            default:
                usage();
                return 1;
        }
    }
#endif
    if ((((tcp && !tcp_file_listen) || send_str) && !addr) || !port)
    {
        if ((tcp && !tcp_file_listen) || send_str)
            printf("You must specify a port and address\n");
        else
            printf("You must specify a port\n");
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
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(port));
    if (send_str || (tcp && !tcp_file_listen))
#ifdef WIN32
        inet_pton(AF_INET, addr, (struct in_addr *)&sa.sin_addr.s_addr);
#else
        inet_aton(addr, (struct in_addr *)&sa.sin_addr.s_addr);
#endif
    if (tcp)
    {
        printf("Socket\n");
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            ReportError("Error creating socket");
            return 1;
        }
        if (tcp_file_listen)
        {
            int fd;
            struct sockaddr_in sa_in;
            socklen_t sa_in_size = sizeof(sa_in);

            sa.sin_addr.s_addr = INADDR_ANY;
            printf("bind\n");
            if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            {
                ReportError("bind");
                return 1;
            }
            if (listen(sock, 5) < 0)
            {
                ReportError("listen");
                return 1;
            }
            while ((fd = accept(sock, (struct sockaddr *)&sa_in, &sa_in_size)) >= 0)
            {
                int len;
                char filename[1024];
                printf("Request from %u.%u.%u.%u\n",
                       ((unsigned char *)&sa_in.sin_addr.s_addr)[0],
                       ((unsigned char *)&sa_in.sin_addr.s_addr)[1],
                       ((unsigned char *)&sa_in.sin_addr.s_addr)[2],
                       ((unsigned char *)&sa_in.sin_addr.s_addr)[3]);
                len = recv(fd, filename, sizeof(filename), 0);
                if (len < 0)
                {
                    ReportError("Error getting file name");
                    return 1;
                }
                if (send_file(fd, filename))
                    return 1;
#ifdef WIN32
                closesocket(fd);
#else
                close(fd);
#endif
            }
            ReportError("accept failed");
            return 1;
        }
        else if (tcp_file_get)
        {
            printf("Send file name\n");
            if (send(sock, tcp_file_get, strlen(tcp_file_get), 0) < 0)
            {
                ReportError("Error sending file name");
                return 1;
            }
            recv_file(sock);
        }
        else
        {
            printf("Doing connect\n");
            if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
                ReportError("connect failed");
            else
                printf("connect succeeded\n");
            if (send_str)
            {
                if (send(sock, send_str, strlen(send_str), 0) < 0)
                    ReportError("send failed");
                else
                    printf("send worked!\n");
            }
        }
    }
    else
    {
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
        if (!send_str)
        {
#ifndef WIN32
            struct pollfd polfd;
#endif
            printf("Calling BIND\n");
            sa.sin_addr.s_addr = INADDR_ANY;
            if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            {
                ReportError("bind");
                return 1;
            }
            printf("Begin poll/recvfrom loop\n");
#ifndef WIN32
            memset(&polfd, 0, sizeof(polfd));
            polfd.fd = sock;
            polfd.events = POLLIN;
#endif
            while (1)
            {
#ifndef WIN32
                int rc = poll(&polfd, 1, -1);
                int err = errno;
                printf("poll rc: %d, errno: %d\n", rc, err);
                errno = err;
                if (rc == 1)
#endif
                {
                    sz = recvfrom(sock, buf, sizeof(buf), 0,
                                  (struct sockaddr *)&sa_in, &sa_in_len);
                    if (sz > 0)
                    {
                        printf("Received %ld bytes from %d.%d.%d.%d\n", sz,
                               ((char *)&sa_in.sin_addr.s_addr)[0],
                               ((char *)&sa_in.sin_addr.s_addr)[1],
                               ((char *)&sa_in.sin_addr.s_addr)[2],
                               ((char *)&sa_in.sin_addr.s_addr)[3]);
                        traceBuffer(buf, sz);
                    }
                    else
                    {
                        ReportError("recvfrom");
                        break;
                    }
                }
#ifndef WIN32
                else
                {
                    ReportError("poll");
                }
                polfd.revents = 0;
#endif
            }
        }
        else
        {
#ifndef WIN32
            struct pollfd polfd;
            int rc;
            memset(&polfd, 0, sizeof(polfd));
            polfd.fd = sock;
            polfd.events = POLLOUT;
            rc = poll(&polfd, 1, -1);
            if (rc != 1)
            {
                int err = errno;
                printf("poll for send returned %d, %s\n", rc, strerror(err));
            }
            else
#endif
            {
                sz = sendto(sock, send_str, strlen(send_str), 0,
                            (struct sockaddr *)&sa, sizeof(sa));
                if (sz < 0)
                {
                    ReportError("sendto");
                }
                else
                    printf("sendto successful, sent %ld bytes\n", sz);
            }
        }

    }
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
}
