#include "lsxdp.h"

#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

void usage()
{
    printf("Usage: testxdp [-beinopw]\n");
    printf("Where:\n");
    printf("   -b <addr> Optional parameter of local IP addr to bind on during discovery\n");
    printf("   -e <interface name> allows you to specify 1 interface name\n");
    printf("   -i <addr> to connect to\n");
    printf("   -n is to NOT unload after initializing\n");
    printf("   -o is to unload ONLY (no initialization)\n");
    printf("   -p <port> is to set the port to connect to\n");
    printf("   -w is to wait for an ENTER after loading\n");
}


int main(int argc, char **argv)
{
    int              msg_len = 256;
    char             msg[msg_len];
    xdp_prog_t      *prog;
    xdp_socket_t    *sock = NULL;
    lsxdp_socket_reqs_t *reqs = NULL;;
    struct sockaddr_in sa;
    struct sockaddr_in sa_bind;
    int              ret = 0;
    int              opt;
    int              unload_only = 0;
    int              unload = 1;
    int              pause = 0;
    char            *ifn = NULL;
    char            *addr = "127.0.0.1";
    char            *port = "80";
    char            *addr_bin = NULL;
    void            *send_buffer = NULL;
    
    while ((opt = getopt(argc, argv, "b:e:i:nop:w")) != -1)
    {
        switch (opt)
        {
            case 'b':
                addr_bin = strdup(optarg);
                break;
            case 'e':
                ifn = strdup(optarg);
                break;
            case 'i':
                addr = strdup(optarg);
                break;
            case 'n':
                unload = 0;
                break;
            case 'o':
                unload_only = 1;
                unload = 1;
                break;
            case 'p':
                port = strdup(optarg);
                break;
            case 'w':
                pause = 1;
                break;
            default:
                usage();
                return 1;
        }
    }
    printf("Calling xdp_prog_init\n");
    prog = xdp_prog_init(msg, msg_len, 1500);
    if (!prog)
    {
        printf("ERROR in xdp_prog_init: %s\n", msg);
        return 1;
    }
    if (!unload_only)
    {
        printf("Calling xdp_get_socket_reqs using addr: %s\n", addr);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(80);
        inet_aton(addr, (struct in_addr *)&sa.sin_addr.s_addr);
        if (addr_bin)
        {
            printf("Specified a bind address of %s\n", addr_bin);
            memset(&sa_bind, 0, sizeof(sa));
            sa_bind.sin_family = AF_INET;
            inet_aton(addr_bin, (struct in_addr *)&sa_bind.sin_addr.s_addr);
        }
        reqs = xdp_get_socket_reqs(prog, (struct sockaddr *)&sa, sizeof(sa),
                                   (struct sockaddr *)(addr_bin ? &sa_bind : NULL),
                                   ifn);
        if (!reqs)
        {
            ret = -1;
            printf("Error in xdp_get_socket_reqs: %s\n", xdp_get_last_error(prog));
        }
        if (!ret)
        {
            printf("Calling xdp_socket\n");
            sock = xdp_socket(prog, reqs, atoi(port));
            if (!sock)
            {
                ret = -1;
                printf("Error in xdp_socket: %s\n", xdp_get_last_error(prog));
            }
            else
                printf("xdp_socket successful\n");
        }
        if (!ret)
        {
            struct pollfd fds[1];
            int timeout = 1000; // In ms
            memset(fds, 0, sizeof(fds));
            fds[0].fd = xdp_get_poll_fd(sock);
            fds[0].events = POLLOUT;
            printf("Doing poll, fd: %d\n", fds[0].fd);
            if ((ret = poll(fds, 1, timeout)) < 1)
            {
                printf("Error in poll ret: %d, errno: %s\n", ret, strerror(errno));
                ret = -1;
            }
            else
            {
                ret = 0;
                printf("Poll successful, getting send buffer\n");
                send_buffer = xdp_get_send_buffer(sock);
                if (!send_buffer)
                {
                    printf("Error getting send buffer: %s\n", xdp_get_last_error(prog));
                    ret = -1;
                }
            }
        }
        if (!ret)
        {
            strcpy(send_buffer, "Test string!");
            ret = xdp_send(sock, send_buffer, strlen(send_buffer));
            if (ret)
                printf("Error sending: %s\n", xdp_get_last_error(prog));
            else
            {
                int pending;
                int ret;
                do
                {
                    ret = xdp_send_completed(sock, &pending);
                    if (pending)
                        usleep(1);
                } while (!ret && pending);
            }
        }
        if (sock)
        {
            printf("Calling xdp_socket_close()\n");
            xdp_socket_close(sock);
        }
        if (reqs)
        {
            printf("Freeing reqs\n");
            free(reqs);
        }
    }
    if (pause)
    {
        char input[80];
        printf("Press [ENTER] to complete the program ->");
        fgets(input, sizeof(input), stdin);
    }
    xdp_prog_done(prog, unload, unload_only);
    return ret;
}
