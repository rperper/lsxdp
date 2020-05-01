#include "lsxdp.h"

#include <poll.h>
#include <unistd.h>

// To avoid including <arpa/inet.h> which conflicts with lsxdp
uint16_t htons(uint16_t hostshort);
int inet_aton(const char *cp, struct in_addr *inp);

void usage()
{
    printf("Usage: testxdp [-behimnopQrsSvwx]\n");
    printf("Where:\n");
    printf("   -b <addr> Optional parameter of local IP addr to bind on during discovery\n");
    printf("   -d Turns on debugging\n");
    printf("   -e <interface name> allows you to specify 1 interface name\n");
    printf("   -h Turns on Hardware XDP (DRV mode)\n");
    printf("   -i <addr> to connect to\n");
    printf("   -m <max memory> maximum amount of memory for all packets\n");
    printf("   -n is to NOT unload after initializing\n");
    printf("   -o is to unload ONLY (no initialization)\n");
    printf("   -p <port> is to set the port to connect to\n");
    printf("   -Q to turn on MULTI-QUEUE\n");
    printf("   -r is to receive ONLY (no send - wait until [ENTER]\n");
    printf("   -s to turn on SEND-ONLY\n");
    printf("   -S to turn on MULTI-SHARD\n");
    printf("   -v to turn on VIRT-IO (you must specify -e)\n");
    printf("   -w is to wait for an ENTER after loading\n");
    printf("   -x <max> max queues/shards\n");
}


int do_send(xdp_prog_t *prog, xdp_socket_t *sock, struct sockaddr_in6 *sa)
{
    int      ret = 0;
    void    *send_buffer = NULL;
    void    *send_buffer2 = NULL;

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
            send_buffer2 = xdp_get_send_buffer(sock);
            if (!send_buffer2)
            {
                printf("Error getting send buffer2: %s\n", xdp_get_last_error(prog));
                ret = -1;
            }
        }
        if (!ret)
        {
            strcpy(send_buffer, "Test string!");
            strcpy(send_buffer2, "The second send buffer.");
            ret = xdp_send(sock, send_buffer, strlen(send_buffer), 0,
                           (struct sockaddr *)sa);
            if (ret)
                printf("Error sending send_buffer: %s\n", xdp_get_last_error(prog));
            else if ((ret = xdp_send(sock, send_buffer2, strlen(send_buffer2), 1,
                                     (struct sockaddr *)sa)))
                printf("Error sending send_buffer2: %s\n", xdp_get_last_error(prog));
            else
            {
                int pending;
                int ret;
                int counter = 0;
                do
                {
                    ret = xdp_send_completed(sock, &pending);
                    if (pending)
                    {
                        usleep(1);
                        counter++;
                        if (counter > 10)
                        {
                            printf("Pending too long - giving up\n");
                            break;
                        }
                    }
                } while (!ret && pending);
                if (!ret && !pending)
                    printf("send completed successfully\n");
                else if (ret)
                    printf("Error in xdp_send_completed: %s\n",
                           xdp_get_last_error(prog));
                else
                    ret = -1;
            }
        }
    }
    return ret;
}


int do_recv(xdp_prog_t *prog, xdp_socket_t *sock, struct sockaddr_in6 *sa)
{
    int      ret = 0;
    struct pollfd fds[2];

    while (!ret)
    {
        printf("In recv, press [ENTER] to stop ->");
        fflush(stdout);
        int timeout = -1; // In ms
        memset(fds, 0, sizeof(fds));
        fds[0].fd = xdp_get_poll_fd(sock);
        fds[0].events = POLLIN;
        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;
        ret = poll(fds, 2, timeout);
        if (ret < 0)
        {
            printf("\npoll returned %s\n", strerror(errno));
            break;
        }
        if (ret == 0)
            continue;
        if (fds[1].revents)
        {
            char input[80];
            fgets(input, sizeof(input), stdin);
            printf("Receive terminated by user\n");
            break;
        }
        else
        {
            void *buffer;
            socklen_t sa_len = sizeof(*sa);
            int sz;
            printf("\nPoll successful (ret: %d), doing receive\n", ret);
            ret = xdp_recv(sock, &buffer, &sz, (struct sockaddr *)sa, &sa_len);
            if (ret < 0)
            {
                printf("Error in xdp_recv: %s\n", xdp_get_last_error(prog));
                break;
            }
            else if (!buffer)
            {
                ret = 0;
                continue;
            }
            else if (xdp_recv_return(sock, buffer))
            {
                printf("Error in xdp_recv_return: %s\n", xdp_get_last_error(prog));
                break;
            }
            ret = 0;
        }
    }
    return ret;
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
    __u64            max_memory = 0;
    char            *ifn = NULL;
    char            *addr = "127.0.0.1";
    char            *port = "80";
    char            *addr_bin = NULL;
    char             recv_only = 0;
    int              send_only = 0;
    int              multi_queue = 0;
    int              multi_shard = 0;
    int              max_queues_shards = 0;
    int              virtio = 0;
    int              hardware = 0;
    struct sockaddr_in6 sa_comm;

    memset(&sa_comm, 0, sizeof(sa_comm));
    while ((opt = getopt(argc, argv, "b:de:hi:m:nop:QrSsvwx:")) != -1)
    {
        switch (opt)
        {
            case 'b':
                addr_bin = strdup(optarg);
                break;
            case 'd':
                xdp_debug(1);
                printf("Debugging on\n");
                break;
            case 'e':
                ifn = strdup(optarg);
                break;
            case 'h':
                hardware = 1;
                break;
            case 'i':
                addr = strdup(optarg);
                break;
            case 'm':
                max_memory = atoi(optarg);
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
            case 'Q':
                multi_queue = 1;
                break;
            case 'r':
                recv_only = 1;
                break;
            case 's':
                send_only = 1;
                break;
            case 'S':
                multi_shard = 1;
                break;
            case 'v':
                virtio = 1;
                break;
            case 'w':
                pause = 1;
                break;
            case 'x':
                max_queues_shards = atoi(optarg);
                break;
            default:
                usage();
                return 1;
        }
    }
    printf("Calling xdp_prog_init\n");
    prog = xdp_prog_init(msg, msg_len, 1500, max_memory, send_only, multi_queue,
                         multi_shard, virtio ? ifn : NULL, max_queues_shards,
                         hardware);
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
        sa.sin_port = htons(atoi(port));
        if (!inet_aton(addr, (struct in_addr *)&sa.sin_addr.s_addr))
        {
            printf("Invalid IP address\n");
            return 1;
        }
        if (addr_bin)
        {
            printf("Specified a bind address of %s\n", addr_bin);
            memset(&sa_bind, 0, sizeof(sa));
            sa_bind.sin_family = AF_INET;
            if (!inet_aton(addr_bin, (struct in_addr *)&sa_bind.sin_addr.s_addr))
            {
                printf("Invalid bind IP address\n");
                return 1;
            }
        }
        reqs = xdp_get_socket_reqs(prog, (struct sockaddr *)&sa, sizeof(sa),
                                   (struct sockaddr *)(!recv_only ? &sa_bind : NULL),
                                   ifn);
        if (!reqs)
        {
            ret = -1;
            printf("Error in xdp_get_socket_reqs: %s\n", xdp_get_last_error(prog));
        }
        if (!ret)
        {
            printf("Calling xdp_socket\n");
            if (pause)
            {
                char input[80];
                printf("Press [ENTER] to continue... ->");
                fgets(input, sizeof(input), stdin);
            }
            sock = xdp_socket(prog, reqs, htons(atoi(port)), 0);
            if (!sock)
            {
                ret = -1;
                printf("Error in xdp_socket: %s\n", xdp_get_last_error(prog));
            }
            else
                printf("xdp_socket successful\n");
        }
        if (!ret && !recv_only)
            ret = do_send(prog, sock, &sa_comm);
        if (!ret && recv_only)
            ret = do_recv(prog, sock, &sa_comm);
        if (pause)
        {
            char input[80];
            printf("Press [ENTER] to close the socket ->");
            fgets(input, sizeof(input), stdin);
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
