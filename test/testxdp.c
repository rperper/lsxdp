#include "lsxdp.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

void usage()
{
    printf("Usage: testxdp [-einopw]\n");
    printf("Where:\n");
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
    int              ret = 0;
    int              opt;
    int              unload_only = 0;
    int              unload = 1;
    int              pause = 0;
    char            *ifn = NULL;
    char            *addr = "127.0.0.1";
    char            *port = "80";
    
    while ((opt = getopt(argc, argv, "e:i:nop:w")) != -1)
    {
        switch (opt)
        {
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
        reqs = xdp_get_socket_reqs(prog, (struct sockaddr *)&sa, sizeof(sa), ifn);
        if (!reqs)
        {
            ret = -1;
            printf("Error in xdp_get_socket_reqs: %s\n", xdp_get_last_error(prog));
        }
        if (!ret)
        {
            printf("Calling xdp_socket\n");
            sock = xdp_socket(prog, reqs);
            if (!sock)
            {
                ret = -1;
                printf("Error in xdp_socket: %s\n", xdp_get_last_error(prog));
            }
        }
        if (!ret)
        {
        }
        if (sock)
            xdp_socket_close(sock);
        if (reqs)
            free(reqs);
    }
    if (pause)
    {
        char input[80];
        printf("Press [ENTER] to complete the program ->");
        fgets(input, sizeof(input), stdin);
    }
    xdp_prog_done(prog, unload);
    return ret;
}
