/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#include "lsxdp.h"
#include "sendbufs.h"

#include <sys/mman.h>

/* see lsxdp.c for the real DEBUG_MESSAGE */
int debug_message(const char *format, ...);
#define DEBUG_MESSAGE debug_message

/**
 * NOTE: There are two conditions that limit reuse of the shared memory:
 * - Application allocation.  This is clear cut.  Either it's allocated or it's
 *   been freed.  I'm simply going to keep a count of the number I believe have
 *   been allocated.
 * - In-flight by the adapter.  I thought that they might be sent out of order
 *   but I can't believe it's true.  There's too many bugs in trying to
 *   ascertain which packets are freed to have that be the case.
 **/
#define SEND_BUF_CHARS(sock)        (sock->m_tx_max + 7) / 8
#define SEND_BUF_CHAR(num)          ((num) / 8)
#define SEND_BUF_BIT(num)           (1 << ((num) % 8))
#define SEND_BUF_TEST(sock, num)    (sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(num)] & SEND_BUF_BIT(num))
#define SEND_BUF_SET(sock, num)     sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(num)] |= SEND_BUF_BIT(num)
#define SEND_BUF_CLR(sock, num)     sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(num)] &= (~(SEND_BUF_BIT(num)))

int s_last_alloc = 0;
int s_last_free = 0;

int send_bufs_init(xdp_socket_t *sock)
{
    xdp_prog_t *prog = sock->m_xdp_prog;

    if (sock->m_send_bufs)
    {
        DEBUG_MESSAGE("send_bufs_init, Already created\n");
    }
    else
    {
        DEBUG_MESSAGE("send_bufs_init, size: %d\n", SEND_BUF_CHARS(sock));
        sock->m_send_bufs = mmap(NULL, SEND_BUF_CHARS(sock),
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1 /*memfd*/, 0);
        if (sock->m_send_bufs == MAP_FAILED)
        {
            int err = errno;
            DEBUG_MESSAGE("Error creating send_buffer used memory: %s\n",
                          strerror(err));
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "Error creating send_buffer used memory: %s", strerror(err));
            sock->m_send_bufs = NULL;
            return -1;
        }
        memset(sock->m_send_bufs, 0, SEND_BUF_CHARS(sock));
    }
    return 0;
}

int send_bufs_get_one_free(xdp_socket_t *sock, int *index)
{
    int try;
    xdp_prog_t *prog = sock->m_xdp_prog;
    int queue = sock->m_queue;

    DEBUG_MESSAGE("send_bufs_get_one_free, queue: %d\n", queue);
    if (sock->m_tx_count >=
        sock->m_tx_max - sock->m_tx_outstanding)
    {
        //fprintf(stderr, "No free buffers!  Count: %d, Max: %d, Outstanding: %d\n",
        //        sock->m_tx_count, sock->m_tx_max,
        //        sock->m_tx_outstanding);
        DEBUG_MESSAGE("   No free buffers\n");
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "send_bufs_get_one_free, No free buffers");
        errno = EAGAIN;
        return -1;
    }
    // Try to add one to the last one and see if it works.
    if (!sock->m_tx_last && !sock->m_tx_count)
        try = (sock->m_tx_last + 1) % sock->m_tx_max;
    else
        try = (sock->m_tx_last + 1) % sock->m_tx_max;
    if (SEND_BUF_TEST(sock, try))
    {
        fprintf(stderr, "Exhaustively search, try: %d, count: %d, outstanding: %d, max: %d\n",
                try, sock->m_tx_count,
                sock->m_tx_outstanding, sock->m_tx_max);
        int i;
        int found = 0;
        int fail = 0;
        int compares = 0;

        DEBUG_MESSAGE("Not found where I hoped, exhaustively search\n");
        for (i = 0; i < SEND_BUF_CHARS(sock); ++i)
        {
            ++compares;
            if (sock->m_send_bufs->m_lbuf[i] != 0xfffffffffffffffful)
            {
                // One of the 8 (I can make this more efficient by going though the ints and then shorts, but this is enough for now
                int j;
                for (j = i * 8; j < (i + 1) * 8; ++j)
                {
                    ++compares;
                    if (sock->m_send_bufs->m_cbuf[j] != 0xffu)
                    {
                        int k;
                        for (k = 0; k < 8; ++k)
                        {
                            ++compares;
                            if (!(SEND_BUF_TEST(sock, j * 8 + k)))
                            {
                                found = 1;
                                try = j + k;
                                break;
                            }
                        }
                        if (!found)
                        {
                            fail = 1;
                            try = j;
                        }
                        break;
                    }
                }
                if (!found && !fail)
                {
                    fail = 1;
                    try = i;
                }
                break;
            }
            if (found || fail)
                break;
        }
        if (fail)
        {
            DEBUG_MESSAGE("send_bufs_get_one_free, "
                          "INTERNAL ERROR - HIT AND MISS AT %d, byte: 0x%x\n",
                          try, sock->m_send_bufs->m_cbuf[try / 8]);
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "send_bufs_get_one_free, "
                     "INTERNAL ERROR - HIT AND MISS AT %d, byte: 0x%x", try,
                     sock->m_send_bufs->m_cbuf[try / 8]);
            errno = EBADF;
            return -1;
        }
        else if (!found)
        {
            DEBUG_MESSAGE("send_bufs_get_one_free, INTERNAL ERROR; COUNTER "
                          "SAYS WE SHOULD FIND A BUFFER BUT WE DIDN'T\n");
            snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                     "send_bufs_get_one_free, INTERNAL ERROR; COUNTER "
                     "SAYS WE SHOULD FIND A BUFFER BUT WE DIDN'T");
            errno = EBADF;
            return -1;
        }
    }
    s_last_alloc = try;
    SEND_BUF_SET(sock, try);
    DEBUG_MESSAGE("   found: %d, bitmap byte[%d]: 0x%x\n", try,
                  SEND_BUF_CHAR(try),
                  sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(try)]);
    sock->m_tx_last = try;
    sock->m_tx_count++;
    if (index)
        *index = try;
    return 0;
}

int send_bufs_freed_one(xdp_socket_t *sock, int index)
{
    xdp_prog_t *prog = sock->m_xdp_prog;

    DEBUG_MESSAGE("send_bufs_freed_one %d\n", index);
    if (!sock->m_tx_count)
    {
        DEBUG_MESSAGE("send_bufs_freed_one, INTERNAL ERROR; COUNTER SAYS WE "
                      "SHOULD NOT FIND A BUFFER, BUT WE HAVE: %d\n", index);
        snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
                 "send_bufs_freed_one, INTERNAL ERROR; COUNTER SAYS WE SHOULD "
                 "NOT FIND A BUFFER, BUT WE HAVE: %d", index);
        errno = EBADF;
        return -1;
    }
    if (!SEND_BUF_TEST(sock, index))
    {
        DEBUG_MESSAGE("send_bufs_freed_one, INTERNAL ERROR; TRYING TO FREE "
                      "%d, BUT ALREADY FREE, bitmap byte[%d]: 0x%x\n", index,
                      SEND_BUF_CHAR(index),
                      sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(index)]);
        //snprintf(prog->m_err, LSXDP_PRIVATE_MAX_ERR_LEN,
        //         "send_bufs_freed_one, INTERNAL ERROR; TRYING TO FREE %d BUT "
        //         "ALREADY FREE, bitmap byte[%d]: 0x%x, last_alloc: %d, last_free: %d",
        //         index, SEND_BUF_CHAR(index),
        //         sock->m_send_bufs->m_cbuf[SEND_BUF_CHAR(index)],
        //         s_last_alloc, s_last_free);
        int i = 0;
        fprintf(stderr, "Internal error freeing: %d, allocated: %d, Orphaned: ",
                index, sock->m_tx_count);
        for (i = 0; i < sock->m_tx_max; ++i)
        {
            if (SEND_BUF_TEST(sock, i))
                fprintf(stderr," %d, ", i);
        }
        fprintf(stderr, "\n");
        //errno = EBADF;
        //return -1;
        return 0; // Can't be fatal, happens too often!
    }
    s_last_free = index;
    SEND_BUF_CLR(sock, index);
    sock->m_tx_count--;
    return 0;
}

void send_bufs_done(xdp_socket_t *sock)
{
    DEBUG_MESSAGE("send_bufs_done\n");
    if (sock && sock->m_send_bufs)
    {
        munmap(sock->m_send_bufs, SEND_BUF_CHARS(sock));
        sock->m_send_bufs = NULL;
    }
}
