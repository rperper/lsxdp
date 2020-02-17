/* Copyright (c) 2020 - 2020 LiteSpeed Technologies Inc.  See LICENSE. */

#ifndef __LSXDP_H__
#define __LSXDP_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file
 * public API for using lsxdp is defined in this file.
 *
 */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "bpf.h"
#include "libbpf.h"
#include "xsk.h"


#include "lsxdp_private.h"

#define LSXDP_MAX_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

/**
 * @fn xdp_prog_init
 * @brief Call once when the program starts.  Call xdp_prog_done when completed
 * @param[in] max_frame_size Probably should be hard-coded at 1500
 * @param[in] prog_init_err_len Maximum length of prog_init_err.
 * @param[out] prog_init_err Any errors that should be logged if this function
 *                           returns NULL.
 * @returns A pointer to xdp_prog_t if successful or NULL if an error can be
 *          reported.
 **/
xdp_prog_t *xdp_prog_init(char *prog_init_err, int prog_init_err_len,
                          int max_frame_size);
/**
 * @fn xdp_socket
 * @brief Call to create a socket to a remote system
 * @param[in] prog The return from xdp_prog_init
 * @param[in] reqs The required information to setup a socket.  Use
 *                 xdp_get_socket_reqs to obtain this info and leave it
 *                 allocated through the life of this socket.
 * @param[in] port The port to use for UDP traffic.
 * @returns A pointer to xdp_socket_t if successful and NULL if an error can be
 *          reported.
 * @note reqs is not freed when the socket is freed so you can reuse it for
 *       another socket call.
 **/
xdp_socket_t *xdp_socket(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs, int port);
/**
 * @fn xdp_get_socket_reqs
 * @brief Sets up the environment to build a socket.  You must call this once
 * for the program but the results can be used for multiple sockets.  You must
 * call this for both connect type sockets and accept type sockets.  For a
 * connect type socket, uses a simple send on a socket to get the ethernet
 * address and other stuff.  For an accept type socket, just sets up the
 * variables.
 * @param[in] prog The program handle.
 * @param[in] addr The address (as for connect) - please put in the port!
 *                 For accept type connections, MUST be NULL.
 * @param[in] addrLen The address length (as for connect)
 * @param[in] addr_bind An optional parameter of the local address to use.  The
 *            length is assumed to be the same as the addrLen above.
 * @param[in] ifport Optional ethernet system port to use.
 * @returns A pointer to lsxdp_socket_reqs_t if successful or NULL if not.
 * This pointer MUST be freed with a free() call when done.
 * @warning This function waits for up to 5 seconds for a packet response to
 * return. If it's integrated, there will need to be event handling done!
 **/
lsxdp_socket_reqs_t *xdp_get_socket_reqs(xdp_prog_t *prog,
                                         const struct sockaddr *addr,
                                         socklen_t addrLen,
                                         const struct sockaddr *addr_bind,
                                         const char *ifport);
/**
 * @fn xdp_get_poll_fd
 * @brief The the fd that can be used to determine if it's ok to send/recv now.
 * @param[in] sock The socket to get the fd for.
 * @returns the fd to poll on.
 **/
int xdp_get_poll_fd(xdp_socket_t *sock);

/**
 * @fn xdp_get_send_buffer
 * @brief For true zero copy sending, you can get a buffer from here and we'll
 * not copy it if the next operation is a xdp_send_zc using the returned buffer.
 * @note You should do a poll before getting the buffer to make sure that
 * there's one available.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @returns A zero copy buffer for sending at least of the length of the
 * specified packet size.
 **/
void *xdp_get_send_buffer(xdp_socket_t *sock);

/**
 * @fn xdp_send
 * @brief Sends a packet to the remote system.  Set it up the way you'd send
 * a UDP packet.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @param[in] data The data to send.
 * @param[in] len The length of the data to send.  Must not be greater than
 * the supplied packet length.
 * @param[in] last 1 if this is the last (kick it now) or 0 if there are more
 * to send.
 * @returns -1 for an error or 0 for success.
 **/
int xdp_send(xdp_socket_t *sock, void *data, int len, int last);

/**
 * @fn xdp_send_zc
 * @brief Sends a packet to the remote system.  Set it up the way you'd send
 * a UDP packet.  This is a zero copy version of the xdp_send function, so you
 * must leave sufficient headroom to add the headers.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @param[in] buffer The starting point of the buffer (space for headroom).
 * @param[in] len The length of the data to send (not including the headroom).
 * @param[in] last 1 if this is the last (kick it now) or 0 if there are more
 * to send.
 * @returns -1 for an error or 0 for success.
 **/
int xdp_send_zc(xdp_socket_t *sock, void *buffer, int len, int last);

/**
 * @fn xdp_send_completed
 * @brief Tries to complete all sends, but doesn't wait at all.
 * @param[in] sock The socket sent on.
 * @param[out] still_pending The number of pending packets (0 if done).
 * @returns 0 for no error and -1 for an error.
 **/
int xdp_send_completed(xdp_socket_t *sock, int *still_pending);

/**
 * @fn xdp_send_udp_headroom
 * @brief Returns the number of bytes of headroom necessary for a UDP packet.
 * @note This is not hard coded to allow the concept of virtual adapters which
 * would have varied amount of headroom requirements.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @returns The number of bytes of headroom.
 **/
int xdp_send_udp_headroom(xdp_socket_t *sock);

/**
 * @fn xdp_recv
 * @brief Receives a UDP packet from the remote system.  While you must call
 * poll before this operation, it may return with no data (NULL *buffer)
 * if the receive is NOT for a UDP packet.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @param[out] data The received UDP data.
 * @param[out] sz The length of the data received (UDP data length).
 * @param[out] addr The optional IP address
 * @param[in,out] addrlen On input the maximum length, on output the real length
 * of the addr.  Optional.
 * @returns -1 for an error or 0 for success.
 * @note You MUST call poll before calling this function.
 * @note You MUST return the received buffer with xdp_recv_return
 **/
int xdp_recv(xdp_socket_t *sock, void **data, int *sz, struct sockaddr *addr,
             socklen_t *addrlen);

/**
 * @fn xdp_recv_return
 * @brief Returns a received packet back to the system for reuse.
 * @param[in] sock The socket to send on (created with xdp_socket)
 * @param[in] data The data buffer from xdp_recv.
 * @returns -1 for an error or 0 for success.
 **/
int xdp_recv_return(xdp_socket_t *sock, void *data);

/**
 * @fn xdp_socket_close
 * @brief Call to close a socket previously opened with xdp_socket.
 * @param[in] xdp_socket_t The socket previously created with xdp_prog_init\
 * @returns None
 **/
void xdp_socket_close(xdp_socket_t *socket);
/**
 * @fn xdp_prog_done
 * @brief Call to close the use of the XDP package system after a successful
 *        call to xdp_prog_init.
 * @param[in] prog The handle to be closed (from xdp_prog_init)
 * @param[in] unload 1 if we're to unload the loaded binary; 0 to not unload it.
 * @param[in] force_unload 1 if we're to unload whatever XDP program is loaded!
 * @returns None
 **/
void xdp_prog_done(xdp_prog_t *prog, int unload, int force_unload);
/**
 * @fn xdp_get_last_error
 * @brief If a XDP function fails, call to pass in the program handle and get
 *        the error text for logging.
 * @param[in] prog program handle
 * @returns A pointer to the error text to be logged
 **/
const char *xdp_get_last_error(xdp_prog_t *prog);


#ifdef __cplusplus
}
#endif

#endif // __LSXDP_H__
