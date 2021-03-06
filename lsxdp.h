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
 * @fn xdp_get_virtio_info
 * @brief Call to get the virtio_net limits, if any.
 * @param[in] dev The device name to query.
 * @param[in] err_len The size of prog_init_err_len
 * @param[out] err Will return a non-zero first character if there's an error.
 * @param[out] queues The number of queues if virtio_net.  This defines the
 *                    number of receives you must post upon if using XDP for
 *                    receives.
 * @param[out] cpus The number of cpus if virtio_net.  This defines the maximum
 *                  number of send queues that can be used.
 * @returns 1 if virtio could be determined.  0 if not and -1 for an error (see
 *          err).
 **/
int xdp_get_virtio_info(const char *dev, int *queues, int *cpus, char *err,
                        int err_len);

/**
 * @fn xdp_prog_init
 * @brief Call once when the program starts.  Call xdp_prog_done when completed
 * @param[in] max_frame_size Probably should be hard-coded at 1500
 * @param[in] prog_init_err_len Maximum length of prog_init_err.
 * @param[in] max_memory The maximum amount of memory to be used for packets.
 *                       If not specified (0) 16MB will be used.
 * @param[in] send_only Whether to do this for sending or both sending AND
 *            receiving
 * @param[in] multi_queue 1 if this is a multi-queue program.  At this time it
 *            is required that each socket be on a separate queue for proper
 *            memory management.
 * @param[in] multi_shard 1 if this is a multi-shard program.  For the same
 *            reasons as multi-queue.
 * @param[in] virtio_dev Non-NULL if you wish to use virtio.  If you specify
 *            this you must use separate xdp_prog_t definitions for each device.
 *            You should only specify this if you are going to be multi-queue,
 *            have shard support, and the number of shards is the number of
 *            queues.  If specified, max_queues_shards is ignored.
 * @param[in] max_queues_shards Set as a single value so you can't forget that
 *            you can't have multiple queues and shards that are different
 *            0 if both of the flags above are off or virtio is on.
 * @param[in] hardware_xdp Set if you wish to turn on the hardware socket
 *            flag.
 * @param[out] prog_init_err Any errors that should be logged if this function
 *                           returns NULL.
 * @returns A pointer to xdp_prog_t if successful or NULL if an error can be
 *          reported.
 **/
xdp_prog_t *xdp_prog_init(char *prog_init_err, int prog_init_err_len,
                          int max_frame_size, __u64 max_memory, int send_only,
                          int multi_queue, int multi_shard,
                          const char *virtio_dev, int max_queues_shards,
                          int hardware);

/**
 * @fn xdp_get_debug
 * @brief Returns the internal debugging flag.
 * @returns The internal debugging flag.
 **/
int xdp_get_debug(void);
/**
 * @fn xdp_debug
 * @brief Allows you to turn on/off debugging.  It sets a static so it can be
 *        done anytime.
 * @param[in] on Whether you want it on or off.
 * @returns None.
 **/
void xdp_debug(int on);
/**
 * @fn xdp_socket
 * @brief Call to create a socket to a remote system
 * @param[in] prog The return from xdp_prog_init
 * @param[in] reqs The required information to setup a socket.  Use
 *                 xdp_get_socket_reqs to obtain this info and leave it
 *                 allocated through the life of this socket.
 * @param[in] port The port to use for UDP traffic in host order.
 * @param[in] queue The 0 based queue number
 * @returns A pointer to xdp_socket_t if successful and NULL if an error can be
 *          reported.
 * @note reqs is not freed when the socket is freed so you can reuse it for
 *       another socket call.
 * @note Only one socket per queue has been tested.
 **/
xdp_socket_t *xdp_socket(xdp_prog_t *prog, lsxdp_socket_reqs_t *reqs, int port,
                         int queue);
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
 *            length is assumed to be the same as the addrLen above.  For
 *            sending you must specify either the addr_bind or the ifport.
 * @param[in] ifport Optional ethernet system port to use (required for
 *            listening).  For sending, you must specify either the addr_bind
 *            or the ifport.
 * @returns A pointer to lsxdp_socket_reqs_t if successful or NULL if not.
 * This pointer MUST be freed with a free() call when done.
 * @warning This function waits for up to 5 seconds for a packet response to
 * return. If it's integrated, there will need to be event handling done!
 **/
lsxdp_socket_reqs_t *xdp_get_socket_reqs(xdp_prog_t *prog,
                                         const struct sockaddr_storage *addr,
                                         socklen_t addrLen,
                                         const struct sockaddr_storage *addr_bind,
                                         const char *ifport);
/**
 * @fn xdp_get_local_addr
 * @brief Given a lsxdp_socket_reqs_t * returns the address bound to.
 * @param[in] prog The program handle.
 * @param[in] reqs The previously returned lsxdp_socket_reqs *
 * @param[in] ipv4 1 for ipv4 address; 0 for ipv6 address.
 * @param[out] addr The address that was bound to.
 * @returns -1 if the address couldn't be found; 0 if it could.
 **/
int xdp_get_local_addr(xdp_prog_t *prog,
                       lsxdp_socket_reqs_t *reqs,
                       int ipv4,
                       struct sockaddr_storage *addr);

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
 * @fn xdp_release_send_buffer
 * @brief Returns a send buffer to reuse.
 * @param[in] sock The socket to release from.
 * @param[in] buffer The buffer to release.
 * @returns Whether the buffer could be released.
 **/
int xdp_release_send_buffer(xdp_socket_t *sock, void *buffer);

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
 * @param[in] addr The destination address and port.  Required (in case they
 *                 change!)
 * @returns -1 for an error or 0 for success.
 **/
int xdp_send(xdp_socket_t *sock, void *data, int len, int last,
             struct sockaddr_storage *addr);

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
 * @param[in] addr The destination address and port.  Required (in case they
 *                 change!)
 * @returns -1 for an error or 0 for success.
 **/
int xdp_send_zc(xdp_socket_t *sock, void *buffer, int len, int last,
                struct sockaddr_storage *addr);

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
int xdp_recv(xdp_socket_t *sock, void **data, int *sz,
             struct sockaddr_storage *addr, socklen_t *addrlen);

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
 * @param[in] xdp_socket_t The socket previously created with xdp_prog_init
 * @returns None
 **/
void xdp_socket_close(xdp_socket_t *socket);

/**
 * @fn xdp_socket_close_child
 * @brief Call to close a socket previously opened with xdp_socket in a child
 *        process where another process is known to own the socket (a parent or
 *        another child).
 * @param[in] xdp_socket_t The socket previously created with xdp_socket.
 * @note If you use xdp_socket_close from a child, any other owners of this
 * socket will lose receive access as the eBPF filter map will have its value
 * removed!
 * @returns None
 **/
void xdp_socket_close_child(xdp_socket_t *socket);

/**
 * @fn xdp_socket_close2
 * @brief Call to close a socket previously opened with xdp_socket.  Lets you
 *        specify if you're a child and thus can't really close.
 * @param[in] xdp_socket_t The socket previously created with xdp_prog_init
 * @param[in] child 1 if you're a child for sure; 0 if you're a singleton or
 *                  a parent.
 * @returns None
 **/
void xdp_socket_close2(xdp_socket_t *socket, int child);

/**
 * @fn xdp_sockets_get_socket_for_fd
 * @brief Given an array of sockets and a fd, finds the socket that the
 *        fd belongs to.
 * @param[in] socks The array of valid sockets (0..n where n+1 is NULL).
 * @param[in] fd The file handle to check for.
 * @returns A pointer to the socket or a NULL if not found.
 **/
xdp_socket_t *xdp_sockets_get_socket_for_fd(xdp_socket_t *socks[], int fd);

/**
 * @fn xdp_sockets_get_socket_for_buf
 * @brief Given an array of sockets and a buffer, finds the socket that the
 *        buffer belongs to.
 * @param[in] socks The array of valid sockets (0..n where n+1 is NULL).
 * @param[in] buffer A buffer to check for in the array.
 * @returns A pointer to the socket or a NULL if not found.
 **/
xdp_socket_t *xdp_sockets_get_socket_for_buf(xdp_socket_t *socks[], void *buffer);

/**
 * @fn xdp_add_ip_filter
 * @brief Lets you add an IP to accept from.  All other UDP packets are dropped.
 * @param[in] xdp_socket_t The socket previously created with xdp_prog_init
 * @param[in] ipkey The IP address to accept.
 * @param[in] shard The shard number this filter is to be processed for.
 * @returns -1 if the filter can't be added.
 **/
int xdp_add_ip_filter(xdp_socket_t *socket, struct ip_key *ipkey, int shard);

/**
 * @fn xdp_assign_shard
 * @brief Call to set the shard number for a subtask.
 * @param[in] prog The program structure.
 * @param[in] shard  The shard number (1 based).
 * @returns None.
 **/
void xdp_assign_shard(xdp_prog_t *prog, int shard);

/**
 * @fn xdp_get_shard
 * @brief Call to get the shard number for a subtask.
 * @param[in] prog The program structure.
 * @returns The shard number (0 for the parent).
 **/
int xdp_get_shard(xdp_prog_t *prog);

/**
 * @fn xdp_change_in_port
 * @brief If you've created your socket, but need to change the listening port
 *        (for UDP receives for example), do it here.
 * @param[in] sock The socket structure.
 * @param[in] port The port to now use (in host order).
 * @returns None.
 **/
void xdp_change_in_port(xdp_socket_t *sock, __u16 port);

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
