#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include "rdp.h"
#include "rdppkt.h"

// RDP header strings.
#define RDP_ACK_HDR "Magic: cscs361p2\nType: ACK\nAcknowledgement: %u\nWindow: %u\n\n"
#define RDP_DAT_HDR "Magic: cscs361p2\nType: DAT\nSequence: %u\nPayload %u\n\n"
#define RDP_FIN_HDR "Magic: cscs361p2\nType: FIN\nSequence: %u\n\n"
#define RDP_RST_HDR "Magic: cscs361p2\nType: RST\n\n"
#define RDP_SYN_HDR "Magic: cscs361p2\nType: SYN\nSequence: %u\n\n"


// packet size.
#define RDP_BUF_SIZE 1024
#define RDP_MAX_PAY 959

// RDP timing.
#define RDP_BURST 100
#define RDP_RETRANS 3
#define RDP_RE_TIME 1000000
#define RDP_WAIT_TIME 250000

#define RDP_ADDR_LEN 16

#define RDP_SEND 's'
#define RDP_RESEND 'S'
#define RDP_RECEIVE 'r'
#define RDP_DUPLICATE 'R'

/*
 * @param conn connection of rdp
 */
void rdp_begin(struct rdp_conn *conn)
{
    gettimeofday(&conn->stats.time, NULL);
}

/*
 * param conn connection of rdp
 */
void rdp_end(struct rdp_conn *conn)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    // calculate time consuming
    if (conn->stats.time.tv_usec > now.tv_usec) {
        int n = (conn->stats.time.tv_usec - now.tv_usec) / 1000000 + 1;
        conn->stats.time.tv_sec += n;
        conn->stats.time.tv_usec -= 1000000 * n;
    }

    conn->stats.time.tv_sec = now.tv_sec - conn->stats.time.tv_sec; 
    conn->stats.time.tv_usec = now.tv_usec - conn->stats.time.tv_usec;
}

/*
 * @param event event associated with packet
 * @parma sender sending address
 * @param receiver receiving address
 * @param type packet type
 * @param number packet number
 * @param info packet information
 */
void rdp_log(char event, const struct sockaddr_in *sender,
    const struct sockaddr_in *receiver, int type, unsigned int number,
    unsigned int info)
{
    char sndaddr[RDP_ADDR_LEN];
    char recvaddr[RDP_ADDR_LEN];
    unsigned int h, m, s, us;
    struct timeval tv;

    // Time format
    gettimeofday(&tv, NULL);
    h = (tv.tv_sec / 3600 - 8) % 24;
    m = tv.tv_sec / 60 % 60;
    s = tv.tv_sec % 60;
    us = tv.tv_usec;

    // IP addresses.
    strncpy(sndaddr, inet_ntoa(sender->sin_addr), RDP_ADDR_LEN);
    strncpy(recvaddr, inet_ntoa(receiver->sin_addr), RDP_ADDR_LEN);

    // packet log
    switch (type) {
    case RDP_ACK:
    case RDP_DAT:
        printf("%02u:%02u:%02u.%d %c %s:%d %s:%d %s %u %u\n", h, m, s, us,
            event, sndaddr, ntohs(sender->sin_port), recvaddr,
            ntohs(receiver->sin_port), rdp_types[type], number, info);
        break;
    case RDP_FIN:
    case RDP_SYN:
        printf("%02u:%02u:%02u.%d %c %s:%d %s:%d %s %u\n", h, m, s, us,
            event, sndaddr, ntohs(sender->sin_port), recvaddr,
            ntohs(receiver->sin_port), rdp_types[type], number);
        break;
    case RDP_RST:
        printf("%02u:%02u:%02u.%d %c %s:%d %s:%d %s\n", h, m, s, us, event,
            sndaddr, ntohs(sender->sin_port), recvaddr,
            ntohs(receiver->sin_port), rdp_types[type]);
        break;
    default:
        fprintf(stderr, "invalid packet\n");
    }
}

/*
 * @param sock socket handler
 * @param sender rpd connection
 */
void rdp_reset(int sock, struct rdp_conn *sender)
{
    char buffer[RDP_BUF_SIZE];

    int fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_RST_HDR);
    sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
        &sender->peer.addr, sender->peer.length);

    sender->stats.rts++;
    rdp_log(RDP_SEND, &sender->self.addr, &sender->peer.addr,
        RDP_RST, 0, 0);
}

/*
 * @param sock socket handler
 * @param receiver rdp connection
 * @return 0: packet received, -1: no packet received
 */
int rdp_accept(int sock, struct rdp_conn *receiver)
{
    char buffer[RDP_BUF_SIZE];
    struct rdp_packet packet;
    int fill_len, result;

    memset(receiver, 0, sizeof(*receiver));
    receiver->self.length = sizeof(receiver->self.addr);
    receiver->peer.length = sizeof(receiver->peer.addr);
    result = getsockname(sock, (struct sockaddr *) &receiver->self.addr,
        &receiver->self.length);

    // timing and receive incoming connection.
    rdp_begin(receiver);
    result = recvfrom(sock, buffer, RDP_BUF_SIZE, 0, (struct sockaddr *)
        &(receiver->peer.addr), &receiver->peer.length);

    // packet interpret
    result = rdp_interp(buffer, result, &packet);
    rdp_log(RDP_RECEIVE, &receiver->peer.addr, &receiver->self.addr,
        packet.type, packet.number, packet.info);

    // packet is a synchronization packet?
    if (packet.type != RDP_SYN) {
        switch (packet.type) {
        case RDP_FIN:
            receiver->stats.fin++;
            break;
        case RDP_RST:
            receiver->stats.rtr++;
        }

        fprintf(stderr, "exptected SYN packet\n");
        return -1;
    }

    // update state
    receiver->number = packet.number + 1;
    receiver->window = RDP_BUF_SIZE;

    // ACK packet.
    fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_ACK_HDR,
        receiver->number, receiver->window);
    result = sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
        &receiver->peer.addr, receiver->peer.length);

    receiver->stats.ack++;

    rdp_log(RDP_SEND, &receiver->self.addr, &receiver->peer.addr,
        RDP_ACK, receiver->number, receiver->window);
    return 0;
}

/* 
 * @param sock socket handler
 * @param sender send connection
 * @return int 0: success close, -1: not success
 * -1.
 */
int rdp_close(int sock, struct rdp_conn *sender)
{
    char buffer[RDP_BUF_SIZE];
    struct rdp_packet packet;
    struct timeval timeout;
    int trys, fill_len, result;
    fd_set readers;

    for (trys = 0; trys < RDP_RETRANS; trys++) {
        fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_FIN_HDR,
            sender->number);
        result = sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
            &sender->peer.addr, sender->peer.length);

        sender->stats.fin++;
        rdp_log(trys ? RDP_RESEND : RDP_SEND, &sender->self.addr,
            &sender->self.addr, RDP_FIN, sender->number, 0);

        do {
            FD_ZERO(&readers);
            FD_SET(sock, &readers);

            // timeout 
            timeout.tv_sec = 0;
            timeout.tv_usec = RDP_RE_TIME;

            // select with timeout.
            result = select(sock + 1, &readers, NULL, NULL, &timeout);

            if (result > 0) {
                result = recvfrom(sock, buffer, RDP_BUF_SIZE, 0,
                    (struct sockaddr *) &sender->peer.addr,
                    &sender->peer.length);

                rdp_interp(buffer, result, &packet);
                rdp_log(packet.number < sender->number + 1 ?
                    RDP_DUPLICATE : RDP_RECEIVE, &sender->peer.addr,
                    &sender->self.addr, packet.type, packet.number,
                    packet.info);

                if (packet.type == RDP_ACK) {
                    sender->stats.ack++;

                    // FIN acknowledgement.
                    if (packet.number == sender->number + 1) {
                        rdp_end(sender);
                        return 0;
                    }
                } else if (packet.type == RDP_RST) {
                    sender->stats.rtr++;
                    rdp_end(sender);
                    return -1;
                } else {
                    rdp_reset(sock, sender);
                }
            }
        } while (result);
    }

    rdp_end(sender);
    fprintf(stderr, "host not responsive\n");
    return -1;
}

/*
 *  @param sock socket handler
 *  @param addr client address
 *  @param sender rdp connection
 *  @return 0: ok, -1: failed
 */
int rdp_connect(int sock, struct sockaddr_in *addr, struct rdp_conn
    *sender)
{
    char buffer[RDP_BUF_SIZE];
    struct rdp_packet packet;
    struct timeval timeout;
    int fill_len, trys, result;
    fd_set readers;

    memset(sender, 0, sizeof(*sender));
    sender->peer.addr = *addr;
    sender->self.length = sizeof(sender->self.addr);
    sender->peer.length = sizeof(*addr);
    result = getsockname(sock, (struct sockaddr *) &sender->self.addr,
        &sender->self.length);

    rdp_begin(sender);
    fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_SYN_HDR, sender->number);

    // retransmit until a response is received. 
    for (trys = 0; trys < RDP_RETRANS; trys++) {
        FD_ZERO(&readers);
        FD_SET(sock, &readers);

        // timeout
        timeout.tv_sec = RDP_RE_TIME * (1 << trys) / 1000000;
        timeout.tv_usec = RDP_RE_TIME * (1 << trys) % 1000000;

        result = sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
            &sender->peer.addr, sender->peer.length);
        
        sender->stats.syn++;
        rdp_log(trys ? RDP_RESEND : RDP_SEND, &sender->self.addr,
            &sender->peer.addr, RDP_SYN, sender->number, 0);

        // select with timeout.
        result = select(sock + 1, &readers, NULL, NULL, &timeout);

        if (result < 0) {
            perror("select");
            return -1;
        } else if (result > 0) {
            break;
        }
    }

    if (trys >= RDP_RETRANS) {
        fprintf(stderr, "connection timeout\n");
        return -1;
    }

    // response.
    result = recvfrom(sock, buffer, RDP_BUF_SIZE, 0, (struct sockaddr *)
        &sender->peer.addr, &sender->peer.length);

    result = rdp_interp(buffer, result, &packet);    
    rdp_log(RDP_RECEIVE, &sender->peer.addr, &sender->self.addr,
        packet.type, packet.number, packet.info);

    if (result < 0) {
        return -1;
    }

    // handle response.
    switch (packet.type) {
    case RDP_ACK:
        sender->stats.ack++;

        if (packet.number == sender->number + 1) {
            sender->number++;
            sender->window = packet.info;
            return 0;
        }
    default:
        rdp_reset(sock, sender);
    case RDP_RST:
        sender->stats.rtr++;
        fprintf(stderr, "connection failure\n");
        return -1;
    }
}

/*
 * @param sock socket handler
 * @param rdp_conn rdp connection
 * @param data received data
 * @param length length of received data
 * @return int state of connection, 1: open, 0: closed, -1: reset
 */
int rdp_receive(int sock, struct rdp_conn *receiver, void *data,
    size_t length, size_t *read)
{
    char buffer[RDP_BUF_SIZE];
    char eventr, events;
    struct rdp_packet packet;
    int fill_len, result;
    *read = 0;

    receiver->window = length;

    // Receive data buffer can accomodate.
    while (length - *read > RDP_MAX_PAY) {
        result = recvfrom(sock, buffer, RDP_BUF_SIZE, 0, NULL, NULL);

        rdp_interp(buffer, result, &packet);

        // packet is a duplicate?
        if (packet.number < receiver->number) {
            eventr = RDP_DUPLICATE;
            events = RDP_RESEND;
        } else {
            eventr = RDP_RECEIVE;
            events = RDP_SEND;
        }

        rdp_log(eventr, &receiver->peer.addr, &receiver->self.addr,
            packet.type, packet.number, packet.info);

        // handle received packet.
        switch (packet.type) {
        case RDP_FIN:
            receiver->stats.fin++;
            fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_ACK_HDR,
                receiver->number + 1, receiver->window);
            result = sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
                &receiver->peer.addr, receiver->peer.length);


            rdp_end(receiver);
            receiver->stats.ack++;
            rdp_log(events, &receiver->self.addr, &receiver->peer.addr,
                RDP_ACK, receiver->number + 1, receiver->window);
            return 0;
        case RDP_DAT:
            // check DAT packet
            if (packet.number == receiver->number) {
                fill_len = packet.info < RDP_BUF_SIZE ?
                    packet.info : RDP_BUF_SIZE;
                memcpy(data + *read, packet.data, fill_len);
                *read += fill_len;
                receiver->number += fill_len;
                receiver->window -= fill_len;
                receiver->stats.ubytes += packet.info;
                receiver->stats.upkts++;
            }

            receiver->stats.tbytes += packet.info;
            receiver->stats.tpkts++;
            break;
        case RDP_SYN:
            receiver->stats.syn++;
            break;
        case RDP_RST:
            receiver->stats.rtr++;
            eventr = RDP_RECEIVE;
            rdp_end(receiver);
            return -1;
        }

        // Acknowledge packet.
        fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_ACK_HDR,
            receiver->number, receiver->window);
        result = sendto(sock, buffer, fill_len, 0, (struct sockaddr *)
            &receiver->peer.addr, receiver->peer.length);

        receiver->stats.ack++;
        rdp_log(events, &receiver->self.addr, &receiver->peer.addr,
            RDP_ACK, receiver->number, receiver->window);
    }

    return 1;
}

/*
 * @param sock socket handler
 * @param sender rdp connection
 * @param data data to send
 * @param length send data length
 * @return int state of connection, 1: open, 0: closed, -1: reset
 */
int rdp_send(int sock, struct rdp_conn *sender, const void *data,
    size_t length)
{
    char buffer[RDP_BUF_SIZE];
    char event;

    struct rdp_packet packet;

    struct timeval timeout;

    size_t sent = 0;
    int fill_len, i, result;

    unsigned int rmd, pay, seq;
    unsigned int trys = 0;
    unsigned int pre = sender->number - 1;
    unsigned int wnd = length;
    unsigned int start = sender->number;
    unsigned int received;

    fd_set readers;

    // send packets with error resend
    while (wnd) {
        // receiver's window
        rmd = sender->window < wnd ? sender->window : wnd;
        seq = sender->number;

        for (i = 0; i < RDP_BURST && rmd; i++) {
            pay = rmd < RDP_MAX_PAY ? rmd : RDP_MAX_PAY;

            rmd -= pay;

            // Send data.
            fill_len = snprintf(buffer, RDP_BUF_SIZE, RDP_DAT_HDR,
                seq, pay);
            memcpy(buffer + fill_len, data + seq - start, pay);
            result = sendto(sock, buffer, fill_len + pay, 0,
                (struct sockaddr *) &sender->peer.addr,
                sender->peer.length);

            // sent already?
            if (seq > pre) {
                pre = seq;
                event = RDP_SEND;
                sender->stats.tbytes += pay;
                sender->stats.ubytes += pay;
                sender->stats.upkts++;
                sender->stats.tpkts++;
            } else {
                event = RDP_RESEND;
                sender->stats.tbytes += pay;
                sender->stats.tpkts++;
            }

            rdp_log(event, &sender->self.addr, &sender->peer.addr,
                RDP_DAT, seq, pay);
            seq += pay;
        }

        received = 0;

        do {
            FD_ZERO(&readers);
            FD_SET(sock, &readers);

            // timeout
            timeout.tv_sec = 0;
            timeout.tv_usec = RDP_WAIT_TIME;

            result = select(sock + 1, &readers, NULL, NULL, &timeout);

            if (result > 0) {
                result = recvfrom(sock, buffer, RDP_BUF_SIZE, 0, NULL,
                    NULL);

                received++;
                rdp_interp(buffer, result, &packet);

                if (packet.type == RDP_ACK) {
                    if (packet.number > sender->number) {
                        event = RDP_RECEIVE;
                        sent += packet.number - sender->number;
                        sender->number = packet.number;
                        sender->window = packet.info;
                        wnd = length - sent;

                        if (packet.number == seq) {
                            result = 0;
                        }
                    } else {
                        event = RDP_DUPLICATE;
                    }

                    sender->stats.ack++;
                    rdp_log(event, &sender->peer.addr,
                        &sender->self.addr, packet.type, packet.number,
                        packet.info);
                } else if (packet.type == RDP_RST) {
                    sender->stats.rtr++;
                    rdp_log(RDP_RECEIVE, &sender->peer.addr,
                        &sender->self.addr, packet.type, packet.number,
                        packet.info);
                    return -1;
                }
            }
        } while (result);

        // increment trys count.
        if (!received) {
            trys++;
        } else {
            trys = 0;
        }

        // if trys limit is reached, stop sending and reset connection.
        if (trys == RDP_RETRANS) {
            rdp_reset(sock, sender);
            rdp_end(sender);
            return -1;
        }
    }

    return 0;
}

/*
 * @param conn rdp connection
 * @param sender is a send or not
 */
void rdp_stats(const struct rdp_conn *conn, int sender)
{
    char *a1, *a2;
    double dur;

    if (sender) {
        a1 = "sent";
        a2 = "received";
    } else {
        a1 = "received";
        a2 = "sent";
    }

    dur = conn->stats.time.tv_sec;
    dur += conn->stats.time.tv_usec / 1000000.0;

    printf("total data bytes %s: %u\n", a1, conn->stats.tbytes);
    printf("unique data bytes %s: %u\n", a1, conn->stats.ubytes);
    printf("total data packets %s: %u\n", a1, conn->stats.tpkts);
    printf("unique data packets %s: %u\n", a1, conn->stats.upkts);

    printf("SYN packets %s: %u\n", a1, conn->stats.syn);
    printf("FIN packets %s: %u\n", a1, conn->stats.fin);
    printf("RST packets %s: %u\n", a1, sender ?  conn->stats.rts : conn->stats.rtr);
    printf("ACK packets %s: %u\n", a2, conn->stats.ack);
    printf("RST packets %s: %u\n", a2, sender ?  conn->stats.rtr : conn->stats.rts);

    printf("total time duration: %.3fs\n", dur);
}
