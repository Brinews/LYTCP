#ifndef RDP_H
#define RDP_H

#include <netinet/in.h>

struct rdp_stats {
    unsigned int tbytes;
    unsigned int ubytes;
    unsigned int tpkts;
    unsigned int upkts;
    unsigned int ack;
    unsigned short syn;
    unsigned short fin;
    unsigned short rtr;
    unsigned short rts;
    struct timeval time;
};

struct socket_info {
    struct sockaddr_in addr;
    socklen_t length;
};

struct rdp_conn {
    struct socket_info self;
    struct socket_info peer;
    struct rdp_stats stats;
    unsigned int number;
    unsigned int window;
};

int rdp_send(int sock, struct rdp_conn *sender, const void *data, size_t length);
int rdp_receive(int sock, struct rdp_conn *receiver, void *data, size_t length, size_t *read);
int rdp_accept(int sock, struct rdp_conn *receiver);
int rdp_connect(int sock, struct sockaddr_in *addr, struct rdp_conn *sender);
void rdp_stats(const struct rdp_conn *context, int sender);
int rdp_close(int sock, struct rdp_conn *sender);

#endif // RDP_H
