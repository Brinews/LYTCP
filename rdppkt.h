#ifndef RDP_PKT_H
#define RDP_PKT_H

// RDP header types.
#define RDP_ACK 0
#define RDP_DAT 1
#define RDP_FIN 2
#define RDP_RST 3
#define RDP_SYN 4

#define RDP_TYPE_COUNT 5

// RDP packet 
struct rdp_packet {
    char *data;
    unsigned int number;
    unsigned int info;
    int type; 
};

// RPD types
static const char *rdp_types[RDP_TYPE_COUNT] = {
    "ACK",
    "DAT",
    "FIN",
    "RST",
    "SYN"
};

int rdp_interp(char *buffer, size_t length, struct rdp_packet *packet);

#endif // RDP_PKT_H
