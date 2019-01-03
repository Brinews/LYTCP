#include <stdlib.h>
#include <string.h>
#include "rdppkt.h"

#define RDP_DELIMS " \t\n:"
#define RDP_BITS_COUNT 6
#define RDP_TOKEN_COUNT RDP_BITS_COUNT * 2 + 1

// RDP header bits.
#define RDP_ACK_BITS 0x0001
#define RDP_MAG_BITS 0x0002
#define RDP_PAY_BITS 0x0004
#define RDP_SEQ_BITS 0x0008
#define RDP_TYP_BITS 0x0010
#define RDP_WIN_BITS 0x0020
#define RDP_DAT_BITS 0x0040


int rdp_interp_magic(char *, struct rdp_packet*);
int rdp_interp_number(char *, struct rdp_packet*);
int rdp_interp_info(char *, struct rdp_packet*);
int rdp_interp_type(char *, struct rdp_packet*);


typedef int (*rdp_interp_func)(char *, struct rdp_packet *);

const int rdp_contents[RDP_TYPE_COUNT] = {
    RDP_MAG_BITS | RDP_TYP_BITS | RDP_ACK_BITS | RDP_WIN_BITS,
    RDP_MAG_BITS | RDP_TYP_BITS | RDP_SEQ_BITS | RDP_PAY_BITS,
    RDP_MAG_BITS | RDP_TYP_BITS | RDP_SEQ_BITS,
    RDP_MAG_BITS | RDP_TYP_BITS,
    RDP_MAG_BITS | RDP_TYP_BITS | RDP_SEQ_BITS
};

const char *rdp_fields[RDP_BITS_COUNT] = {
    "acknowledgement",
    "magic",
    "payload",
    "sequence",
    "type",
    "window"
};

const rdp_interp_func rdp_parsers[RDP_BITS_COUNT] = {
    rdp_interp_number,
    rdp_interp_magic,
    rdp_interp_info,
    rdp_interp_number,
    rdp_interp_type,
    rdp_interp_info
};

/*
 * @param field to find string
 * @param array strings to be searched
 * @param length strings size
 * @return index of found, -1 for not found
 */
int rdp_bsearch(char *field, const char **array, size_t length)
{
    int low = 0;
    int high = length - 1;
    int mid;
    int result;

    do {
        mid = (low + high) / 2;
        result = strcasecmp(field, array[mid]);
        if (result < 0) {
            high = mid - 1;
        } else if (result > 0) {
            low = mid + 1;
        } else {
            return mid;
        }
    } while (low <= high);

    return -1;
}
/*
 * @param field string to check
 * @param packet RDP packet
 * @return int 0
 */
int rdp_interp_type(char *field, struct rdp_packet *packet)
{
    int result = rdp_bsearch(field, rdp_types, RDP_TYPE_COUNT);
    
    if (result < 0) {
        return -1; 
    } 

    packet->type = result;
    return result;
}

/* 
 * @param buffer RDP packet
 * @param length packet length
 * @param packet structure of packet
 * @return int -1 failed
 */
int rdp_interp(char *buffer, size_t length,
		struct rdp_packet *packet)
{
    char *ctx;
    char *token;
    int field;
    int contents = 0;
    packet->type = -1;

    int ret = -1;

    token = strstr(buffer, "\n\n");

    if (!token)  return ret;

    *token = '\0';
    packet->data = token + 2;

    if (packet->data - buffer < length) {
        contents |= RDP_DAT_BITS;
    }

    for (token = strtok_r(buffer, RDP_DELIMS, &ctx); token; 
        token = strtok_r(NULL, RDP_DELIMS, &ctx)) {
        // Find header field code.
        field = rdp_bsearch(token, rdp_fields, RDP_BITS_COUNT); 
        // header field is valid?
        if (field < 0) return ret; 

        // get field associated with header field.
        token = strtok_r(NULL, RDP_DELIMS, &ctx);

        if (!token) return ret;
        if (rdp_parsers[field](token, packet) < 0) return ret;

        contents |= 1 << field;
    }

    if (packet->type < 0) {
        return 1;
    } else {
        if (rdp_contents[packet->type] != contents)
            return -1;
        else
            return packet->type;
    }
}

/*
 * @param field string to check
 * @param packet dummy parameter
 * @returns int 0 for supported, non-zero otherwise.
 */
int rdp_interp_magic(char *field, struct rdp_packet *packet)
{
    return !strcasecmp("cscs361p2", field);
}


/*
 * @param field string to check
 * @param packet RDP packet
 * @return int 0
 */
int rdp_interp_number(char *field, struct rdp_packet *packet)
{
    packet->number = atoi(field);
    return 0;
}

/*
 * @param field string to check
 * @param packet RDP packet
 * @return int 0
 */
int rdp_interp_info(char *field, struct rdp_packet *packet)
{
    packet->info = atoi(field);
    return 0;
}


