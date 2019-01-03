#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rdp.h"

#define BUFFER_SIZE 65536

int main(int argc, char **argv)
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    struct rdp_conn receiver;
    int fd, result, sock;
    size_t received;

    if (argc < 4) {
        printf("usage: %s receiver_ip receiver_port receiver_file_name\n", 
            *argv);
        exit(EXIT_FAILURE);
    }

    fd = open(argv[3], O_CREAT|O_TRUNC|O_WRONLY, 0777);

    sock = socket(AF_INET, SOCK_DGRAM, 0);    

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);
    addr.sin_port = htons(atoi(argv[2]));
    result = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

    rdp_accept(sock, &receiver);

    do {
        result = rdp_receive(sock, &receiver, buffer, BUFFER_SIZE, &received);
        // received data -> file.
        int r = write(fd, buffer, received);
		if (r < 0) {
			fprintf(stderr, "write data error\n");
		}
    } while (result > 0);

    rdp_stats(&receiver, 0);

    close(fd);
    close(sock);

    return 0;
}
