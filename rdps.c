/**
 * RDP sender
 * Date: 2017-3-9
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rdp.h"

int main(int argc, char **argv)
{
    struct sockaddr_in srcaddr;
    struct sockaddr_in dstaddr;
    struct rdp_conn sender;
    struct stat fs;
    void *data;
    int fd, result, sock;

    if (argc < 6) {
        printf("usage: %s sender_ip sender_port receiver_ip "
            "receiver_port sender_file_name\n", *argv);
        exit(EXIT_FAILURE);
    }

    fd = open(argv[5], O_RDONLY);
	fstat(fd, &fs);
    data = mmap(NULL, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);    

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Sender
    memset(&srcaddr, 0, sizeof(srcaddr));
    srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = inet_addr(argv[1]);
    srcaddr.sin_port = htons(atoi(argv[2]));

    // Receiver
    memset(&dstaddr, 0, sizeof(dstaddr));
    dstaddr.sin_family = AF_INET;
    dstaddr.sin_addr.s_addr = inet_addr(argv[3]);
    dstaddr.sin_port = htons(atoi(argv[4]));

    result = bind(sock, (struct sockaddr *) &srcaddr, sizeof(srcaddr));

    // Establish connection with receiver.
    rdp_connect(sock, &dstaddr, &sender);

    // Send contents of file.
    rdp_send(sock, &sender, data, fs.st_size);

    // Output connection statistics.
    rdp_stats(&sender, 1);

    close(sock);
    munmap(data, fs.st_size);

    return 0;
}
