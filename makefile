all: rdpr rdps

CC = gcc
CFLAGS = -Wall -O3

rdpr: rdp.o rdppkt.o rdpr.o
rdps: rdp.o rdppkt.o rdps.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm *.o
