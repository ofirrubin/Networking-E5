CC=gcc
AR=ar
FLAGS= -Wall -g


all: sniffer

sniffer: sniffer.o
	$(CC) $(FLAGS) sniffer.c -o sniffer -lpcap



.PHONY: clean all

clean: # Remove any file that might created.
	rm -f *.o *.a *.so *.gch sniffer