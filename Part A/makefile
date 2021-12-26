CC=gcc
AR=ar
FLAGS= -Wall -g


all: myping

myping: myping.o
	$(CC) $(FLAGS) myping.c -o myping



.PHONY: clean all

clean: # Remove any file that might created.
	rm -f *.o *.a *.so *.gch myping
