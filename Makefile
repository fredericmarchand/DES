des:	des.o
		gcc des.o -o des

des.o:	des.h 
		gcc -c des.c -o des.o
clean:
		rm -rf *.o des
