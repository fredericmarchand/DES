des:	des.o
		g++ des.o -o des

des.o:	des.h 
		g++ -c des.cpp -o des.o
clean:
		rm -rf *.o des
