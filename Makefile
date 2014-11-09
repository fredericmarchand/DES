des:	des.o
		g++ des.o -o des

des.o:  
		g++ -c des.cpp -o des.o
clean:
		rm -rf *.o des
