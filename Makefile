hw3: hw3.o
	mpicc -g -Wall -o hw3 hw3.o -lcrypto -lssl

hw3.o: hw3.c
	mpicc -g -Wall -c hw3.c -o hw3.o