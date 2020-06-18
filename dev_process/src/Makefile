cc=g++
cflags=-g
ldflags=-g 
CFLAGS=-I ../lib/
OBJ = dev_process.o astnetwork.o crc16.o md5.o

default: build
	@echo "Done"

build: dev_process

dev_process: $(OBJ)
	$(cc) $(ldflags) $(CFLAGS) -o dev_process $(OBJ)

%.o: %.cpp Makefile
	${cc} $(CFLAGS) ${cflags} -c $<
	
clean:
	rm -f *.o
	rm -f dev_process
