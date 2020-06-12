
cc=g++
cflags=-O3 -g
ldflags=-g 
CFLAGS=-I ../lib/
OBJ = node_list.o astnetwork.o wrap.o crc16.o md5.o

default: build
	@echo "Done"

build: node_list

node_list: $(OBJ)
	$(cc) $(ldflags) $(CFLAGS) -o node_list $(OBJ)

%.o: %.cpp Makefile
	${cc} $(CFLAGS) ${cflags} -c $<
	
clean:
	rm -f *.o
	rm -f node_list
