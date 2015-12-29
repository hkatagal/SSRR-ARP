# This is a sample Makefile which compiles source files named:

CC = gcc

LIBS = 	-lpthread\
	/users/cse533/Stevens/unpv13e/libunp.a\
	
LIBS1 = /users/cse533/Asgn3_code\
	
	
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I/users/cse533/Stevens/unpv13e/lib

all: tour_hkatagal arp_hkatagal


#client	
tour_hkatagal.o: tour_hkatagal.c
	${CC} ${CFLAGS} -c tour_hkatagal.c

tour_hkatagal: tour_hkatagal.o
	${CC} ${FLAGS} -o tour_hkatagal tour_hkatagal.o ${LIBS}

#get_hw_addrs
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${FLAGS} -c get_hw_addrs.c

#ping
# ping.o: ping.c 
	# ${CC} ${CFLAGS} -c ping.c
	
# ping: ping.o
	# ${CC} ${FLAGS} -o ping ping.o ${LIBS}
	
#ODR	
arp_hkatagal.o: arp_hkatagal.c
	${CC} ${CFLAGS} -c arp_hkatagal.c

arp_hkatagal: arp_hkatagal.o get_hw_addrs.o
	${CC} ${FLAGS} -o arp_hkatagal arp_hkatagal.o get_hw_addrs.o ${LIBS}


clean:
	rm arp_hkatagal.o arp_hkatagal tour_hkatagal.o tour_hkatagal get_hw_addrs.o
