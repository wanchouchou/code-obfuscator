all: elftest

# OBJECTS
OBJECTS=elftest.o


# WHICH COMPILER
CC=arm-linux-gcc

# OPTIONS FOR DEVELOPMENT
CFLAGS= -c -Wall 


# LINKING OPTIONS
LINKS= -lstdc++
#LINKS= 


# COMPILING
.C.o:
	${CC} ${CFLAGS} -o $*.o $<

# LINKING
elftest: $(OBJECTS)
	arm-linux-gcc -o elftest $(OBJECTS) $(LINKS)

clean:
	rm *.o elftest
