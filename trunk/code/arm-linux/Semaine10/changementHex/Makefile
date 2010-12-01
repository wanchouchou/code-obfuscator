all: test

# OBJECTS
OBJECTS=test.o


# WHICH COMPILER
CC=gcc

# OPTIONS FOR DEVELOPMENT
CFLAGS= -c -Wall 


# LINKING OPTIONS
LINKS= -lstdc++
#LINKS= 


# COMPILING
.C.o:
	${CC} ${CFLAGS} -o $*.o $<

# LINKING
test: $(OBJECTS)
	gcc -o test $(OBJECTS) $(LINKS)

clean:
	rm *.o test
