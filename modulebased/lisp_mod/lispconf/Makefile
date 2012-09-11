CC=gcc
GENGETOPT=gengetopt
CFLAGS=-I../include -g
DEPS = ../include/lisp_ipc.h
LIBS = -lm
LDFLAGS = $(LIBS)
OBJS = cmdline.o lispconf.o 

lispconf: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS)

cmdline.c: lispconf.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm *.o cmdline.[ch]
