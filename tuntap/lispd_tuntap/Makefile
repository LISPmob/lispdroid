#
#	Makefile for lispd
#
#
#
#	David Meyer
#	dmm@1-4-5.net
#	Mon Apr 19 11:40:19 2010
#
#	$Header: /home/dmm/lisp/lispd/RCS/Makefile,v 1.2 2010/04/19 22:02:33 dmm Exp $
#


CC		= gcc
GENGETOPT	= gengetopt
CFLAGS		= -I../include -g -DDEBUG=3
LIBS		= -lconfuse -lssl -lrt
INC		= lispd.h
MAKEFILE	= Makefile
OBJS		= cmdline.o lispd.o lispd_config.o lispd_syslog.o	\
		  lispd_lib.o lispd_ipc.o lispd_map_register.o		\
		  patricia/patricia.o lispd_map_request.o cksum.o	\
		  lispd_patricia.o 
EXE		= lispd

$(EXE): $(OBJS) 
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

#
#	gengetops generates this...
#
cmdline.c: lispd.ggo
	$(GENGETOPT) -i $<

%.o: %.c $(DEPS) $(INC) $(MAKEFILE)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm *.o cmdline.[ch] $(EXE) patricia/*.o

