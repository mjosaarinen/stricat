# Makefile
# 07-Dec-13 	Markku-Juhani O. Saarinen <mjos@cblnk.com>
#		See LICENSE for Licensing and Warranty information.

BINARY		= stricat
OBJS     	= blnk.o iocom.o main.o selftest.o \
		sbob_pi64.o sbob_tab64.o stribob.o streebog.o
DIST            = stricat

CC		= gcc
CFLAGS          = -Wall -O3
LIBS            =
LDFLAGS         =
INCLUDES        =

$(BINARY):      $(OBJS)
		$(CC) $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

.c.o:
		$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
		rm -rf $(DIST)-*.tgz $(OBJS) $(BINARY) *~ 

dist:           clean		
		cd ..; \
		tar cfvz $(DIST)-`date "+%Y%m%d%H%M00"`.tgz $(DIST)/*
