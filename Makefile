# $Id: Makefile,v 1.4 1999/08/20 18:24:12 sova Exp sova $

OS=$(shell uname)

DEBUGFLAGS=-DDEBUG=512

include Makefile.$(OS)

#INC=-I/usr/netscape/server4/plugins/slapd/slapi/include
#INC=-I/usr/local/directory-5.2/plugins/slapd/slapi/include
INC=-I/usr/include/dirsrv -I/usr/include/nspr
HDR	= udb.h md5.h otp_password.h
SRC	= udb.c otp_password.c md5c.c btoe.c udb_hash.c rdwr.c otp_sasl.c \
	util.c udb_config.c udb_mod.c udb_func.c

OBJS	= $(SRC:.c=.o)

SSM_SRC	= udb_mod.c udb_config.c udb_func.c util.c
SSM_OBJS = $(SSM_SRC:.c=.o)

all:	udb.so

ssm:	ssm.so

ssm.so:	$(SSM_OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

fake:	fake.so

fake.so: fake.o
	$(LD) $(LDFLAGS) -o $@ $^

udb.so:	$(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

test-config: udb_config.c
	$(CC) $(CFLAGS) -DMAIN=1 -o $@ $< -lefence 

test-config-checker: udb_config.c 
	checkergcc $(CFLAGS) -DMAIN=1 -o $@ $<

test-preop.so: test-preop.o
	$(LD) $(LDFLAGS) -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -f *.so *.o

distclean: clean
	-rm -f *.d

checkin: $(SRC)
	$(CI) -l -t-init -m"" $(SRC)

tags:	$(SRC)
	etags $(SRC) $(HDR)

#.c.d:
%.d: %.c
	@$(SHELL) -ec '$(CC) -MM $(CPPFLAGS) $< \
        | sed '\''s/\($*\)\.o[ :]*/\1.o $@ : /g'\'' > $@; \
        [ -s $@ ] || rm -f $@'

#include $(SRC:.c=.d)

install:
	cp *.so ../../plugins
depend:
	$(CC) $(CFLAGS) -MM $(SRC) > depend
#	-makedepend -Y $(SRC) >/dev/null 2>&1

# DO NOT DELETE

#udb.o: udb.h otp_password.h
#otp_password.o: udb.h otp_password.h md5.h
#md5c.o: md5.h
#btoe.o: otp_password.h md5.h
#udb_hash.o: udb_hash.h rdwr.h
#rdwr.o: rdwr.h
