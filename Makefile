SOBJ=$(PACKSODIR)/ldap4pl.$(SOEXT)
LIBS=-lldap

ifeq "$(DEBUG)" "1"
	CFLAGS += -DO_DEBUG
endif

ifeq "$(CC)" "gcc"
	CFLAGS += -std=c99 -DLDAP_DEPRECATED
endif

all:	$(SOBJ)

$(SOBJ): c/ldap4pl.o
	mkdir -p $(PACKSODIR)
	$(LD) $(LDSOFLAGS) $(SWISOLIB) -o $@ $< $(LIBS)

c/ldap4pl.o:
	$(CC) $(CFLAGS) -c -o c/ldap4pl.o c/ldap4pl.c

check::
install::
clean:
	rm -f c/ldap4pl.o
distclean: clean
	rm -f $(SOBJ)
