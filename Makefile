SOBJ=$(PACKSODIR)/ldap4pl.$(SOEXT)
LIBS=-lldap

all:	$(SOBJ)

$(SOBJ): c/ldap4pl.o
	mkdir -p $(PACKSODIR)
	$(LD) $(LDSOFLAGS) $(SWISOLIB) -o $@ $< $(LIBS)

c/ldap4pl.o:
	$(CC) $(CFLAGS) -std=c99 -DO_DEBUG -DLDAP_DEPRECATED -c -o c/ldap4pl.o c/ldap4pl.c

check::
install::
clean:
	rm -f c/ldap4pl.o
distclean: clean
	rm -f $(SOBJ)
