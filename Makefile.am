AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I aclocal

if PATH_PLUGINS
pkgplugindir=$(PATH_PLUGINS)
else
pkgplugindir=$(NFSLIBDIR)/libnfsidmap
endif

libdir=${pkgplugindir}

LDAP_LIB = ldap_simple.la
pkgplugin_LTLIBRARIES = $(LDAP_LIB)

ldap_simple_la_SOURCES = ldap_simple.c
ldap_simple_la_LDFLAGS = -module -avoid-version
ldap_simple_la_LIBADD = conffile.o xlog.o -lldap

man5_MANS	= ldap_simple.5

conffile.o xlog.o:
	${AR} x ${NFSLIBDIR}/libnfsidmap.a conffile.o xlog.o

EXTRA_DIST = \
    autogen.sh \
	$(man5_MANS)

install-data-hook:
	@(cd $(DESTDIR)$(pkgplugindir) && $(RM) $(pkgplugin_LTLIBRARIES))
