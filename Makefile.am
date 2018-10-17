AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS = dns

noinst_LTLIBRARIES = libresolvertask.la

SOURCES = \
	AILookupTask.h \
	AILookupTask.cxx \
	Resolver.h \
	Resolver.cxx \
	Lookup.h \
	Lookup.cxx \
	AddressInfo.h \
	AddressInfo.cxx \
	Service.h \
	Service.cxx

libresolvertask_la_SOURCES = ${SOURCES}
libresolvertask_la_CXXFLAGS = @LIBCWD_R_FLAGS@
libresolvertask_la_LIBADD = dns/src/libdns.la @LIBCWD_R_LIBS@

# --------------- Maintainer's Section

if MAINTAINER_MODE
distclean-local:
	-rm -f *.s *.ii

clean-local:
endif

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
