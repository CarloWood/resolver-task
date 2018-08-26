AM_CPPFLAGS = -iquote $(top_builddir) -iquote $(top_srcdir) -iquote $(top_srcdir)/cwds

SUBDIRS = dns

noinst_LTLIBRARIES = libresolvertask.la

SOURCES = \
	AIResolver.h \
	AIResolver.cxx \
	AILookupTask.h \
	AILookupTask.cxx \
	AILookup.h \
	AILookup.cxx \
	AddressInfo.h \
	AddressInfo.cxx

libresolvertask_la_SOURCES = ${SOURCES}
libresolvertask_la_CXXFLAGS = -std=c++11 @LIBCWD_R_FLAGS@
libresolvertask_la_LIBADD = dns/src/libdns.la @LIBCWD_R_LIBS@

# --------------- Maintainer's Section

if MAINTAINER_MODE
distclean-local:
	-rm -f *.s *.ii

clean-local:
endif

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
