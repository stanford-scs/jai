bin_PROGRAMS = jai

AM_CXXFLAGS = $(MOUNT_CFLAGS) $(LIBACL_CFLAGS)

jai_SOURCES = complete.cc cred.cc default_conf.cc fs.cc jai.cc	\
options.cc cred.h argtype.h defer.h err.h fs.h jai.h
jai_LDADD = $(MOUNT_LIBS) $(LIBACL_LIBS)

man1_MANS = jai.1

jai.1: jai.1.md
	-pandoc -s -w man jai.1.md -o jai.1

sysusersdir = $(prefix)/lib/sysusers.d
sysusers_DATA = jai.conf

bashcompdir = $(datadir)/bash-completion/completions
bashcomp_DATA = bash-completion/jai

EXTRA_DIST = jai.1 jai.1.md jai.conf.in jai.bash logo.svg

CLEANFILES = *~
DISTCLEANFILES = jai.conf

distclean-local:
	-rm -rf .deps

MAINTAINERCLEANFILES = \
	jai.1 \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/configure \
	$(srcdir)/Makefile.in \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/missing

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/jai
	-chmod 04511 $(DESTDIR)$(bindir)/jai

install-data-hook:
	test ! -r "$(DESTDIR)/etc/passwd" || \
		systemd-sysusers --root="$(DESTDIR)/"

uninstall-hook:
	@if test -r "$(DESTDIR)/etc/passwd" && \
	gecos=$$(getent passwd @UNTRUSTED_USER@ 2>/dev/null | cut -d: -f5) \
	    && test "$$gecos" = "JAI sandbox untrusted user"; then \
	  echo "userdel @UNTRUSTED_USER@"; \
	  userdel -R "$(DESTDIR)/" @UNTRUSTED_USER@; \
	fi
