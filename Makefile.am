SUBDIRS = tests

bin_PROGRAMS = jai

AM_CXXFLAGS = $(MOUNT_CFLAGS) $(LIBACL_CFLAGS)

jai_SOURCES = complete.cc cred.cc default_conf.cc fs.cc jai.cc	\
options.cc argtype.h config.h cred.h defer.h err.h fs.h jai.h	\
options.h
jai_LDADD = $(MOUNT_LIBS) $(LIBACL_LIBS)

man1_MANS = jai.1

jai.1: jai.1.md
	-pandoc -s -w man jai.1.md -o jai.1

sysusersdir = $(prefix)/lib/sysusers.d
sysusers_DATA = jai.conf

bashcompdir = $(datadir)/bash-completion/completions
bashcomp_DATA = bash-completion/jai

EXTRA_DIST = jai.1 jai.1.md jai.conf.in bash-completion/jai logo.svg

CLEANFILES = *~ jai.suid
DISTCLEANFILES = jai.conf

maintainer-clean-local:
	-rm -rf .deps

MAINTAINERCLEANFILES = \
	jai.1 \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/configure \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in \
	$(srcdir)/depcomp \
	$(srcdir)/install-sh \
	$(srcdir)/missing

JAI_USER = @UNTRUSTED_USER@

install-exec-hook:
	-chown root $(DESTDIR)$(bindir)/jai
	-chmod 04511 $(DESTDIR)$(bindir)/jai

install-data-hook:
	test ! -r "$(DESTDIR)/etc/passwd" || \
		([[ "$(prefix)" == /usr || "$(prefix)" == /usr/local ]] && \
		systemd-sysusers --root="$(DESTDIR)/") || :

uninstall-hook:
	@set -x; if test -r "$(DESTDIR)/etc/passwd" && \
	[[ "$(prefix)" == /usr || "$(prefix)" == /usr/local ]] && \
	gecos=$$(getent passwd @UNTRUSTED_USER@ 2>/dev/null | cut -d: -f5) \
	    && test "$$gecos" = "JAI sandbox untrusted user"; then \
	  echo "userdel $(JAI_USER)"; \
	  userdel -R "$(DESTDIR)/" "$(JAI_USER)" || :; \
	fi
