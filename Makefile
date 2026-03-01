
DESTDIR=
PREFIX=/usr/local

all: jai

CXX ?= c++
CXXFLAGS ?= -std=gnu++23 -Wall -Werror -ggdb
CPPFLAGS += $(shell pkg-config --cflags mount libacl)
LDLIBS += $(shell pkg-config --libs mount libacl)

OBJS = fs.o jai.o

all: jai jai.1

jai: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDLIBS)

.c.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $<

$(OBJS): jai.h

jai.1: jai.1.md
	-pandoc -s -w man jai.1.md -o jai.1
	@touch jai.1

install: all
	install -D -o root -m 04511 -t $(DESTDIR)$(PREFIX)/bin jai
	install -D -t $(DESTDIR)$(PREFIX)/share/man/man1 jai.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/jai \
		$(DESTDIR)$(PREFIX)/share/man/man1/jai.1

clean:
	rm -f jai *~ *.o

.PHONY: all clean install uninstall
