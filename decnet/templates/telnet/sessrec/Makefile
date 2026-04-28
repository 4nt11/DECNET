# Build sessrec, a tiny pty relay + transcript recorder installed as the
# login shell inside SSH / Telnet decky containers. Built per-image during
# the template Dockerfile's build stage; gcc + libc6-dev are installed only
# for this step and purged in the same layer.
#
# Output: /usr/libexec/login-session (plausible login-machinery name)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
LIBS    := -lutil

PREFIX  ?= /usr/libexec
TARGET  := login-session

all: $(TARGET)

$(TARGET): sessrec.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
	strip --strip-unneeded $@

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
