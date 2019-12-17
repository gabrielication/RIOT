PKG_NAME=mbed-crypto
PKG_URL=https://github.com/ARMmbed/mbed-crypto.git
PKG_VERSION=16027956cd383a6fcb125e7b9dfe41c6e8471c9b

.PHONY: all

CFLAGS += --std=c11

all:
	cp config.h $(PKG_BUILDDIR)/include/mbedtls/config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/library \
	-f $(RIOTPKG)/mbed-crypto/Makefile.$(PKG_NAME)

include $(RIOTBASE)/pkg/pkg.mk