PKG_NAME=mbed-tls13
PKG_URL=git@github.com:ARMmbed/mbed-tls-tls-1.3-prototype.git
PKG_VERSION=e3a6a8cd8dc18ab58f3a3095b8fa4fab8231c0a8

.PHONY: all

all:
	cp config.h $(PKG_BUILDDIR)/include/mbedtls/config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/library \
	-f $(RIOTPKG)/mbed-tls13/Makefile.$(PKG_NAME)

include $(RIOTBASE)/pkg/pkg.mk