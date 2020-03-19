PKG_NAME=mbed-tls
PKG_URL=https://github.com/ARMmbed/mbedtls.git
PKG_VERSION=acfa36890c80971f915e46e90c2176185161d5ef

.PHONY: all

all:
	cp config.h $(PKG_BUILDDIR)/include/mbedtls/config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/library \
	-f $(RIOTPKG)/mbed-tls/Makefile.$(PKG_NAME)

include $(RIOTBASE)/pkg/pkg.mk