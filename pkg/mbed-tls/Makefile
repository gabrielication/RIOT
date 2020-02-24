PKG_NAME=mbed-tls
PKG_URL=https://github.com/ARMmbed/mbedtls.git
PKG_VERSION=0fce215851cc069c5b5def12fcc18725055fa6cf

.PHONY: all

all:
	cp config.h $(PKG_BUILDDIR)/include/mbedtls/config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/library \
	-f $(RIOTPKG)/mbed-tls/Makefile.$(PKG_NAME)

include $(RIOTBASE)/pkg/pkg.mk