PKG_NAME=wolfssl
PKG_URL=https://github.com/wolfssl/wolfssl.git

# Current version: v4.4.0+
PKG_VERSION=d22016838483df80b60d4d6430b48969cc575937
PKG_LICENSE=GPLv2

.PHONY: all
all:  # Nothing to do here when building

prepare:
	cp Makefile.wolfssl $(PKG_BUILDDIR)/src/Makefile
	cp Makefile.wolfcrypt $(PKG_BUILDDIR)/wolfcrypt/src/Makefile
	touch $(PKG_BUILDDIR)/wolfssl.a
	cp Makefile.wolfcrypt-test $(PKG_BUILDDIR)/wolfcrypt/test/Makefile
	cp Makefile.wolfcrypt-benchmark $(PKG_BUILDDIR)/wolfcrypt/benchmark/Makefile

include $(RIOTBASE)/pkg/pkg.mk
