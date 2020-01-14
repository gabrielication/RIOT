# name of your application
APPLICATION = mbedtls

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
#USEMODULE += gnrc_netdev_default
#USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default

# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_commands

USEPKG += mbed-tls

# A larger stack size is required or the board will reboot
ifneq ($(BOARD),native)
  CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=2048
endif
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)

CFLAGS += -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function

# Uncomment the following line to add debug symbols
#CFLAGS+=-g -ggdb3

# CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include