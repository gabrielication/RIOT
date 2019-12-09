# name of your application
APPLICATION = coap_dtls

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# use ethos (ethernet over serial) for network communication and stdio over
# UART, but not on native, as native has a tap interface towards the host.
ifeq (,$(filter native,$(BOARD)))
  GNRC_NETIF_NUMOF := 2
  USEMODULE += stdio_ethos

  # ethos baudrate can be configured from make command
  ETHOS_BAUDRATE ?= 115200
  CFLAGS += -DETHOS_BAUDRATE=$(ETHOS_BAUDRATE)
endif

# Increase from default for confirmable block2 follow-on requests
GCOAP_RESEND_BUFS_MAX ?= 2
CFLAGS += -DGCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gcoap
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

# Required by gcoap example
USEMODULE += od
USEMODULE += fmt

# include sha256 (used by example blockwise handler)
USEMODULE += hashes

# Modules to include:
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfssl
USEMODULE += wolfssl_dtls

# Select public key algorithm (or PSK) support for ciphersuites:
# You have to redefine also the PDU_BUF_SIZE
USEMODULE += wolfcrypt_ecc
CFLAGS += -DGCOAP_PDU_BUF_SIZE=1024

# USEMODULE += wolfssl_psk
# CFLAGS += -DGCOAP_PDU_BUF_SIZE=256

# DTLS stuff
CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable

# A larger stack size is required if using ECC or RSA
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)

# Comment this out to enable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
#DEVELHELP = 1

# Use different settings when compiling for one of the following (low-memory)
# boards
LOW_MEMORY_BOARDS := nucleo-f334r8

ifneq (,$(filter $(BOARD),$(LOW_MEMORY_BOARDS)))
  $(info Using low-memory configuration for microcoap_server.)
  ## low-memory tuning values
  # lower pktbuf buffer size
  CFLAGS += -DGNRC_PKTBUF_SIZE=1000
  USEMODULE += prng_minstd
endif

TAP ?= tap0
IPV6_PREFIX ?= 2001:db8::/64

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

# Set a custom channel if needed
include $(RIOTMAKE)/default-radio-settings.inc.mk
