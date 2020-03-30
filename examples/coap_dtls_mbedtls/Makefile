# name of your application
APPLICATION = coap_dtls_mbedtls

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
# Specify the mandatory networking modules
USEMODULE += gcoap
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

# Required by gcoap example
USEMODULE += od
USEMODULE += fmt

CFLAGS += -DGCOAP_PDU_BUF_SIZE=1512

# A larger stack size is required if using ECC or RSA
ifneq ($(BOARD),native)
  # 2048 is the minimum when using certificates
  # YOU CAN DISABLE THIS IF YOU WANT TO USE PSK ONLY OTHERWISE
  # BOARDS LIKE nrf52dk will not work
  CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=2048
endif
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(5*THREAD_STACKSIZE_DEFAULT\)

# Add also the shell, some shell commands
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEPKG += mbed-tls

CFLAGS += -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function

# Uncomment the following line to add debug symbols
#CFLAGS+=-g -ggdb3

# CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP

TAP ?= tap0
IPV6_PREFIX ?= 2001:db8::/64

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include