include ../Makefile.tests_common
USEMODULE += embunit
USEMODULE += usbus
FEATURES_PROVIDED += periph_usbdev

# USB device vendor and product ID
DEFAULT_VID = 1209
DEFAULT_PID = 0001
USB_VID ?= $(DEFAULT_VID)
USB_PID ?= $(DEFAULT_PID)

CFLAGS += -DUSB_CONFIG_VID=0x$(USB_VID) -DUSB_CONFIG_PID=0x$(USB_PID)

include $(RIOTBASE)/Makefile.include

.PHONY: usb_id_check
usb_id_check:
	@if [ $(USB_VID) = $(DEFAULT_VID) ] || [ $(USB_PID) = $(DEFAULT_PID) ] ; then \
		$(COLOR_ECHO) "$(COLOR_RED)Private testing pid.codes USB VID/PID used!, do not use it outside of test environments!$(COLOR_RESET)" 1>&2 ; \
		$(COLOR_ECHO) "$(COLOR_RED)MUST NOT be used on any device redistributed, sold or manufactured, VID/PID is not unique!$(COLOR_RESET)" 1>&2 ; \
	fi

all: | usb_id_check
