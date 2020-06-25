include ../Makefile.tests_common

USEPKG += mbed-tls

# A larger stack size is required or the board will reboot
ifneq ($(BOARD),native)
  CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=2048
endif
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)

CFLAGS += -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function

include $(RIOTBASE)/Makefile.include