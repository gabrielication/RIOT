include ../Makefile.tests_common

# AVR boards: require avr-gcc >= 7.0 (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=60040)
# MSP430 boards: invalid alignment of 'hydro_random_context'
BOARD_BLACKLIST := arduino-duemilanove arduino-leonardo \
                   arduino-mega2560 arduino-uno atmega328p \
                   mega-xplained microduino-corerf waspmote-pro \
                   chronos msb-430 msb-430h telosb wsn430-v1_3b wsn430-v1_4 z1

USEPKG += libhydrogen
USEMODULE += embunit

include $(RIOTBASE)/Makefile.include
