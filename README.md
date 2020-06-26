## ATLS and ADTLS prototypes on RIOT OS

This branch presents different prototypes running Application Layer TLS and DTLS sessions over CoAP using RIOT OS as the base environment for the tests.
RIOT is a real-time multi-threading operating system that supports a range of
devices that are typically found in the Internet of Things (IoT):
8-bit, 16-bit and 32-bit microcontrollers. For more information, see the [RIOT website](https://www.riot-os.org).

[Mbed TLS](https://github.com/ARMmbed/mbedtls) and [WolfSSL](https://github.com/wolfSSL/wolfssl) are the TLS/DTLS libraries used in our tasks.

In order to run the prototypes you have to go to `RIOT/examples` and enter to the `coap_tls*` or `coap_dtls*` folders. In there you will find the READMEs that will explain how to run them.

## LICENSE
* Most of the code developed by the RIOT community is licensed under the GNU
  Lesser General Public License (LGPL) version 2.1 as published by the Free
  Software Foundation.
* Some external sources, especially files developed by SICS are published under
  a separate license.

All code files contain licensing information.
