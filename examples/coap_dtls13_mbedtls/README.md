# ADTLS 1.3 over CoAP with Mbed TLS

This program provides an example of a DTLS 1.3 handshake using CoAP as a transport layer.
The [Mbed TLS](https://github.com/ARMmbed/mbedtls) library was used for the DTLS implementation and [gCoAP](https://riot-os.org/api/group__net__gcoap.html) as the CoAP implementation.

**KEEP IN MIND** that it is highly experimental at the moment and does suffer stability issues!

## Testing

You can test both on native and/or your board. Keep in mind that to this release only nrf52840dk was tested, other boards may not have enough RAM and/or flash memory.

Go to `RIOT/pkg/mbed-tls13/configs` and copy one of the configurations coherently with the ciphersuite and key exchange that you want to use. Paste that to `RIOT/pkg/mbed-tls13/config.h` file and save.

### On natives ONLY:

You need to create two bridged tap interfaces in order to let client and server communicate:

    ./../../dist/tools/tapsetup/tapsetup --create 2

Then just compile and execute:

    make clean all term WERROR=0

The first device **MUST** be the server. You have to grab its ip address first. Just type:

    > ifconfig
    
Which will output something like:

```
Iface  6  HWaddr: AE:4A:F4:F7:B2:3D 
          L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
          Link type: wired
          inet6 addr: fe80::ac4a:f4ff:fef7:b23d  scope: link  VAL
          inet6 group: ff02::1
          inet6 group: ff02::1:fff7:b23d
```

Copy the `inet6 addr` for later. Then you can start the server by choosing the ciphersuite and key exchange that you want to use. For example:

    > dtlss psk TLS_AES_128_CCM_SHA256
    
Which will start the TLS server on the background. Keep the terminal of the server open.

You have to start the client now. Open a new terminal on the same folder. Type:

    PORT=tap1 make term
    
And then type `dtlsc` followed by the previous server address you copied from the server, key exchange and the ciphersuite like:

    > dtlsc fe80::ac4a:f4ff:fef7:b23d psk TLS_AES_128_CCM_SHA256

In the end they should both print a test message from both client and server and exit from the TLS session.

### On ethos (native + nrf52840dk):

You need to create two bridged tap interfaces in order to let client and server communicate. We use this script to initialize only the bridge and the tap for a native. The tap for the other device will be done later:

    ./../../dist/tools/tapsetup/tapsetup --create 1

Compile and execute for native:

    make clean all term WERROR=0
    
Compile and flash for nrf:

    BOARD=nrf52840dk make clean all flash WERROR=0
    
Ethos device has to be started using one script in the tools folder. Just execute:

    sudo sh ../../dist/tools/ethos/start_network_wo_uhcpd.sh /dev/ttyACM0 tap1 2001:db8::/64
    
(It may happen that you do not have `ethos` compiled. Just go to `RIOT/dist/tools/ethos` and do a `make clean all`. Then you can go back to the example's folder.)

The ethos device has to be bridged, type on another terminal:

    sudo ip link set dev tap1 master tapbr0

The first device **MUST** be the server. You have to grab its ip address first. Just type on the terminal:

    > ifconfig
    
Which will output something like:

```
Iface  6  HWaddr: AE:4A:F4:F7:B2:3D 
          L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
          Link type: wired
          inet6 addr: fe80::ac4a:f4ff:fef7:b23d  scope: link  VAL
          inet6 group: ff02::1
          inet6 group: ff02::1:fff7:b23d
```

Copy the `inet6 addr` for later (if are using the nrf as server, make sure to grab the `wired` iface address). Then you can start the server by choosing the ciphersuite and key exchange that you want to use. For example:

    > dtlss psk TLS_AES_128_CCM_SHA256
    
Which will start the TLS server on the background. Keep the terminal of the server open.

You have to start the client now. Type `dtlsc` followed by the previous server address you copied from the server and the ciphersuite like:

    > dtlsc fe80::ac4a:f4ff:fef7:b23d psk TLS_AES_128_CCM_SHA256
    
If you are using the nrf as a client you have to specify also the interface (in this case the wired one is set to '7'), like:

    > dtlsc fe80::ac4a:f4ff:fef7:b23d%7 psk TLS_AES_128_CCM_SHA256

In the end they should both print a test message from both client and server and exit from the TLS session.

## Heap Measurement:

You can also log max heap usage. Just uncomment this line on the Makefile of the example:

    #CFLAGS += -DMBED_HEAP_LOG
    
At the end of the session the console will output also the maximum heap usage in both client and server. 

## Known Bugs:

- CoAP can hang up sometimes. Currently working on a retransmission mechanism.
- At this stage we have a lot of warnings from the library, just ignore them for the moment.

## Want to know more?

Just read the [draft](https://tools.ietf.org/html/draft-friel-tls-atls-03).
