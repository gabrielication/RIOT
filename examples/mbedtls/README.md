# ATLS 1.3 over CoAP with Mbed TLS

This program provides an example of a TLS 1.3 handshake and exchange of data using CoAP as a transport layer.
The [mbed TLS](https://github.com/ARMmbed/mbedtls) library was used for the TLS 1.3 implementation and [gCoAP](https://riot-os.org/api/group__net__gcoap.html) as the CoAP implementation.

**KEEP IN MIND** that it is highly experimental at the moment and does suffer stability issues!

## Testing

You can test both on native and/or your board. Keep in mind that to this release only nrf52840dk was tested, other boards may not have enough RAM and/or flash memory.

### On native:

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

Copy the `inet6 addr` for later. Then type:

    > server
    
Which will start the TLS server on the background. Keep it open.

You have to start the client now. Open a new terminal on the same folder. Type:

    PORT=tap1 make term
    
And then type `client` followed by the previous address you copied from the server, like:

    > client fe80::ac4a:f4ff:fef7:b23d
    
It will start by default in a verbose mode printing all the bytes sent and received (you can disable it by changing a flag in the code).

In the end they should both print a test message from both client and server and exit from the TLS session.

### On ethos:

You need to create two bridged tap interfaces in order to let client and server communicate. We use this script to initialize only the bridge and the tap for a native client. The tap for the server will be done later:

    ./../../dist/tools/tapsetup/tapsetup --create 1

Compile and execute (for native):

    make clean all term WERROR=0
    
Compile and flash for nrf:

    BOARD=nrf52840dk make clean all flash WERROR=0
    
Ethos has to be started using one script in the tools folder. Just execute:

    sudo sh ../../dist/tools/ethos/start_network_wo_uhcpd.sh /dev/ttyACM0 tap1 2001:db8::/64

The ethos device has to be bridged, type on another terminal:

    sudo ip link set dev tap1 master tapbr0

The first device **MUST** be the server. You have to grab its ip address first. Just type on the ethos terminal:

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

Copy the `inet6 addr` for later. Then type:

    > server
    
Which will start the TLS server on the background. Keep it open.

You have to start the client now. Return to the native terminal and then type `client` followed by the previous address you copied from the server, like:

    > client fe80::ac4a:f4ff:fef7:b23d
    
It will start by default in a verbose mode printing all the bytes sent and received (you can disable it by changing a flag in the code).

In the end they should both print a test message from both client and server and exit from the TLS session.

## Known Bugs:

- CoAP can hang up sometimes. Currently working on a retransmission mechanism.
- A lot of warnings.

## Want to know more?

Just read the [draft](https://tools.ietf.org/html/draft-friel-tls-atls-03).
