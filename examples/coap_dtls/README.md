# ADTLS 1.2 over CoAP Transport

This program provides an example of a DTLS 1.2 handshake and exchange of data using CoAP as a transport layer.
The [wolfSSL](https://github.com/wolfSSL/wolfssl) library was used for the DTLS 1.2 implementation and [gCoAP](https://riot-os.org/api/group__net__gcoap.html) as the CoAP implementation.

**KEEP IN MIND** that it is highly experimental at the moment and does suffer stability issues!

## Testing

Only the 'native' emulator was tested at the time of this release.

### On native:

You need to create two bridged tap interfaces in order to let client and server communicate:

    ./../../dist/tools/tapsetup/tapsetup --create 2

Then just compile and execute:

    make all term

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

    > dtlss
    
Which will start the DTLS server on the background. Keep it open.

You have to start the client now. Open a new terminal on the same folder. Type:

    PORT=tap1 make term
    
And then type `dtlsc` followed by the previous address you copied from the server, like:

    > dtlsc fe80::ac4a:f4ff:fef7:b23d
    
It will start printing all the bytes sent and received.

In the end they should both print a configuration message from both client and server and exit from the DTLS session.

### On ethos:

You need to create two bridged tap interfaces in order to let client and server communicate. We use this script to initialize only the bridge and the tap for a native client. The tap for the server will be done later:

    ./../../dist/tools/tapsetup/tapsetup --create 1

Compile for native:

    make clean all
    
Compile and flash for nrf:

    BOARD=nrf52840dk make clean all flash
    
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

    > dtlss

Keep the terminal of the server open.

You have to start the client now. Type in another terminal:

    make term

And then type `dtlsc` followed by the previous address you copied from the server, like:

    > dtlsc fe80::ac4a:f4ff:fef7:b23d
    
It will start printing all the bytes sent and received.

In the end they should both print a configuration message from both client and server and exit from the DTLS session.

## Known Bugs:

- CoAP can hang up sometimes. Currently working on a retransmission mechanism.

## Want to know more?

Just read the [paper](https://tools.ietf.org/html/draft-friel-tls-atls-03).
