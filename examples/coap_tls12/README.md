# ATLS 1.3 over CoAP Transport

This program provides an example of a TLS 1.2 handshake and exchange of data using CoAP as a transport layer.
The [wolfSSL](https://github.com/wolfSSL/wolfssl) library was used for the TLS 1.2 implementation and [gCoAP](https://riot-os.org/api/group__net__gcoap.html) as the CoAP implementation.

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

    > tlss
    
Which will start the TLS server on the background. Keep it open.

You have to start the client now. Open a new terminal on the same folder. Type:

    PORT=tap1 make term
    
And then type `tlsc` followed by the previous address you copied from the server, like:

    > tlsc fe80::ac4a:f4ff:fef7:b23d
    
It will start by default in a verbose mode printing all the bytes sent and received (you can disable it by changing a flag in the code).

In the end they should both print a test message from both client and server and exit from the TLS session.

## Known Bugs:

The last print of test messages can print also some random characters. I just have to find where to put correctly the string terminators.

## Want to know more?

Just read the [paper](https://tools.ietf.org/html/draft-friel-tls-atls-03).
