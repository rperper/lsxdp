LiteSpeed XDP (LSXDP) Library README (updated May 1, 2020)
====================================

Description
-----------

LiteSpeed XDP (LSXDP) Library is intended to test LSQUIC with XDP and be an XDP enabler for LiteSpeed products.

After a clone
-------------
```
git submodule init
git submodule update
```

Building the library
--------------------
```
cmake .
make
```

Using the library
-----------------
See the test program test/testxdp.c for an example.  You should be able to compile it.  But MUCH more comprehensive testing can be done in the LSQUIC programs http_server and http_client.  At this time you need to use the latest `xdp` branch to get support.

The xdp and QUIC code has been heavily modified to best support the virtio-net driver used with most VMs.  While you can use other drivers, the best speed is with virtio-net.  However, you need to have the number of CPUs be less than the number of queues hardcoded into the driver.  My experience so far seems that 4 is the best.  Note that you need to listen on ALL queues with that driver, which means you need to use the -V option in http_server to accept requests.

You can also use direct hardware and support is available in xdp_prog_init().  Testing was done on an Intel 10 Gb Ethernet adapter with success.  However, it takes the driver out on install and removal for a few seconds.  It comes back and all works.

The test program has a lot of options.  To test it with UDP, on interface enp0s3 destination IP address 192.168.0.197, port 1972 and pausing after it runs you'd execute:
```
sudo ./testxdp -w -i 192.168.0.197 -e enp0s3 -p 1972
```
Note that since testxdp is an XDP program, it must be run as root.  So must all LSQUIC programs using LSXDP including http_client and http_server.

I kept **detailed** notes as I went and they are available in https://docs.google.com/document/d/1V5_36-SzMXPXacBAMOUPhSKXv7Ny4Fvz7G7kJV2DpAQ/edit?usp=sharing for LiteSpeed developers.


Other test programs
-------------------
Also in the test directory is **socketudprecv** which allows you to pretend to be a UDP receiver and it traces anything it receives.  It can receive tests from testxdp.  For example, to run it on 192.168.0.197 listening on port 1972, execute:
```
./socketudprecv -i 192.168.0.197 -p 1972
```
Note that it does not have to run run as root.
