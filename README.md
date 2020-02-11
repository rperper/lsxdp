LiteSpeed XDP (LSXDP) Library README
====================================

Description
-----------

LiteSpeed XDP (LSXDP) Library is intended to test LSQUIC with XDP.

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
See the test program test/testxdp.c for an example.  You should be able to compile it.

To run it you must be using an Ethernet driver that allows Large Receive Offload (LRO) to be disabled.  The virtio-net driver used with VirtualBox will not work.  For VirtualBox you must select a driver.  For my machine I chose the Am79C973 driver because it was the default before virtio.  The command in Windows to select this requires that you take the virtual machine down and run:
```
C:\Program Files\Oracle\VirtualBox>vboxmanage modifyvm "Lubuntu 19.10" --nictype1 Am79C973
```
Once run, you can restart the virtual machine and begin testing.

The test program has a lot of options.  To test it with UDP, on interface enp0s3 destination IP address 192.168.0.197, port 1972 and pausing after it runs you'd execute:
```
sudo ./testxdp -w -i 192.168.0.197 -e enp0s3 -p 1972
```
Note that since testxdp is an XDP program, it must be run as root.


Other test programs
-------------------
Also in the test directory is **socketudprecv** which allows you to pretend to be a UDP receiver and it traces anything it receives.  It can receive tests from testxdp.  For example, to run it on 192.168.0.197 listening on port 1972, execute:
```
./socketudprecv -i 192.168.0.197 -p 1972
```
Note that it does not have to run run as root.
