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
