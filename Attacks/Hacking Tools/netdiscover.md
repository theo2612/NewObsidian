The following command will scan a network for devices connected to it. 


```bash
$ sudo netdiscover -i enp0s3 -r 192.168.0.0/24

 Currently scanning: 192.168.0.0/24   |   Screen View: Unique Hosts

 24 Captured ARP Req/Rep packets, from 24 hosts.   Total size: 1554
 Currently scanning: 192.168.0.0/24   |   Screen View: Unique Hosts       _
 28 Captured ARP Req/Rep packets, from 27 hosts.   Total size: 1794
 Currently scanning: Finished!   |   Screen View: Unique Hosts                    -

 85 Captured ARP Req/Rep packets, from 29 hosts.   Total size: 5214               2
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      2.168
 -----------------------------------------------------------------------------
 192.168.0.6     6c:29:90:2f:fc:f8      6     360  WiZ Connected Lighting Company
 192.168.0.8     a8:bb:50:76:dd:dc      6     360  WiZ IoT Company Limited
 192.168.0.29    f8:54:b8:73:c5:7a      1      60  Amazon Technologies Inc.
 192.168.0.4     d8:a0:11:ba:07:73      6     360  WiZ
 192.168.0.46    70:2a:d5:e6:c3:ef      2     120  Samsung Electronics Co.,Ltd
 192.168.0.12    b0:39:56:75:97:16      1      60  NETGEAR
 192.168.0.19    b0:fc:0d:29:26:29      1      60  Amazon Technologies Inc.
 192.168.0.22    68:54:fd:6f:80:59      1      60  Amazon Technologies Inc.
 192.168.0.13    a4:77:33:47:fd:0c      2     120  Google, Inc.
 192.168.0.14    30:fd:38:b1:60:de      6     360  Google, Inc.
 192.168.0.23    b8:5f:98:81:56:a1      1      60  Amazon Technologies Inc.
 192.168.0.11    cc:9e:a2:cd:97:ce      1      60  Amazon Technologies Inc.
 192.168.0.30    c0:18:03:12:46:68      2     120  HP Inc.
 192.168.0.34    58:2f:40:0d:61:80      1      60  Nintendo Co.,Ltd
 192.168.0.31    a0:d0:dc:ab:22:98      1      60  Amazon Technologies Inc.
 192.168.0.83    10:7c:61:20:ff:d1      1      60  Unknown vendor
 192.168.0.62    b0:39:56:75:97:16      1      60  NETGEAR
 192.168.0.69    24:ce:33:b3:62:0c      1     174  Amazon Technologies Inc.
 192.168.0.239   9c:c9:eb:0f:53:bc      1      60  NETGEAR
 192.168.0.239   38:94:ed:1f:63:f3      1      60  NETGEAR
 192.168.0.252   00:00:ca:01:02:03      1      60  ARRIS Group, Inc.
 192.168.0.5     54:e0:19:48:fb:84     10     600  Ring LLC
 192.168.0.9     4c:24:98:33:a0:8b      1      60  Texas Instruments
```
