Last login: Thu Jun  8 17:11:25 on ttys000

The default interactive shell is now zsh.
To update your account to use zsh, please run `chsh -s /bin/zsh`.
For more details, please visit https://support.apple.com/kb/HT208050.
carolyns-MBP:~ carolynsong$ ssh p4@localhost -p4444
p4@localhost's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-144-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

23 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Your Hardware Enablement Stack (HWE) is supported until April 2023.
*** System restart required ***
Last login: Thu Jun  8 10:12:18 2023 from 10.0.2.2
p4@ubuntu:~$ cd cs145-23-project3
p4@ubuntu:~/cs145-23-project3$ ls
apps        log                p4src           README.md     test_scripts
controller  logs               pcap            report        topology
figures     p4_explanation.md  pull_update.sh  tcpdump_logs  topology.json
p4@ubuntu:~/cs145-23-project3$ cd p4src/
p4@ubuntu:~/cs145-23-project3/p4src$ ls
l2fwd.p4  l3fwd.json  l3fwd.p4  l3fwd.p4i
p4@ubuntu:~/cs145-23-project3/p4src$ less l3fwd.p4

/*

Summary: this module does L3 forwarding. For more info on this module, read the project README.

*/

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*

Summary: The following section defines the protocol headers used by packets. These include the IPv4, TCP, and Ethernet headers. A header declaration in P4 includes all the field names (in order) together with the size
 (in bits) of each field. Metadata is similar to a header but only holds meaning during switch processing. It is only part of the packet while the packet is in the switch pipeline and is removed when the packet exits 
the switch.

*/


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
:
