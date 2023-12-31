/*

Summary: this module does L3 forwarding. For more info on this module, read the project README.

*/

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*

Summary: The following section defines the protocol headers used by packets. These include the IPv4, TCP, and Ethernet headers. A header declaration in P4 includes all the field names (in order) together with the size (in bits) of each field. Metadata is similar to a header but only holds meaning during switch processing. It is only part of the packet while the packet is in the switch pipeline and is removed when the packet exits the switch.

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
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

struct metadata {
    bit<16> hash_res;
    bit<14> ecmp_group_id;
}


/*

Summary: the following section defines logic required to parse a packet's headers. Packets need to be parsed in the same order they are added to a packet. See headers.p4 to see header declarations. Deparsing can be thought of as stitching the headers back into the packet before it leaves the switch. Headers need to be deparsed in the same order they were parsed.

*/

/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

     state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        
	}

    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
	    0x6: parse_tcp; 
      	    default: accept;
   	 }
    }

    state parse_tcp{
	packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // TODO: Deparse the ethernet, ipv4 and tcp headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4); 
	packet.emit(hdr.tcp);  
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  } 
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
   
    action set_nhop(egressSpec_t port) {
        standard_metadata.egress_spec = port;   
    }
    action drop() { 
	 mark_to_drop(standard_metadata);
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.hash_res, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort}, num_nhops); 
        meta.ecmp_group_id = ecmp_group_id;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ecmp_group;
            set_nhop;
            drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
    
    table ecmp_group_to_nhop {
    key = {
        meta.ecmp_group_id: exact;
        meta.hash_res: exact;
    }
    actions = {
        set_nhop;
        drop;
        NoAction;
    }
    size = 256;
    default_action = drop();
      
    }

    apply {
        switch (ipv4_lpm.apply().action_run) {
            ecmp_group: {
                ecmp_group_to_nhop.apply();
            }
            default: {
            }
        }
    } 
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);    
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
