#include <core.p4>
#include <v1model.p4>

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
    bit<16> num_nhops;
    bit<14> ecmp_gid;
    bit<48> interval;
    bit<16> flow_index1;
    bit<16> flow_index2;
    bit<16> flowlet_id;
}

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
        transition select(hdr.ipv4.protocol) {
            0x6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }   
    
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
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

    register<bit<48>>(1024) last_seen1;
    register<bit<16>>(1024) flowlet_id_tb1;
    register<bit<16>>(1024) flow_id_tb1;

    register<bit<48>>(1024) last_seen2;
    register<bit<16>>(1024) flowlet_id_tb2;
    register<bit<16>>(1024) flow_id_tb2;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action ecmp_group(bit<16> num_nhops){
        meta.num_nhops = num_nhops;
    }

    table ipv4_lpm {
 	key = {
            hdr.ipv4.dstAddr: lpm; 
        }

        actions = {
            set_nhop;
            ecmp_group;
            drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
	
    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_gid: exact; 
	}
        actions = {
            set_nhop;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    apply {
        bit<16> flow_id1;
        bit<16> flow_id2;
        bit<48> last_pkt_ts1;
        bit<48> last_pkt_ts2;
        bit<16> flow_sig;

        switch (ipv4_lpm.apply().action_run) {
            ecmp_group: {
		if (hdr.ipv4.isValid()){
                    hash(meta.flow_index1, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort, (bit<8>)1}, (bit<16>)1024);        
                    hash(meta.flow_index2, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort, (bit<8>)2}, (bit<16>)1024);                 
                    hash(flow_sig, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<16>)65535);        
	        flow_id_tb1.read(flow_id1, (bit<32>)meta.flow_index1);
	        flow_id_tb2.read(flow_id2, (bit<32>)meta.flow_index2);
                
                last_seen1.read(last_pkt_ts1, (bit<32>)meta.flow_index1);   
                last_seen2.read(last_pkt_ts2, (bit<32>)meta.flow_index2);
            
                if (flow_id1 == flow_sig) {
                    if (standard_metadata.ingress_global_timestamp - last_pkt_ts1 > 50000) {           
            	        random(meta.flowlet_id, (bit<16>)0, (bit<16>)65000);
		        flowlet_id_tb1.write((bit<32>)meta.flow_index1, meta.flowlet_id);
                    }
                    last_seen1.write((bit<32>)meta.flow_index1, standard_metadata.ingress_global_timestamp);
		    flowlet_id_tb1.read(meta.flowlet_id, (bit<32>)meta.flow_index1);
                } else if (flow_id2 == flow_sig) {
                    if (standard_metadata.ingress_global_timestamp - last_pkt_ts2 > 50000) {           
            	        random(meta.flowlet_id, (bit<16>)0, (bit<16>)65000);
		        flowlet_id_tb2.write((bit<32>)meta.flow_index2, meta.flowlet_id);
                    }
                    last_seen2.write((bit<32>)meta.flow_index2, standard_metadata.ingress_global_timestamp);
		    flowlet_id_tb2.read(meta.flowlet_id, (bit<32>)meta.flow_index2);
                } else {
                    if (last_pkt_ts1 < last_pkt_ts2){
                        flow_id_tb1.write((bit<32>)meta.flow_index1, flow_sig);        
                        last_seen1.write((bit<32>)meta.flow_index1, standard_metadata.ingress_global_timestamp);
            	        random(meta.flowlet_id, (bit<16>)0, (bit<16>)65000);
		        flowlet_id_tb1.write((bit<32>)meta.flow_index1, meta.flowlet_id);
                    } else {
                        flow_id_tb2.write((bit<32>)meta.flow_index2, flow_sig);        
                        last_seen2.write((bit<32>)meta.flow_index2, standard_metadata.ingress_global_timestamp);
            	        random(meta.flowlet_id, (bit<16>)0, (bit<16>)65000);
		        flowlet_id_tb2.write((bit<32>)meta.flow_index2, meta.flowlet_id);
                    }    
                }     
                hash(meta.ecmp_gid, HashAlgorithm.crc16, (bit<1>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort, meta.flowlet_id}, meta.num_nhops);
                }
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
