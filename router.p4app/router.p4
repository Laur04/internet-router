/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<8> TYPE_PWOSPF        = 0x0059;

const port_t CPU_PORT           = 0x1;
const macAddr_t CPU_MAC         = 0x1;
const bit<16> BCAST_GRP         = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}


header cpu_metadata_t {
    bit<16>   origEtherType;
    bit<16>   origSrcPort;
    bit<8>    awaitingARP;
}

header pwospf_t {
    bit<8>    version;
    bit<8>    type;
    bit<16>   length;
    bit<32>   router_id;
    bit<32>   area_id;
    bit<16>   checksum;
    bit<16>   autype;
    bit<64>   authentication;
}


struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    pwospf_t          pwospf;
}

struct metadata {
    ip4Addr_t         nextHop;
}


parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_PWOSPF: parse_pwospf;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_pwospf {
        packet.extract(hdr.pwospf);
        transition accept;
    }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.origSrcPort = (bit<16>) standard_metadata.ingress_port;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }
    
    action send_to_controller() {
        cpu_meta_encap();
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
        hdr.ethernet.dstAddr = CPU_MAC;
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_forward(ip4Addr_t nextHop, port_t port) {
        standard_metadata.egress_spec = port;
        meta.nextHop = nextHop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_dst_mac(macAddr_t dstMac) {
        hdr.ethernet.dstAddr = dstMac;
    }

    action trigger_arp_req() {
        hdr.cpu_metadata.awaitingARP = 1;
        send_to_controller();
    }

    action forward_local(port_t dstPort) {
        standard_metadata.egress_spec = dstPort;
        meta.nextHop = hdr.ipv4.dstAddr;
    }

    table routing {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            send_to_controller;
        }
        size = 1024;
        default_action = send_to_controller();
    }

    table arp {
        key = {
            meta.nextHop: exact;
        }
        actions = {
            set_dst_mac;
            trigger_arp_req;
        }
        size = 1024;
        default_action = trigger_arp_req();
    }

    table local {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            send_to_controller;
            forward_local;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            cpu_meta_decap();
        } 
        
        if (hdr.ethernet.etherType == TYPE_IPV4) {
            if (hdr.ipv4.isValid()) {
                if (hdr.ipv4.protocol == TYPE_PWOSPF) {
                    if (standard_metadata.ingress_port != CPU_PORT) {
                        send_to_controller();
                    } else {
                        if (hdr.pwospf.type == 1) {
                            hdr.ethernet.dstAddr = 0xffffffffffff;
                            standard_metadata.egress_spec = (port_t) hdr.cpu_metadata.origSrcPort;
                        } else {
                            standard_metadata.egress_spec = (port_t) hdr.cpu_metadata.origSrcPort;
                            meta.nextHop = hdr.ipv4.dstAddr;
                            arp.apply();
                        }
                    }
                } else {
                    switch(local.apply().action_run) {
                        forward_local: {
                            arp.apply();
                        }
                        NoAction: {
                            if (hdr.ipv4.ttl > 0) {
                                switch(routing.apply().action_run) {
                                    ipv4_forward: {
                                        arp.apply();
                                    }
                                }
                            } else {
                                mark_to_drop(standard_metadata);
                            }
                        }
                    }
                }                    
            } else {
                mark_to_drop(standard_metadata);            
            }
        } else if (hdr.ethernet.etherType == TYPE_ARP) {
            if (hdr.arp.isValid()) {
                if (standard_metadata.ingress_port != CPU_PORT) {
                    send_to_controller();
                } else {
                    if (hdr.arp.opcode == ARP_OP_REPLY) {
                        hdr.ethernet.dstAddr = hdr.arp.dstEth;
                        standard_metadata.egress_spec = (port_t) hdr.cpu_metadata.origSrcPort;
                    } else {
                        hdr.ethernet.dstAddr = 0xffffffffffff;
                        standard_metadata.mcast_grp = BCAST_GRP;
                    }
                }
            } else {
                mark_to_drop(standard_metadata);
            }
        } else {
            send_to_controller();
        }
    }
}


control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_src_mac(macAddr_t srcMac) {
        hdr.ethernet.srcAddr = srcMac;
    }

    table source_mac {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_src_mac;
            NoAction;
        }
        size = 8;
        default_action = NoAction();
    }

    apply {
        source_mac.apply();
    }
}


control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
	    update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.pwospf);
    }
}


V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
