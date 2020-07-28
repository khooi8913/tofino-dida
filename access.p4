#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define TOLERABLE_RANGE 0x14

struct metadata_t {
    // indexes
    bit<16> index0;
    bit<16> index1;
    bit<16> index2;

    bit<1> is_request;
    bit<1> is_ctrl;
    bit<1> is_attack;
    bit<2> exceed;

    bit<16> increment_val;
    bit<16> current_tstamp;
}

struct pair {
    bit<16>     first;
    bit<16>     second;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP    : parse_tcp;
            IP_PROTOCOLS_UDP    : parse_udp;
        }

    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_CTRL : parse_ctrl;
            default   : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_CTRL : parse_ctrl;
            default   : accept;
        }
    }

    state parse_ctrl {
        pkt.extract(hdr.ctrl);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_zero;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_zero_zero;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_one;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_one_one;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_two;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_two_two;

    Register<pair,_>(32w65536) sketch0;
    Register<pair,_>(32w65536) sketch1;
    Register<pair,_>(32w65536) sketch2;

    RegisterAction<pair, bit<16>, void> (sketch0) sketch0_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch0) sketch0_diff = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            bit<16> temp;
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            
            temp = hdr.ctrl.counter_val - val.first;
            rv = temp;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch1) sketch1_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch1) sketch1_diff = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            bit<16> temp;
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            
            temp = hdr.ctrl.counter_val - val.first;
            rv = temp;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch2) sketch2_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch2) sketch2_diff = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            bit<16> temp;
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            
            temp = hdr.ctrl.counter_val - val.first;
            rv = temp;
        }
    };

    // Hash
    action hash0_ctrl() {
        ig_md.index0 = hash_zero_zero.get(
            {
                hdr.ipv4.dst_addr,
                hdr.ipv4.src_addr,
                hdr.ipv4.protocol,
                hdr.udp.dst_port,
                hdr.udp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.src_port
            }
        );
    }

    action hash0_req() {
        ig_md.index0 = hash_zero.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.tcp.src_port,
                hdr.tcp.dst_port
            }
        );
    }

    action hash1_ctrl() {
        ig_md.index1 = hash_one_one.get(
            {
                hdr.ipv4.dst_addr,
                hdr.ipv4.src_addr,
                hdr.ipv4.protocol,
                hdr.udp.dst_port,
                hdr.udp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.src_port
            }
        );
    }

    action hash1_req() {
        ig_md.index1 = hash_one.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.tcp.src_port,
                hdr.tcp.dst_port
            }
        );
    }


    action hash2_ctrl() {
        ig_md.index2 = hash_two_two.get(
            {
                hdr.ipv4.dst_addr,
                hdr.ipv4.src_addr,
                hdr.ipv4.protocol,
                hdr.udp.dst_port,
                hdr.udp.src_port,
                hdr.tcp.dst_port,
                hdr.tcp.src_port
            }
        );
    }

    action hash2_req() {
        ig_md.index2 = hash_two.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.tcp.src_port,
                hdr.tcp.dst_port
            }
        );
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;    // drop packet
    }

    action forward(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action countRequests() {
        ig_md.is_request = 1;
    }

    action markPacket() {
        ig_md.is_ctrl = 1;
    }
    
    action markAttack() {
        hdr.ctrl.flag = 0xAAAA;
        hdr.ipv4.dst_addr = hdr.ctrl.source_rtr_id;
        hdr.ctrl.counter_val = 0;
        hdr.ctrl.tstamp_val = 0;
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action unmarkAttack() {
        hdr.ctrl.setInvalid();
    }

    table ipv4_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward;
            NoAction;
        }
        default_action = NoAction();
    }

    table mark_packet {
        key = {
            hdr.ipv4.frag_offset : exact;
            hdr.udp.dst_port : exact;
            hdr.ctrl.flag : exact;
        }
        actions = {
            NoAction;
            countRequests;
            markPacket;
        }
        default_action = NoAction;
    }

    table compute_hash0 {
        key = {
            ig_md.is_ctrl : exact;
        }
        actions = {
            hash0_req;
            hash0_ctrl;
            NoAction;
        }
        default_action = NoAction();
    }

    table compute_hash1 {
        key = {
            ig_md.is_ctrl : exact;
        }
        actions = {
            hash1_req;
            hash1_ctrl;
            NoAction;
        }
        default_action = NoAction();
    }

    table compute_hash2 {
        key = {
            ig_md.is_ctrl : exact;
        }
        actions = {
            hash2_req;
            hash2_ctrl;
            NoAction;
        }
        default_action = NoAction();
    }

    table mark_attack {
        key = {
            ig_md.is_attack : exact;
        }
        actions = {
            markAttack;
            unmarkAttack;
        }
        default_action = unmarkAttack();
    }
  
    apply {
        ig_md.current_tstamp = ig_intr_md.ingress_mac_tstamp[47:32];
        ipv4_forward.apply();

        // differentiate between requests and responses (with control header)
        mark_packet.apply();
        
        // init val
        ig_md.is_attack = 0; 
        ig_md.exceed = 0; 

        compute_hash0.apply();
        compute_hash1.apply();
        compute_hash2.apply();

        if(ig_md.is_request == 1) {
            sketch0_count.execute(ig_md.index0); 
            sketch1_count.execute(ig_md.index1); 
            sketch2_count.execute(ig_md.index2); 
        } else if(ig_md.is_ctrl == 1) {
            // only compare counts with same tstamps (corner case)
            if((hdr.ctrl.tstamp_val == ig_md.current_tstamp)) {
                bit<12> temp0;
                bit<12> temp1;
                bit<12> temp2;

                // have to cast to 12-bits (hw limitation)
                temp0 = (bit<12>)sketch0_diff.execute(ig_md.index0);
                if(temp0 > TOLERABLE_RANGE) {
                    ig_md.exceed = ig_md.exceed + 1;
                }

                temp1 = (bit<12>)sketch1_diff.execute(ig_md.index1);
                if(temp1 > TOLERABLE_RANGE) {
                    ig_md.exceed = ig_md.exceed + 1;
                }

                temp2 = (bit<12>)sketch2_diff.execute(ig_md.index2);
                if(temp2 > TOLERABLE_RANGE) {
                    ig_md.exceed = ig_md.exceed + 1;
                }

                if(ig_md.exceed == 3) {
                    ig_md.is_attack = 1;
                }
            }
            
            mark_attack.apply();
        }
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
