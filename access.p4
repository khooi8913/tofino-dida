#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"


struct metadata_t {
    // indexes
    bit<16> index0;
    bit<16> index1;
    bit<16> index2;

    bit<1> is_request;
    bit<1> is_ctrl;
    bit<1> is_attack;
    bit<2> exceed;

    bit<32> tolerable_range;

    // window ID
    // bit<32> relative_window_id;
    // bit<32> global_window_id;

    // bit<16> ts;
}

struct pair {
    bit<32>     first;
    bit<32>     second;
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

    Register<bit<32>,_>(32w65536) sketch0;
    Register<bit<32>,_>(32w65536) sketch1;
    Register<bit<32>,_>(32w65536) sketch2;

    RegisterAction<bit<32>, _, void> (sketch0) sketch0_count = {
        void apply(inout bit<32> val) {
            val = val + 1;
        }
    };
    RegisterAction<bit<32>, _, bit<2>> (sketch0) sketch0_read = {
        void apply(inout bit<32> val, out bit<2> rv) {
            // rv = val;
            rv = 0;

            bit<32> temp;
            temp = val;
            bit<32> diff;
            diff = hdr.ctrl.counter_val - val;

            val = diff;
            if(val > ig_md.tolerable_range) {
                rv = 1;
            }
            val = temp;
        }
    };


    RegisterAction<bit<32>, _, void> (sketch1) sketch1_count = {
        void apply(inout bit<32> val) {
            val = val + 1;
        }
    };
    RegisterAction<bit<32>, _, bit<2>> (sketch1) sketch1_read = {
        void apply(inout bit<32> val, out bit<2> rv) {
            // rv = val;
            rv = 0;

            bit<32> temp;
            temp = val;
            bit<32> diff;
            diff = hdr.ctrl.counter_val - val;

            val = diff;
            if(val > ig_md.tolerable_range) {
                rv = 1;
            }
            val = temp;
        }
    };

    RegisterAction<bit<32>, _, void> (sketch2) sketch2_count = {
        void apply(inout bit<32> val) {
            val = val + 1;
        }
    };
    RegisterAction<bit<32>, _, bit<2>> (sketch2) sketch2_read = {
        void apply(inout bit<32> val, out bit<2> rv) {
            rv = 0;

            bit<32> temp;
            temp = val;
            bit<32> diff;
            diff = hdr.ctrl.counter_val - val;

            val = diff;
            if(val > ig_md.tolerable_range) {
                rv = 1;
            }
            val = temp;
        }
    };

    Register<bit<32>,_>(1) tolerable_range;
    RegisterAction<bit<32>, _, bit<32>> (tolerable_range) tolerable_range_read = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
        }
    };

    // Register<pair, _>(1) global_window;
    // RegisterAction<pair, _, bit<32>> (global_window) global_window_update = {
    //     void apply(inout pair val, out bit<32> rv) {
    //         // first, second - wrap_around_constant, global_window_id

    //         bit<32> temp_wrap_constant;
    //         temp_wrap_constant = 0;

    //         bit<32> temp_window_id;
    //         temp_window_id = ig_md.relative_window_id + val.first;

    //         if(temp_window_id < val.second) {
    //             // 10 is window_per_phase
    //             temp_wrap_constant = 10;
    //         }
    //         val.first = val.first + temp_wrap_constant;
    //         val.second = ig_md.relative_window_id + val.first;
    //         // val.second = temp_window_id;
    //         rv = val.second;
    //     }
    // };


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
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    // action getAbsoluteWindowId(bit<32> window_id) {
    //     ig_md.relative_window_id = window_id;
    // }

    // table get_window_id {
    //     key = {     
    //         ig_md.ts : range;
    //     }
    //     actions = {
    //         getAbsoluteWindowId;
    //     }
    // }

    table ipv4_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward;
            NoAction;
        }
        default_action = NoAction();
        // const entries = {
        //     9w0x1 : forward(9w0x2);
        //     9w0x2 : forward(9w0x1);
        // }
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
        // const entries = {
        //     (0, 53, _) : countRequests;
        //     (_, _, 0xAAAA) : markPacket; 
        // }
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
            NoAction;
        }
        default_action = NoAction();
        // const entries = {
        //     1 : markAttack();
        // }
    }
  
    apply {
        // ig_md.ts = (bit<16>) ig_prsr_md.global_tstamp;
        // get_window_id.apply();
        // ig_md.global_window_id = global_window_update.execute(0);
        

        ig_md.tolerable_range = tolerable_range_read.execute(0);
        ipv4_forward.apply();

        // differentiate between requests and responses (with control header)
        mark_packet.apply();
        
        // init val
        ig_md.is_attack = 0; 
        ig_md.exceed = 0; 

        if(ig_md.is_request==1 || ig_md.is_ctrl==1) {
            compute_hash0.apply();
            compute_hash1.apply();
            compute_hash2.apply();
            if(ig_md.is_request == 1) {
                // count requests
                sketch0_count.execute(ig_md.index0);
                sketch1_count.execute(ig_md.index1);
                sketch2_count.execute(ig_md.index2);
            } else {
                // check request counts
                ig_md.exceed = ig_md.exceed + sketch0_read.execute(ig_md.index0);
                ig_md.exceed = ig_md.exceed + sketch1_read.execute(ig_md.index1);
                ig_md.exceed = ig_md.exceed + sketch2_read.execute(ig_md.index2);

                // if all 3 diffs exceed tolerable range
                if(ig_md.exceed == 3) {
                    ig_md.is_attack = 1;
                }

                // confirm the attack and send back to the originating border
                mark_attack.apply();
            }
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
