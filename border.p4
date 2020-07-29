#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define SUSPICIOUS_THRESHOLD 0x20

struct metadata_t {
    // indexes
    bit<16> index0;
    bit<16> index1;
    bit<16> index2;

    bit<16> bl0index;

    // counts
    bit<16> min_count;
    bit<16> count0;
    bit<16> count1;
    bit<16> count2;

    bit<1> is_response;
    bit<1> is_ctrl;
    bit<1> is_attack;
    bit<1> is_suspicious;
    bit<1> is_bl;
    bit<2> exceed;

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
            ETHERTYPE_IPV4 | ETHERTYPE_CTRL : parse_ipv4;
            default : accept;
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
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_one;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_two;

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_bl0_one;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_bl0_two;

    Register<pair,_>(32w65536) sketch0;
    Register<pair,_>(32w65536) sketch1;
    Register<pair,_>(32w65536) sketch2;

    RegisterAction<pair, _, bit<16>> (sketch0) sketch0_count = {
        void apply(inout pair val, out bit<16> rv) {
            bit<16> temp;

            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            temp = ig_md.min_count - val.first;
            rv = temp;            
        }
    };

    RegisterAction<pair, _, bit<16>> (sketch1) sketch1_count = {
        void apply(inout pair val, out bit<16> rv) {
            bit<16> temp;

            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            temp = ig_md.min_count - val.first;
            rv = temp;            
        }
    };

    RegisterAction<pair, _, bit<16>> (sketch2) sketch2_count = {
        void apply(inout pair val, out bit<16> rv) {
            bit<16> temp;

            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            temp = ig_md.min_count - val.first;
            rv = temp;            
        }
    };

    Register<bit<32>,_>(1) bl0;
    RegisterAction<bit<32>, _, bit<1>> (bl0) bl0_read = {
        void apply(inout bit<32> val, out bit<1> rv) {
            rv = 0;
            if(hdr.ipv4.src_addr == val) {
                rv = 1;
            }
        }
    };
    RegisterAction<bit<32>, _, void> (bl0) bl0_write = {
        void apply(inout bit<32> val) {
            val = hdr.ipv4.src_addr;
        }
    };

    action hash_bl0_ctrl() {
        ig_md.bl0index = hash_bl0_one.get(
            {
                hdr.ipv4.src_addr
            }
        );
    }
    action hash_bl0_res() {
        ig_md.bl0index = hash_bl0_two.get(
            {
                hdr.ipv4.src_addr
            }
        );
    }

    action hash0_res() {
        ig_md.index0 = hash_zero.get(
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

    action hash1_res() {
        ig_md.index1 = hash_one.get(
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

    action hash2_res() {
        ig_md.index2 = hash_two.get(
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

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;    // drop packet
    }

    action forward(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action countResponses() {
        ig_md.is_response = 1;
    }

    action markPacket() {
        ig_md.is_ctrl = 1;
    }
    
    action markSuspicious() {
        hdr.ctrl.setValid();
        hdr.ctrl.flag = 0xFFFF; // send this to access
        hdr.ctrl.counter_val = ig_md.min_count;
        hdr.ctrl.tstamp_val = ig_md.current_tstamp;
        hdr.ctrl.source_rtr_id = 32w0xc0a80101; // router id is hard coded for now
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
            hdr.udp.src_port : exact;
            hdr.ctrl.flag : exact;
        }
        actions = {
            NoAction;
            countResponses;
            markPacket;
        }
        default_action = NoAction;
    }

    table mark_suspicious {
        key = {
            // ig_md.is_suspicious : exact;
            ig_md.count0 : range;
            ig_md.count1 : range;
            ig_md.count2 : range;
        }
        actions = {
            markSuspicious;
            NoAction;
        }
        default_action = NoAction();
        // if all three falls in the range, then it will trigger the mark suspicious function
    }

    table filter_traffic {
        key = {
            ig_md.is_bl : exact;
            hdr.udp.src_port : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
    }
  
    apply {
        ig_md.current_tstamp = ig_intr_md.ingress_mac_tstamp[47:32];
        ipv4_forward.apply();

        // differentiate between responses and notifications (ctrl)
        mark_packet.apply();

        // init val
        ig_md.is_suspicious = 0; 
        ig_md.exceed = 0; 

        if(ig_md.is_response == 1 || ig_md.is_ctrl == 1) {
            if(ig_md.is_response ==1) { // response packets
                hash0_res();
                hash1_res();
                hash2_res();

                // bit<12> temp0;
                // bit<12> temp1;
                // bit<12> temp2;

                // temp0 = (bit<12>) sketch0_count.execute(ig_md.index0);
                // if(temp0 > SUSPICIOUS_THRESHOLD) {
                //     ig_md.exceed = ig_md.exceed + 1; 
                // }

                // temp1 = (bit<12>) sketch1_count.execute(ig_md.index1);
                // if(temp1 > SUSPICIOUS_THRESHOLD) {
                //     ig_md.exceed = ig_md.exceed + 1; 
                // }

                // temp2 = (bit<12>) sketch2_count.execute(ig_md.index2);
                // if(temp2 > SUSPICIOUS_THRESHOLD) {
                //     ig_md.exceed = ig_md.exceed + 1; 
                // }

                // if(ig_md.exceed == 3) {
                //     ig_md.is_suspicious = 1;
                // }
                ig_md.count0 = sketch0_count.execute(ig_md.index0);
                ig_md.count1 = sketch1_count.execute(ig_md.index1);
                ig_md.count2 = sketch2_count.execute(ig_md.index2);
                mark_suspicious.apply();
            } else { // notification header
                hash_bl0_ctrl(); // hash the source addr
                bl0_write.execute(ig_md.bl0index); // write into BL
                drop();
            }
        } else { // normal traffic
            hash_bl0_res(); // hash the source addr
            ig_md.is_bl = bl0_read.execute(ig_md.bl0index);
            filter_traffic.apply();
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
