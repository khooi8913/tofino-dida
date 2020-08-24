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
    bit<16> bl0index;

    // counts
    bit<16> min_count;
    bit<16> suspicious_count;
    bit<16> count0;
    bit<16> count1;
    bit<16> count2;

    bit<1> is_response;
    bit<1> is_bl;

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
    
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_resp_row0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row1;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_resp_row2;

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) hash_bl0;

    Register<pair,_>(32768) sketch0;
    Register<pair,_>(32768) sketch1;
    Register<pair,_>(32768) sketch2;

    RegisterAction<pair, _, bit<16>> (sketch0) sketch0_count = {
        void apply(inout pair val, out bit<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    RegisterAction<pair, _, bit<16>> (sketch1) sketch1_count = {
        void apply(inout pair val, out bit<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    RegisterAction<pair, _, bit<16>> (sketch2) sketch2_count = {
        void apply(inout pair val, out bit<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    Register<bit<32>,_>(32w65536) bl0;
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

    Register<bit<16>,_>(1) threshold;
    RegisterAction<bit<16>, _, bit<16>> (threshold) threshold_get = {
        void apply(inout bit<16> val, out bit<16> rv) {
            rv = val;
        }
    };

    action hash_src_addr() {
        ig_md.bl0index = hash_bl0.get(
            {
                hdr.ipv4.src_addr
            }
        );
    }

    action hash0_res() {
        ig_md.index0 = hash_resp_row0.get(
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
        ig_md.index1 = hash_resp_row1.get(
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
        ig_md.index2 = hash_resp_row2.get(
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

    action blDrop() {
        ig_dprsr_md.drop_ctl = 0x1;    // drop packet
        exit;
    }

    action forward(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action countResponses() {
        ig_md.is_response = 1;
    }
    
    action markSuspicious() {
        hdr.ctrl.setValid();
        hdr.ctrl.counter_val = threshold_get.execute(0); 
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

    table mark_suspicious {
         key = {
            ig_md.count0 : range;
            ig_md.count1 : range;
            ig_md.count2 : range;
        }
        actions = {
            markSuspicious;
            NoAction;
        }
        default_action = markSuspicious();

        // if all three counts fall within the range, then it is an attack
        const entries = {
            (0x20 .. 0xFFFF, 0x20 .. 0xFFFF, 0x20 .. 0xFFFF) : markSuspicious();
        }
    }

    table filter_traffic {
        key = {
            ig_md.is_bl : exact;
            hdr.udp.src_port : exact;
        }
        actions = {
            blDrop;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (1, 53) : blDrop();
        }
    }

    table count_responses {
        key = {
            hdr.ipv4.frag_offset : exact;
            hdr.udp.src_port : exact;
        }
        actions = {
            NoAction;
            countResponses;
        }
        default_action = NoAction;
    }
  
    apply {
        ig_md.current_tstamp = (bit<16>) ig_intr_md.ingress_mac_tstamp[47:32];
        ipv4_forward.apply();

        hash_src_addr(); // hash the source addr
        
        if(!hdr.ctrl.isValid()){
            // normal traffic
            count_responses.apply();
            if(ig_md.is_response == 1){
                // drop malicious traffic
                ig_md.is_bl = bl0_read.execute(ig_md.bl0index);
                filter_traffic.apply();

                // for non-malicious traffic
                hash0_res();
                hash1_res();
                hash2_res();

                ig_md.count0 = sketch0_count.execute(ig_md.index0);
                ig_md.count1 = sketch1_count.execute(ig_md.index1);
                ig_md.count2 = sketch2_count.execute(ig_md.index2);
                mark_suspicious.apply();
            }
        } else {
            // notification from access 
            bl0_write.execute(ig_md.bl0index); 
            blDrop();
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
