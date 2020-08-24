#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define TOLERABLE_RANGE 0x20

struct metadata_t {
    // indexes
    bit<16> index0;
    bit<16> index1;
    bit<16> index2;

    bit<16> count0;
    bit<16> count1;
    bit<16> count2;

    bit<1> is_request;
    bit<1> is_response;

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
    
    Register<pair,_>(32768) sketch0;
    Register<pair,_>(32768) sketch1;
    Register<pair,_>(32768) sketch2;

    RegisterAction<pair, bit<16>, void> (sketch0) sketch0_req = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }

            if(val.first != 0){
                val.first = val.first - 1;
            }            
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch0) sketch0_resp = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }

            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch1) sketch1_req = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }

            if(val.first != 0){
                val.first = val.first - 1;
            }            
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch1) sketch1_resp = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }

            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch2) sketch2_req = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }

            if(val.first != 0){
                val.first = val.first - 1;
            }            
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, bit<16>> (sketch2) sketch2_resp = {
        void apply(inout pair val, out bit<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }

            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;
        }
    };

    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row2;

    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row2;

    // Hash
    action hash0_req() {
        ig_md.index0 = hash_req_row0.get(
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

    // If is request
    action hash1_req() {
        ig_md.index1 = hash_req_row1.get(
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

    action hash2_req() {
        ig_md.index2 = hash_req_row2.get(
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

    // If is response
    action hash0_resp() {
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

    action hash1_resp() {
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

    action hash2_resp() {
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

    action drop() {
        ig_dprsr_md.drop_ctl = 0x0;    // drop packet
    }

    action send_to_cpu(){
        ig_tm_md.ucast_egress_port = 192; // send to cpu
    }
    
    action dont_send_to_cpu(){
        hdr.cpu.setInvalid();
    }

    action forward(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action countRequests() {
        ig_md.is_request = 1;
    }   
    action countResponses() {
        ig_md.is_response = 1;
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

    table mark_traffic {
         key = {
            hdr.ipv4.frag_offset : exact;
            hdr.udp.dst_port : ternary;
            hdr.udp.src_port : ternary;
        }
        actions = {
            NoAction;
            countRequests;
            countResponses;
        }
        default_action = NoAction();
        const entries = {
            (0, 53, _) :  countRequests();
            (0, _, 53) :  countResponses();
        }
    }

    table threshold {
        key = {
            hdr.cpu.count0 : range;
            hdr.cpu.count1 : range;
            hdr.cpu.count2 : range;
        }
        actions = {
            send_to_cpu;
            dont_send_to_cpu;
        }
        default_action = dont_send_to_cpu();

        // if all three counts fall within the range, then it is an attack
        const entries = {
            (0x20 .. 0xFFFF, 0x20 .. 0xFFFF, 0x20 .. 0xFFFF) : send_to_cpu();
        }
    }
  
    apply {
        ig_md.current_tstamp = (bit<16>)ig_intr_md.ingress_mac_tstamp[47:32];
        ipv4_forward.apply();
        mark_traffic.apply();
        
        if(ig_md.is_response == 1){
             // hash the responses
            hash0_resp();
            hash1_resp();
            hash2_resp();
            
            @stage(2){
                // increment the counts
                hdr.cpu.count0 = sketch0_resp.execute(ig_md.index0);
                hdr.cpu.count1 = sketch1_resp.execute(ig_md.index1);
                hdr.cpu.count2 = sketch2_resp.execute(ig_md.index2);
            }
            
            // check attack
            threshold.apply();

        } else if(ig_md.is_request == 1){
            // hash the requests
            hash0_req();
            hash1_req();
            hash2_req();
            
            @stage(2){
                // decrement the counts
                sketch0_req.execute(ig_md.index0); 
                sketch1_req.execute(ig_md.index1); 
                sketch2_req.execute(ig_md.index2); 
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
