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
    bit<16> index3;
    bit<16> index4;
    bit<16> index5;

    int<16> min_count_req;
    int<16> min_count_resp;
    int<16> min_count_diff;

    int<16> count0;
    int<16> count1;
    int<16> count2;

    int<16> count3;
    int<16> count4;
    int<16> count5;

    // diffs
    int<16> diff0;
    int<16> diff1;
    int<16> diff2;
    int<16> diff3;
    int<16> diff4;
    int<16> diff5;

    bit<1> cmp0;
    bit<1> cmp1;
    bit<1> cmp2;
    bit<1> cmp3;
    bit<1> cmp4;
    bit<1> cmp5;
    bit<1> cmp_threshold;

    bit<1> is_request;
    bit<1> is_response;

    int<16> current_tstamp;
}

struct pair {
    int<16>     first;
    int<16>     second;
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
    
    // Requests
    Register<pair,_>(32768) sketch0req;
    Register<pair,_>(32768) sketch1req;
    Register<pair,_>(32768) sketch2req;

    RegisterAction<pair, bit<16>, void> (sketch0req) sketch0req_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, int<16>> (sketch0req) sketch0req_read = {
        void apply(inout pair val, out int<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            rv = val.first;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch1req) sketch1req_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, int<16>> (sketch1req) sketch1req_read = {
        void apply(inout pair val, out int<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            rv = val.first;
        }
    };

    RegisterAction<pair, bit<16>, void> (sketch2req) sketch2req_count = {
        void apply(inout pair val) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;
        }
    };
    RegisterAction<pair, bit<16>, int<16>> (sketch2req) sketch2req_read = {
        void apply(inout pair val, out int<16> rv) {
            rv = 0;

            if(ig_md.current_tstamp >= val.second -1) {
                val.first = 0;
            }
            val.second = ig_md.current_tstamp;
            rv = val.first;
        }
    };
    
    // Responses
    Register<pair,_>(32768) sketch0resp;
    Register<pair,_>(32768) sketch1resp;
    Register<pair,_>(32768) sketch2resp;

    RegisterAction<pair, _, int<16>> (sketch0resp) sketch0resp_count = {
        void apply(inout pair val, out int<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    RegisterAction<pair, _, int<16>> (sketch1resp) sketch1resp_count = {
        void apply(inout pair val, out int<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    RegisterAction<pair, _, int<16>> (sketch2resp) sketch2resp_count = {
        void apply(inout pair val, out int<16> rv) {
            if(ig_md.current_tstamp != val.second) {
                val.first = 0;
            }
            val.first = val.first + 1;
            val.second = ig_md.current_tstamp;

            rv = val.first;     
        }
    };

    // Comparators
    Register<int<16>,_>(1) min0;
    RegisterAction<int<16>, _, bit<1>> (min0) min0_get = {
        void apply(inout int<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff0 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) min1;
    RegisterAction<bit<16>, _, bit<1>> (min1) min1_get = {
        void apply(inout bit<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff1 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) min2;
    RegisterAction<int<16>, _, bit<1>> (min2) min2_get = {
        void apply(inout int<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff2 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) min3;
    RegisterAction<int<16>, _, bit<1>> (min3) min3_get = {
        void apply(inout int<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff0 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) min4;
    RegisterAction<bit<16>, _, bit<1>> (min4) min4_get = {
        void apply(inout bit<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff1 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) min5;
    RegisterAction<int<16>, _, bit<1>> (min5) min5_get = {
        void apply(inout int<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.diff2 > 0){
                rv = 1;
            }
        }
    };

    Register<int<16>,_>(1) threshold;
    RegisterAction<int<16>, _, bit<1>> (threshold) threshold_check = {
        void apply(inout int<16> val, out bit<1> rv) {
            rv = 0;
            if(ig_md.min_count_diff > TOLERABLE_RANGE){
                rv = 1;
            }
        }
    };


    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_req_row2;

    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row0;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row2;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row3;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row4;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_resp_row5;

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

    action hash3_resp_req() {
        ig_md.index3 = hash_resp_row3.get(
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

    action hash4_resp_req() {
        ig_md.index4 = hash_resp_row4.get(
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

    action hash5_resp_req() {
        ig_md.index5 = hash_resp_row5.get(
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
  
    apply {
        ig_md.current_tstamp = (int<16>)ig_intr_md.ingress_mac_tstamp[47:32];
        ipv4_forward.apply();
        mark_traffic.apply();
        
        if(ig_md.is_response == 1){
             // hash the responses
            hash0_resp();
            hash1_resp();
            hash2_resp();
            ig_md.count0 = sketch0resp_count.execute(ig_md.index0);
            ig_md.count1 = sketch1resp_count.execute(ig_md.index1);
            ig_md.count2 = sketch2resp_count.execute(ig_md.index2);

            // find the responses' corresponding request counts
            hash3_resp_req();
            hash4_resp_req();
            hash5_resp_req();
            ig_md.count3 = sketch0req_read.execute(ig_md.index3);
            ig_md.count4 = sketch1req_read.execute(ig_md.index4);
            ig_md.count5 = sketch2req_read.execute(ig_md.index5);
           
            ig_md.diff0 = ig_md.count1 - ig_md.count0;
            ig_md.diff1 = ig_md.count2 - ig_md.count1;
            ig_md.diff2 = ig_md.count2 - ig_md.count0;

            ig_md.diff3 = ig_md.count4 - ig_md.count3;
            ig_md.diff4 = ig_md.count5 - ig_md.count4;
            ig_md.diff5 = ig_md.count5 - ig_md.count3;
            
            ig_md.cmp0 = min0_get.execute(0);
            ig_md.cmp1 = min1_get.execute(0);
            ig_md.cmp2 = min2_get.execute(0);

            ig_md.cmp3 = min3_get.execute(0);
            ig_md.cmp4 = min4_get.execute(0);
            ig_md.cmp5 = min5_get.execute(0);

            if(ig_md.cmp0 == 1 && ig_md.cmp2 == 1){
                ig_md.min_count_resp = ig_md.count0;
            } else if(ig_md.cmp0 == 0 && ig_md.cmp2 == 1){
                ig_md.min_count_resp = ig_md.count1;
            }else {
                ig_md.min_count_resp = ig_md.count2;
            }

            if(ig_md.cmp3 == 1 && ig_md.cmp5 == 1){
                ig_md.min_count_req = ig_md.count3;
            } else if(ig_md.cmp3 == 0 && ig_md.cmp5 == 1){
                ig_md.min_count_req = ig_md.count4;
            }else {
                ig_md.min_count_req = ig_md.count5;
            }

            ig_md.min_count_diff = ig_md.min_count_resp - ig_md.min_count_req;
            ig_md.cmp_threshold = threshold_check.execute(0);
            if(ig_md.cmp_threshold == 1){
                // it is an attack!
                send_to_cpu();
            }
        } else if(ig_md.is_request == 1){
            // hash the requests
            hash0_req();
            hash1_req();
            hash2_req();
            sketch0req_count.execute(ig_md.index0); 
            sketch1req_count.execute(ig_md.index1); 
            sketch2req_count.execute(ig_md.index2); 
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
