/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_CPU = 16w0x8888;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_TCP = 6;
const ip_proto_t IP_PROTO_UDP = 17;

typedef bit<16> count_t;
typedef bit<16> window_t;
struct reg_pair {
    count_t   count;
    window_t    window;
}

const bit<3> AR_ATTACK_DIGEST = 0x03;
struct l2_digest_t {
    ipv4_addr_t src_addr;
    l4_port_t src_port;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    ip_proto_t   protocol;
    bit<16>  hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header tcp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    // bit<8> flag;
    bit<1> cwr;    
    bit<1> ece;    
    bit<1> urg;    
    bit<1> ack;    
    bit<1> psh;    
    bit<1> rst;    
    bit<1> syn;    
    bit<1> fin;    
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h  ipv4;
    tcp_h   tcp;
    udp_h   udp;
    // cpu_h   cpu;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<1>   lookup_0;
    bit<1>   lookup_1;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.src_port = 0;
        meta.dst_port = 0;
        meta.lookup_0 = 0;
        meta.lookup_1 = 0;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            IP_PROTO_UDP    : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        meta.lookup_0 = hdr.tcp.syn;
        meta.lookup_1 = hdr.tcp.ack;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    window_t    curr_ts = 0;
    ipv4_addr_t ft_0 = 0;
    ipv4_addr_t ft_1 = 0;
    ip_proto_t  ft_2 = 0;
    l4_port_t   ft_3 = 0;
    l4_port_t   ft_4 = 0;
    bool        is_request = false;
    bit<32>     index = 0;
    count_t     count = 0;
    count_t     count_r0 = 0;
    count_t     count_r1 = 0;

    DirectCounter<bit<32>>(CounterType_t.PACKETS) pkt_ctr;

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_index;
    Register<reg_pair,_>(32768) sketch0;
    Register<reg_pair,_>(32768) sketch1;
    RegisterAction<reg_pair, _, count_t> (sketch0) sketch0_req = {
        void apply(inout reg_pair val, out count_t rv) {
            if(curr_ts != val.window) {
                val.count = 0;
            } else {
                val.count = val.count |-| 1;
            }
            val.window = curr_ts;
            rv = val.count;
        }
    };
    RegisterAction<reg_pair, _, count_t> (sketch0) sketch0_res = {
        void apply(inout reg_pair val, out count_t rv) {
            if(curr_ts != val.window) {
                val.count = 1;
            } else {
                val.count = val.count |+| 1;
            }
            val.window = curr_ts;
            rv = val.count;
        }
    };
    RegisterAction<reg_pair, _, count_t> (sketch1) sketch1_req = {
        void apply(inout reg_pair val, out count_t rv) {
            if(curr_ts != val.window) {
                val.count = 0;
            } else {
                val.count = val.count |-| 1;
            }
            val.window = curr_ts;
            rv = val.count;
        }
    };
    RegisterAction<reg_pair, _, count_t> (sketch1) sketch1_res = {
        void apply(inout reg_pair val, out count_t rv) {
            if(curr_ts != val.window) {
                val.count = 1;
            } else {
                val.count = val.count |+| 1;
            }
            val.window = curr_ts;
            rv = val.count;
        }
    };

    action notify_cpu(){
        ig_dprsr_md.digest_type = AR_ATTACK_DIGEST;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x0;    // drop packet
        exit;
    }

    table acl {
        key = {
            hdr.ipv4.src_addr : exact;
            meta.src_port : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 16384;
    }

    action just_count() {
        pkt_ctr.count();
    }

    table count_mac {
        key = {
            hdr.ethernet.src_addr : exact;
        }
        actions = {
            just_count;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        counters = pkt_ctr;
        size = 1024;
    }

    action forward(PortId_t port) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1; 
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
        size = 32;
    }

    action count_request() {
        is_request = true;
    }

    action count_response() {
        is_request = false;
    }

    table mark_traffic {
        key = {
            hdr.ipv4.frag_offset : exact;
            hdr.ipv4.protocol : exact;
            meta.lookup_0 : exact;
            meta.lookup_1 : exact;
            meta.src_port : ternary;
            meta.dst_port : ternary;
        }
        actions = {
            NoAction;
            count_request;
            count_response;
        }
        default_action = NoAction();
        size = 32;
    }

    table threshold {
        key = {
            count : range;
        }
        actions = {
            notify_cpu;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    apply {
        curr_ts = (window_t) ig_intr_md.ingress_mac_tstamp[47:32];
        if(hdr.ipv4.isValid()) {
            ft_0 = min(hdr.ipv4.src_addr, hdr.ipv4.dst_addr);
            ft_1 = max(hdr.ipv4.src_addr, hdr.ipv4.dst_addr);
            ft_2 = hdr.ipv4.protocol;
            ft_3 = min(meta.src_port, meta.dst_port);
            ft_4 = max(meta.src_port, meta.dst_port);

            index = hash_index.get(
                {
                    ft_0,
                    ft_1,
                    ft_2,
                    ft_3,
                    ft_4
                }
            );

            acl.apply();
            count_mac.apply();
            ipv4_forward.apply();
            if(mark_traffic.apply().hit) {
                if (is_request) {
                    count_r0 = sketch0_req.execute((bit<16>)index[30:16]);
                    count_r1 = sketch1_req.execute((bit<16>)index[14:0]);    
                } else {    // response
                    count_r0 = sketch0_res.execute((bit<16>)index[30:16]);
                    count_r1 = sketch1_res.execute((bit<16>)index[14:0]);
                    count = min(count_r0, count_r1);
                    // count = count_r0;
                    threshold.apply();
                }
            }
        }
        
        // we do not need egress processing for now
        ig_tm_md.bypass_egress = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Digest <l2_digest_t>() l2_digest;

    apply {
        if(ig_dprsr_md.digest_type == AR_ATTACK_DIGEST) {
            l2_digest.pack({hdr.ipv4.src_addr, meta.src_port});
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
