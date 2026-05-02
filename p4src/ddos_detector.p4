/* ============================================================
   P4M3: SYN Flood Detection — Pure gRPC Implementation
   Three-layer detection: dangerous_table → CMS → ML controller

   Layer 1 (Algorithm 1): dangerous_table — MAC blocklist, instant drop
   Layer 2 (Algorithm 2): Count-Min Sketch threshold, digest to controller
   Layer 3 (Algorithm 3): ML ensemble in controller (controller.py)

   Delivery change vs p4m3_clean:
     clone_preserving_field_list → digest<cpu_digest_t>
     No CPU mirror session, no CPU port, no virtual interface sniffing.
   ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* CMS: 2 hash functions (crc16 + crc32), 1024 columns each */
#define CMS_COLS 1024

/* Threshold: drop SYN flows above this count.
   Benign hosts send 60 packets (below).
   Attackers send 200 packets (threshold hit at packet 101). */
#define THRESHOLD 100

/* ============================================================
   HEADERS
   ============================================================ */

typedef bit<48>  macAddr_t;
typedef bit<128> ip6Addr_t;
typedef bit<16>  port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header tcp_t {
    port_t  srcPort;
    port_t  dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;   /* FIN=bit0, SYN=bit1, RST=bit2, PSH=bit3, ACK=bit4, URG=bit5 */
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* Features sent to controller via P4Runtime digest (no header needed) */
struct cpu_digest_t {
    bit<16>   ingress_port;
    bit<16>   reason;      /* always 1 = SYN below threshold */
    macAddr_t src_mac;     /* used by controller for dangerous_table blocking */
    bit<16>   dst_port;
    bit<32>   cms_count;
}

struct metadata_t {
    bit<32> cms_count;
}

struct headers_t {
    ethernet_t ethernet;
    ipv6_t     ipv6;
    tcp_t      tcp;
}

/* ============================================================
   PARSER
   ============================================================ */

parser MyParser(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x86DD: parse_ipv6;
            default: accept;
        }
    }
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* ============================================================
   INGRESS — Algorithm 1 + Algorithm 2
   ============================================================ */

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t std_meta) {

    register<bit<32>>(CMS_COLS) cms_row0;   /* Hash_CRC16 row */
    register<bit<32>>(CMS_COLS) cms_row1;   /* Hash_CRC32 row */

    action drop_packet() {
        mark_to_drop(std_meta);
    }

    action forward_packet(bit<9> port) {
        std_meta.egress_spec = port;
    }

    /* Algorithm 1: dangerous_table — MAC blocklist
       Controller pushes block rules here after ML detection.
       Checked FIRST on every packet — highest priority. */
    table dangerous_table {
        key = { hdr.ethernet.srcAddr: exact; }
        actions = { drop_packet; NoAction; }
        default_action = NoAction();
        size = 1024;
    }

    /* Basic L2 forwarding — rules installed by controller at startup */
    table l2_forward {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward_packet; drop_packet; NoAction; }
        default_action = NoAction();
        size = 1024;
    }

    apply {
        /* ====================================================
           Algorithm 1: Quick Detection — check dangerous_table first
           ==================================================== */
        if (hdr.ethernet.isValid()) {
            if (dangerous_table.apply().hit) {
                return;
            }
        }

        /* ====================================================
           Algorithm 2: Threshold Detection — IPv6 TCP only
           ==================================================== */
        if (hdr.ipv6.isValid() && hdr.tcp.isValid()) {

            /* SYN = bit 1 of ctrl field */
            if ((hdr.tcp.ctrl & 0x02) != 0) {

                /* Count-Min Sketch: 5-tuple hash
                   Row 0: crc16 (user's hash choice 1)
                   Row 1: crc32 (user's hash choice 2, replaces paper's identity hash) */
                bit<16> h1;
                bit<32> h2_32;
                bit<16> h2;

                hash(h1, HashAlgorithm.crc16, (bit<16>)0,
                     { hdr.ipv6.srcAddr, hdr.ipv6.dstAddr,
                       hdr.tcp.srcPort,  hdr.tcp.dstPort, hdr.ipv6.nextHdr },
                     (bit<16>)CMS_COLS);

                hash(h2_32, HashAlgorithm.crc32, (bit<32>)0,
                     { hdr.ipv6.srcAddr, hdr.ipv6.dstAddr,
                       hdr.tcp.srcPort,  hdr.tcp.dstPort, hdr.ipv6.nextHdr },
                     (bit<32>)CMS_COLS);
                h2 = (bit<16>)h2_32;

                bit<32> c0; bit<32> c1;
                cms_row0.read(c0, (bit<32>)h1);
                cms_row1.read(c1, (bit<32>)h2);
                c0 = c0 + 1;
                c1 = c1 + 1;
                cms_row0.write((bit<32>)h1, c0);
                cms_row1.write((bit<32>)h2, c1);

                /* CMS estimate = minimum (standard CMS property) */
                meta.cms_count = (c0 < c1) ? c0 : c1;

                if (meta.cms_count > THRESHOLD) {
                    /* Above threshold: drop immediately in data plane */
                    mark_to_drop(std_meta);
                } else {
                    /* Below threshold + SYN:
                       Send features to controller via P4Runtime digest (gRPC stream).
                       Original packet continues to destination via l2_forward.
                       digest() is non-blocking — packet forwarding is not delayed. */
                    digest<cpu_digest_t>(1, {
                        (bit<16>)std_meta.ingress_port,
                        16w1,
                        hdr.ethernet.srcAddr,
                        hdr.tcp.dstPort,
                        meta.cms_count
                    });
                    l2_forward.apply();
                }

            } else {
                /* Not SYN — forward normally */
                l2_forward.apply();
            }

        } else if (hdr.ethernet.isValid()) {
            /* Non-IPv6-TCP — forward normally */
            l2_forward.apply();
        }
    }
}

/* ============================================================
   EGRESS — nothing to do (no CPU clone header to add)
   ============================================================ */

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t std_meta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* ============================================================
   DEPARSER
   ============================================================ */

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
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
