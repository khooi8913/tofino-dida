####### PTF MODULE IMPORTS ########
import ptf
from ptf.testutils import *
####### PTF modules for BFRuntime Client Library APIs #######
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest
######## PTF modules for Fixed APIs (Thrift) ######
import pd_base_tests
from ptf.thriftutils import *
from res_pd_rpc import * # Common data types
from mc_pd_rpc import * # Multicast-specific data types
from mirror_pd_rpc import * # Mirror-specific data types
####### Additional imports ########
import pdb # To debug insert pdb.set_trace() anywhere

class AioTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "aio"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # Connect to the program, running on the target
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # Make table 'shortcut'
        self.ipv4_forward = self.bfrt_info.table_get("Ingress.ipv4_forward")
        self.ipv4_forward.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

        self.tables = [self.ipv4_forward]

    def runTest(self):
        key = self.ipv4_forward.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', "192.168.1.1")])
        data = self.ipv4_forward.make_data([gc.DataTuple('port', 1)], "Ingress.forward")

        self.ipv4_forward.entry_add(self.dev_tgt, [key], [data])
        print("Added an entry to ipv4_forward: {} --> send({})".format("192.168.1.1", 1))

        # Create a test packet
        # pkt = simple_tcp_packet(pktlen=86, ip_dst="192.168.1.1", ip_ihl=5, with_tcp_chksum=True)
        # pkt[IP].chksum = 63566
        # pkt[TCP].dataofs = 5L
        pkt = simple_ip_packet(pktlen=86, ip_dst="192.168.1.1", ip_ihl=5)
        # pkt = simple_icmp_packet(ip_dst="192.168.1.1")
        pkt[IP].chksum = 63586
        pkt[IP].len = 72
        send_packet(self, 13, pkt)

        expected_pkt = copy.deepcopy(pkt)
        expected_pkt[IP].ttl = pkt[IP].ttl - 1

        print("Expecting the packet on port {}".format(1))

        verify_packet(self, expected_pkt, 1, timeout=2)
        print("Packet received on port {}".format(1))


    def cleanUp(self):
        try:
            for t in self.tables:
                keys = []
            for (d, k) in t.entry_get(self.dev_tgt):
                if k is not None:
                    keys.append(k)
            
            t.entry_del(self.dev_tgt, keys)
            try:
                t.defaylt_entry_reset(self.dev_tgt)
            except:
                pass
            print("Tables cleaned up!")
        except Exception as e:
            print("Error cleaning up: {}".format(e))

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)