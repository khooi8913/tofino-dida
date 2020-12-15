import sys
import os

sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))

import grpc
import time
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

# Connect to BfRt Server
interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0,is_master=True)
target = gc.Target(device_id=0, pipe_id=0xFFFF)
print('Connected to BfRt Server!')

# Get the information about the running program
bfrt_info = interface.bfrt_info_get()
print('The target is running the', bfrt_info.p4_name_get())

# Establish that you are working with this program
interface.bind_pipeline_config(bfrt_info.p4_name_get())


### You can now use BFRT CLIENT ###
# count_mac
count_mac = bfrt_info.table_get('Ingress.count_mac')
mac_addrs = ["22:22:22:00:00:01", "00:00:00:00:00:01"]
keys = []
data = []
for mac_addr in mac_addrs:
    keys.append(count_mac.make_key([gc.KeyTuple('hdr.ethernet.src_addr', gc.mac_to_bytes(mac_addr))]))
    data.append(count_mac.make_data([], 'Ingress.just_count'))
count_mac.entry_add(target, keys, data)

# ipv4_forward
ipv4_forward = bfrt_info.table_get('Ingress.ipv4_forward')
key = ipv4_forward.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes('10.0.0.2'))])
data = ipv4_forward.make_data([gc.DataTuple('port', 0)], 'Ingress.forward')
ipv4_forward.entry_add(target, [key], [data])

# mark_traffic
mark_traffic = bfrt_info.table_get('Ingress.mark_traffic')
key = mark_traffic.make_key([gc.KeyTuple('hdr.ipv4.frag_offset', 0), \
    gc.KeyTuple('hdr.ipv4.protocol', 17), \
        gc.KeyTuple('meta.lookup_0', 0), \
            gc.KeyTuple('meta.lookup_1', 0), \
                gc.KeyTuple('meta.src_port', value=0x35, mask=0xff), \
                        gc.KeyTuple('meta.dst_port', value=0x00, mask=0x00)]) 
data = mark_traffic.make_data([], 'Ingress.count_response')
mark_traffic.entry_add(target, [key], [data])

# threshold
threshold = bfrt_info.table_get('Ingress.threshold')
key = threshold.make_key([gc.KeyTuple('count', low=0x0a, high=0xFFFF)]) 
data = threshold.make_data([], 'Ingress.notify_cpu')
threshold.entry_add(target, [key], [data])

# # except:
#     # print("An error has occurred")

# l2_digest = bfrt_info.learn_get("IngressDeparser.l2_digest")
# print(dir(l2_digest.reader_writer_interface))

############## FINALLY #############


# SDE-9.2.0 workaround
interface._tear_down_stream()

####################################

# def table_add(target, table, keys, action, action_data=[]):
#     keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
#     datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
#                                   action)]
#     table.entry_add(target, keys, datas)

# def table_clear(target, table):
#     keys = []
#     for data,key in table.entry_get(target):
#         if key is not None:
#             keys.append(key)
#     table.entry_del(target, keys)

# def fill_table_with_junk(target, table, table_size):
#     table_clear(target, table)
#     for i in range(table_size):
#         table_add(target, table,
#                   [("hdr.ethernet.dst_addr", i)],
#                   "hit")
    
# try:
#     grpc_addr = "localhost:50052"
#     client_id = 0
#     device_id = 0
#     pipe_id = 0xFFFF
    
#     client = gc.ClientInterface(grpc_addr, client_id, device_id)
#     target = gc.Target(device_id, pipe_id)
#     client.bind_pipeline_config("tna_exact_match")
    
#     table = client.bfrt_info_get().table_get("pipe.SwitchIngress.forward_timeout")

#     table_sizes = [1,10,100,1000,10000]

#     results = []
#     n_iters = 5
#     print("num_table_entries,duration")
#     for table_size in table_sizes:
#         fill_table_with_junk(target, table, table_size)

#         for _ in range(n_iters):
#             start = time.time()
#             val = list(table.entry_get(target, []))
#             end = time.time()
#             print("%d,%f"%(table_size, end - start))
# finally:
#     client._tear_down_stream()

# p4 = bfrt.aio.pipe
# def is_attack_callback(dev_id, pipe_id, direction, parser_id, session, msg):
#     global p4
#     with open('/tmp/output.txt', 'a+') as f:
#         f.write(str(msg))
#     return 0