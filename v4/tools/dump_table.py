import sys
import os
import struct
import socket

sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))

import grpc
import time
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

# Connect to BfRt Server
interface = gc.ClientInterface(grpc_addr=sys.argv[1], client_id=3, device_id=0,is_master=False)
target = gc.Target(device_id=0, pipe_id=0xFFFF)
print('Connected to BfRt Server!')

# Get the information about the running program
bfrt_info = interface.bfrt_info_get()
print('The target is running the', bfrt_info.p4_name_get())

# Establish that you are working with this program
interface.bind_pipeline_config(bfrt_info.p4_name_get())

### You can now use BFRT CLIENT ###
acl = bfrt_info.table_get('pipe.Ingress.acl')
start = time.time()
# help(acl.entry_get)
# print(dir(acl.entry_get(target, [], {'from_hw': True})))

entries = list(acl.entry_get(target, []))
end = time.time()
print(end-start)
ips = []
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# for entry in entries:
#     key = entry[1].to_dict()
#     action = entry[0].to_dict()

#     if not action['is_default_entry']:
#         ips.append(int2ip(key['hdr.ipv4.src_addr']['value']))

# with open('/tmp/ips.txt', 'w+') as f:
#     for ip in ips:
#         f.write(ip + '\n')
############## FINALLY #############
# SDE-9.2.0 workaround
interface._tear_down_stream()

####################################