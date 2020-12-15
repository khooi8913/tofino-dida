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

# Establish taht you are working with this program
interface.bind_pipeline_config(bfrt_info.p4_name_get())

# Clear all tables
interface.clear_all_tables()

############## FINALLY #############
# SDE-9.2.0 workaround
interface._tear_down_stream()

####################################