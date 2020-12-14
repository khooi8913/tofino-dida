import sys
import os
sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))
import grpc
import time
import bfrt_grpc.client as gc

def table_add(target, table, keys, action, action_data=[]):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
                                  action)]
    table.entry_add(target, keys, datas)

def table_clear(target, table):
    keys = []
    for data,key in table.entry_get(target):
        if key is not None:
            keys.append(key)
    table.entry_del(target, keys)

def fill_table_with_junk(target, table, table_size):
    table_clear(target, table)
    for i in range(table_size):
        table_add(target, table,
                  [("hdr.ethernet.dst_addr", i)],
                  "hit")
    
try:
    grpc_addr = "localhost:50052"
    client_id = 0
    device_id = 0
    pipe_id = 0xFFFF
    
    client = gc.ClientInterface(grpc_addr, client_id, device_id)
    target = gc.Target(device_id, pipe_id)
    client.bind_pipeline_config("tna_exact_match")
    
    table = client.bfrt_info_get().table_get("pipe.SwitchIngress.forward_timeout")

    table_sizes = [1,10,100,1000,10000]

    results = []
    n_iters = 5
    print("num_table_entries,duration")
    for table_size in table_sizes:
        fill_table_with_junk(target, table, table_size)

        for _ in range(n_iters):
            start = time.time()
            val = list(table.entry_get(target, []))
            end = time.time()
            print("%d,%f"%(table_size, end - start))
finally:
    client._tear_down_stream()