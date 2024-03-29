from bfrtcli import *

dg = bfrt.aio.pipe.IngressDeparser.l2_digest

# def cb(dev_id, pipe_id, direction, parser_id, session, msg):
#     for d in msg:
#         with open('/tmp/output.txt', 'a+') as f:
#             f.write(str(d) + '\n')
#     return 0
# dg.callback_register(cb)

def acl_callback(dev_id, pipe_id, direction, parser_id, sess, msg):
    for d in msg:
        src_addr = d['src_addr']
        src_port = d['src_port']
        try:
            bfrt.aio.pipe.Ingress.acl.add_with_drop(src_addr=src_addr, src_port=src_port)
        except:
            pass
    return 0

try:
    dg.callback_deregister()
except:
    dg.callback_register(acl_callback)

