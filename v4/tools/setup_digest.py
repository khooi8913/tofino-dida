dg = bfrt.aio.pipe.IngressDeparser.l2_digest

try:
    dg.callback_deregister()
except:
    pass

def cb(dev_id, pipe_id, direction, parser_id, session, msg):
    for d in msg:
        with open('/tmp/output.txt', 'a+') as f:
            f.write(str(d) + '\n')
    return 0
dg.callback_register(cb)


def ccb(dev_id, pipe_id, direction, parser_id, sess, msg):
    global acl
    for d in msg:
        src_addr = d['src_addr']
        src_port = d['src_port']
        try:
            bfrt.aio.pipe.Ingress.acl.add_with_drop(src_addr=src_addr, src_port=src_port)
        except:
            pass
    return 0
    
