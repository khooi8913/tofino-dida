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

