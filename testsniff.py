#!/usr/bin/env python

import getopt, sys
try:
    import dpkt
except ImportError as exc:
    if exc.args[0] == 'No module named test' or 'pystone' in exc.args[0]:
        msg =('The package `dpkt` has a dependency on the python standard '
              'library `test` module. The test package is meant for internal ' 
              'use by Python only, and is stripped from many third party '
              'pre-packaged interpreters. '
              '\Recomendation: Install the `test` package manually. '
              'It may be downloaded here: '
              'https://github.com/python/cpython/tree/master/Lib/test',)
        exc.args += msg
        print(exc)
        # This is a hack to avoid the pystones dependancy
        sys.modules['test'] = types.ModuleType('test')
        sys.modules['test'].pystone = None
        import dpkt
        del sys.modules['test']
    else:
        raise exc
import pcap

def usage():
    print >>sys.stderr, 'usage: %s [-i device] [pattern]' % sys.argv[0]
    sys.exit(1)

def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:h')
    name = None
    for o, a in opts:
        if o == '-i': name = a
        else: usage()
        
    pc = pcap.pcap(name)
    pc.setfilter(' '.join(args))
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
    try:
        print 'listening on %s: %s' % (pc.name, pc.filter)
        for ts, pkt in pc:
            print ts, `decode(pkt)`
    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop

if __name__ == '__main__':
    main()
