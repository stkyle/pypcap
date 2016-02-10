# -*- coding: utf-8 -*-
"""
libpcap for Windows (WinPcap)
Reference: https://www.winpcap.org
"""

import ctypes
from ctypes import POINTER

wpcap = ctypes.windll.wpcap
ws2_32 = ctypes.windll.ws2_32

PCAP_ERRBUF_SIZE = 256
PCAP_SRC_FILE_STRING = "file://"
PCAP_SRC_IF_STRING = ctypes.c_char_p("\\")


pcap_lib_version = wpcap.pcap_lib_version
pcap_lib_version.argtypes = None
pcap_lib_version.restype = ctypes.c_char_p

pcap_lookupdev = wpcap.pcap_lookupdev
pcap_lookupdev.argtypes = [ctypes.c_char_p]
pcap_lookupdev.restype = ctypes.c_char_p

pcap_open_live = wpcap.pcap_open_live
pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]

class  pcap_handler(ctypes.Structure):
    """callback function that receives the packets."""
    pass


class sockaddr(ctypes.Structure):
    """socket address"""
    _fields_ = [("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong)]


class pcap_dumper(ctypes.Structure):
    """libpcap savefile descriptor."""


class pcap_addr(ctypes.Structure):
    """Representation of an interface address"""
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

class pcap(ctypes.Structure):
    pass

class pcap_if(ctypes.Structure): pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', ctypes.c_char_p),
                    ('description', ctypes.c_char_p ),
                    ('addresses',POINTER(pcap_addr) ),
                    ('flags', ctypes.c_uint )]

def print_interface(pcap_ifdevice):
    return '<%s:%s>' % ('pcap_if', pcap_ifdevice.name)
pcap_if.__repr__ = print_interface


errbuf = (ctypes.c_char*PCAP_ERRBUF_SIZE)()
wpcap.pcap_findalldevs.argtypes = None
#pcap_findalldevs = wpcap.pcap_findalldevs
#pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
#pcap_findalldevs.restype = ctypes.c_int

# int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
alldevsp = POINTER(POINTER(pcap_if))()
wpcap.pcap_findalldevs(ctypes.byref(alldevsp), errbuf)

d1 = alldevsp.contents.contents
d2 = alldevsp.contents.contents.next

TenDevices = pcap_if * 10
tendevice_instance = TenDevices()
tendevice_instance_p = ctypes.pointer(tendevice_instance)
wpcap.pcap_findalldevs(ctypes.byref(tendevice_instance_p), ctypes.byref(errbuf))

deviceList = tendevice_instance_p.contents

d1 = deviceList[0]
d2 = deviceList[0].next.contents


pcap_open_live = wpcap.pcap_open_live
pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
pcap_open_live.restype = POINTER(pcap)

pcap_open_dead = wpcap.pcap_open_dead
pcap_open_offline = wpcap.pcap_open_offline
pcap_dump_open = wpcap.pcap_dump_open
pcap_setnonblock = wpcap.pcap_setnonblock
pcap_getnonblock = wpcap.pcap_getnonblock
_pcap_findalldevs = wpcap.pcap_findalldevs
def pcap_findalldevs():
    devs = ctypes.pointer(pcap_if())
    errbuf = ctypes.create_string_buffer('',256)
    retval = _pcap_findalldevs(ctypes.byref(devs), ctypes.byref(errbuf))
    if retval != 0:
        raise Exception(errbuf.value)
    responses = []
    dev = devs.contents
    responses.append(dev)
    try:
        while 1:
            next_d = dev.next.contents
            responses.append(next_d)
            dev = next_d
    except:
        pass
    return responses


pcap_freealldevs = wpcap.pcap_freealldevs
pcap_lookupdev = wpcap.pcap_lookupdev
pcap_lookupnet = wpcap.pcap_lookupnet
pcap_dispatch = wpcap.pcap_dispatch
pcap_loop = wpcap.pcap_loop
pcap_next = wpcap.pcap_next
pcap_next_ex = wpcap.pcap_next_ex
pcap_breakloop = wpcap.pcap_breakloop
pcap_sendpacket = wpcap.pcap_sendpacket
pcap_dump = wpcap.pcap_dump
pcap_dump_ftell = wpcap.pcap_dump_ftell
pcap_compile = wpcap.pcap_compile
pcap_compile_nopcap = wpcap.pcap_compile_nopcap
pcap_setfilter = wpcap.pcap_setfilter
pcap_freecode = wpcap.pcap_freecode
pcap_datalink = wpcap.pcap_datalink
pcap_list_datalinks = wpcap.pcap_list_datalinks
pcap_set_datalink = wpcap.pcap_set_datalink
pcap_datalink_name_to_val = wpcap.pcap_datalink_name_to_val
pcap_datalink_val_to_name = wpcap.pcap_datalink_val_to_name
pcap_datalink_val_to_description = wpcap.pcap_datalink_val_to_description
pcap_snapshot = wpcap.pcap_snapshot
pcap_is_swapped = wpcap.pcap_is_swapped
pcap_major_version = wpcap.pcap_major_version
pcap_minor_version = wpcap.pcap_minor_version
pcap_file = wpcap.pcap_file
pcap_stats = wpcap.pcap_stats
pcap_perror = wpcap.pcap_perror
pcap_geterr = wpcap.pcap_geterr
pcap_strerror = wpcap.pcap_strerror
pcap_lib_version = wpcap.pcap_lib_version
pcap_close = wpcap.pcap_close
pcap_dump_file = wpcap.pcap_dump_file
pcap_dump_flush = wpcap.pcap_dump_flush
pcap_dump_close = wpcap.pcap_dump_close

# Windows Specific Functions
pcap_offline_filter = wpcap.pcap_offline_filter
pcap_offline_filter = wpcap.pcap_offline_filter
pcap_live_dump = wpcap.pcap_live_dump
pcap_live_dump_ended = wpcap.pcap_live_dump_ended
pcap_stats_ex = wpcap.pcap_stats_ex
pcap_setbuff = wpcap.pcap_setbuff
pcap_setmode = wpcap.pcap_setmode
pcap_setmintocopy = wpcap.pcap_setmintocopy
pcap_getevent = wpcap.pcap_getevent
pcap_sendqueue_alloc = wpcap.pcap_sendqueue_alloc
pcap_sendqueue_destroy = wpcap.pcap_sendqueue_destroy
pcap_sendqueue_queue = wpcap.pcap_sendqueue_queue
pcap_sendqueue_transmit = wpcap.pcap_sendqueue_transmit
pcap_findalldevs_ex = wpcap.pcap_findalldevs_ex
pcap_createsrcstr = wpcap.pcap_createsrcstr
pcap_parsesrcstr = wpcap.pcap_parsesrcstr
pcap_open = wpcap.pcap_open
pcap_setsampling = wpcap.pcap_setsampling
pcap_remoteact_accept = wpcap.pcap_remoteact_accept
pcap_remoteact_close = wpcap.pcap_remoteact_close
pcap_remoteact_cleanup = wpcap.pcap_remoteact_cleanup
pcap_remoteact_list = wpcap.pcap_remoteact_list
