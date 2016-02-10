
import ctypes

# Constants
PCAP_SRC_IF_STRING = "rpcap://"
PCAP_SRC_FILE_STRING = "file://"

# Functions
bpf_dump = ctypes.windll.wpcap.bpf_dump
bpf_filter = ctypes.windll.wpcap.bpf_filter
bpf_image = ctypes.windll.wpcap.bpf_image
bpf_validate = ctypes.windll.wpcap.bpf_validate
endservent = ctypes.windll.wpcap.endservent
eproto_db = ctypes.windll.wpcap.eproto_db
getservent = ctypes.windll.wpcap.getservent
install_bpf_program = ctypes.windll.wpcap.install_bpf_program
pcap_activate = ctypes.windll.wpcap.pcap_activate
pcap_breakloop = ctypes.windll.wpcap.pcap_breakloop
pcap_close = ctypes.windll.wpcap.pcap_close
pcap_compile = ctypes.windll.wpcap.pcap_compile
pcap_compile_nopcap = ctypes.windll.wpcap.pcap_compile_nopcap
pcap_create = ctypes.windll.wpcap.pcap_create
pcap_createsrcstr = ctypes.windll.wpcap.pcap_createsrcstr
pcap_datalink = ctypes.windll.wpcap.pcap_datalink
pcap_datalink_name_to_val = ctypes.windll.wpcap.pcap_datalink_name_to_val
pcap_datalink_val_to_description = ctypes.windll.wpcap.pcap_datalink_val_to_description
pcap_datalink_val_to_name = ctypes.windll.wpcap.pcap_datalink_val_to_name
pcap_dispatch = ctypes.windll.wpcap.pcap_dispatch
pcap_dump = ctypes.windll.wpcap.pcap_dump
pcap_dump_close = ctypes.windll.wpcap.pcap_dump_close
pcap_dump_file = ctypes.windll.wpcap.pcap_dump_file
pcap_dump_flush = ctypes.windll.wpcap.pcap_dump_flush
pcap_dump_ftell = ctypes.windll.wpcap.pcap_dump_ftell
pcap_dump_open = ctypes.windll.wpcap.pcap_dump_open
pcap_file = ctypes.windll.wpcap.pcap_file
pcap_fileno = ctypes.windll.wpcap.pcap_fileno
pcap_findalldevs = ctypes.windll.wpcap.pcap_findalldevs
_pcap_findalldevs_ex = ctypes.windll.wpcap.pcap_findalldevs_ex
pcap_free_datalinks = ctypes.windll.wpcap.pcap_free_datalinks
pcap_freealldevs = ctypes.windll.wpcap.pcap_freealldevs
pcap_freecode = ctypes.windll.wpcap.pcap_freecode
pcap_get_airpcap_handle = ctypes.windll.wpcap.pcap_get_airpcap_handle
pcap_geterr = ctypes.windll.wpcap.pcap_geterr
pcap_getevent = ctypes.windll.wpcap.pcap_getevent
pcap_getnonblock = ctypes.windll.wpcap.pcap_getnonblock
pcap_hopen_offline = ctypes.windll.wpcap.pcap_hopen_offline
pcap_is_swapped = ctypes.windll.wpcap.pcap_is_swapped
pcap_lib_version = ctypes.windll.wpcap.pcap_lib_version
pcap_list_datalinks = ctypes.windll.wpcap.pcap_list_datalinks
pcap_live_dump = ctypes.windll.wpcap.pcap_live_dump
pcap_live_dump_ended = ctypes.windll.wpcap.pcap_live_dump_ended
pcap_lookupdev = ctypes.windll.wpcap.pcap_lookupdev
pcap_lookupnet = ctypes.windll.wpcap.pcap_lookupnet
pcap_loop = ctypes.windll.wpcap.pcap_loop
pcap_major_version = ctypes.windll.wpcap.pcap_major_version
pcap_minor_version = ctypes.windll.wpcap.pcap_minor_version
pcap_next = ctypes.windll.wpcap.pcap_next
pcap_next_etherent = ctypes.windll.wpcap.pcap_next_etherent
pcap_next_ex = ctypes.windll.wpcap.pcap_next_ex
pcap_offline_filter = ctypes.windll.wpcap.pcap_offline_filter
pcap_offline_read = ctypes.windll.wpcap.pcap_offline_read
pcap_open = ctypes.windll.wpcap.pcap_open
pcap_open_dead = ctypes.windll.wpcap.pcap_open_dead
pcap_open_live = ctypes.windll.wpcap.pcap_open_live
pcap_open_offline = ctypes.windll.wpcap.pcap_open_offline
pcap_parsesrcstr = ctypes.windll.wpcap.pcap_parsesrcstr
pcap_perror = ctypes.windll.wpcap.pcap_perror
pcap_read = ctypes.windll.wpcap.pcap_read
pcap_remoteact_accept = ctypes.windll.wpcap.pcap_remoteact_accept
pcap_remoteact_cleanup = ctypes.windll.wpcap.pcap_remoteact_cleanup
pcap_remoteact_close = ctypes.windll.wpcap.pcap_remoteact_close
pcap_remoteact_list = ctypes.windll.wpcap.pcap_remoteact_list
pcap_sendpacket = ctypes.windll.wpcap.pcap_sendpacket
pcap_sendqueue_alloc = ctypes.windll.wpcap.pcap_sendqueue_alloc
pcap_sendqueue_destroy = ctypes.windll.wpcap.pcap_sendqueue_destroy
pcap_sendqueue_queue = ctypes.windll.wpcap.pcap_sendqueue_queue
pcap_sendqueue_transmit = ctypes.windll.wpcap.pcap_sendqueue_transmit
pcap_set_buffer_size = ctypes.windll.wpcap.pcap_set_buffer_size
pcap_set_datalink = ctypes.windll.wpcap.pcap_set_datalink
pcap_set_promisc = ctypes.windll.wpcap.pcap_set_promisc
pcap_set_snaplen = ctypes.windll.wpcap.pcap_set_snaplen
pcap_set_timeout = ctypes.windll.wpcap.pcap_set_timeout
pcap_setbuff = ctypes.windll.wpcap.pcap_setbuff
pcap_setdirection = ctypes.windll.wpcap.pcap_setdirection
pcap_setfilter = ctypes.windll.wpcap.pcap_setfilter
pcap_setmintocopy = ctypes.windll.wpcap.pcap_setmintocopy
pcap_setmode = ctypes.windll.wpcap.pcap_setmode
pcap_setnonblock = ctypes.windll.wpcap.pcap_setnonblock
pcap_setsampling = ctypes.windll.wpcap.pcap_setsampling
pcap_setuserbuffer = ctypes.windll.wpcap.pcap_setuserbuffer
pcap_snapshot = ctypes.windll.wpcap.pcap_snapshot
pcap_stats = ctypes.windll.wpcap.pcap_stats
pcap_stats_ex = ctypes.windll.wpcap.pcap_stats_ex
pcap_strerror = ctypes.windll.wpcap.pcap_strerror
wsockinit = ctypes.windll.wpcap.wsockinit

# Classes
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

# Add Response Types
pcap_lookupdev.restype = ctypes.c_char_p
pcap_findalldevs_ex.restype = ctypes.c_int


# Adds Doc Strings

def pcap_findalldevs_ex(source, auth, alldevs, errbuf):
    """Retrieve the device list from the local machine
    
    this function returns a linked list of pcap_if structures, each of 
    which contains comprehensive information about an attached adapter. 
    In particular, the fields name and description contain the name and 
    a human readable description, respectively, of the corresponding 
    device.
    
    Args:
        source (ctypes.c_char_p): buffer that keeps the 'source localtion', 
            according to the new WinPcap syntax. This source will be 
            examined looking for adapters (local or remote)
        auth (struct pcap_rmtauth *):a pointer to a pcap_rmtauth 
            structure. This pointer keeps the information required to 
            authenticate the RPCAP connection to the remote host. This 
            parameter is not meaningful in case of a query to the local 
            host: in that case it can be NULL.
        alldevs (pcap_if_t **): a 'struct pcap_if_t' pointer, which will 
            be properly allocated inside this function. When the function 
            returns, it is set to point to the first element of the 
            interface list; each element of the list is of type 
            `struct pcap_if_t`.
        errbuf (ctypes.c_char_p): a pointer to a user-allocated buffer (of size 
            PCAP_ERRBUF_SIZE) that will contain the error message.

    Returns:
        int: 0 successful, otherwise unsuccessful.
    """
    return _pcap_findalldevs_ex(source, auth, alldevs, errbuf)

