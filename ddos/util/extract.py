#!/usr/bin/env python3
import re
import sys
import os
import tarfile
import gzip
import csv
import pandas as pd
import numpy as np
from functools import wraps
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def path_isvalid(f):
    @wraps(f)
    def wrapper(*args, **kargs):
        key = 'path'

        if not key in kargs:
            raise NameError('keyword "path" does not exist')

        if not os.path.exists(kargs.get(key)):
            raise OSError("Path {} does not exist".format(kargs[key]))

        return f(*args, **kargs)
    return wrapper

@path_isvalid
def gunzip(path=None):
    with gzip.open(path, 'rt') as z:
        for l in z:
        #f = z.read()
            print(l)
        #return f

@path_isvalid
def tar(path=None, info=False, extension=None, fname=None):
    ''' Get tar file content without extracting
    :param path: tar file path
    :param info: show tar info
    :param extension: get files match extension inside archive

    :Note: If fname is specified extension is not used.

    :Example:
    >>> import extract
    >>> archive = '../datasets/LLS_DDOS_1.0.tar.gz'
    >>> files = extract.tar(path=archive, extension='.dump', info=True)

    '''
    if not tarfile.is_tarfile(path):
        raise tarfile.TarError("file is not a tar file")
    found_files = []

    print("Start extraction for {}".format(path))
    print("Search extension {} ...".format(extension))
    with tarfile.open(name=path) as tarchive:
        if info:
            print(tarchive.list())

        archives = [a for a in tarchive if a.isfile() and not '*' in a.name]

        for a in archives:
            ext = os.path.splitext(a.name)[1]

            if a.name == fname:
                found_files = a
                break

            if ext == extension or extension is None:
                found_files.append(a)

        print("Extraction finished")
        if fname is None:
            return found_files
        else:
            return found_file[0]

if __name__ == '__main__':
    tar(path='./data/summary.tgz', info=True)
    tar(path='./datasets/LLS_DDOS_1.0.tar.gz', info=True)


@path_isvalid
def write_csv(path=None, fname=None):
    load_contrib("cdp")
    # /!\ Do NOT use this method, it will causes a memory trouble
    #reader = rdpcap(pcap_file)
    reader = PcapReader(path)
    name, ext = os.path.splitext(fname)

    if ext != '.csv':
        raise csv.Error("file {} is not a csv file".format(fname))

    with open(fname, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=csv_keys_type().keys)
        writer.writeheader()

        for i, pkt in enumerate(reader):
            try:
                if pkt.haslayer('TCP'):
                    writer.writerow({
                                        "time"        : pkt.time            ,
                                        "id"          : i                   ,
                                        "eth_mac_dst" : pkt.dst             ,
                                        "eth_mac_src" : pkt.src             ,
                                        "ip_ihl"      : pkt['IP' ].ihl      ,
                                        "ip_tos"      : pkt['IP' ].tos      ,
                                        "ip_len"      : pkt['IP' ].len      ,
                                        "ip_id"       : pkt['IP' ].id       ,
                                        "ip_flags"    : pkt['IP' ].flags    ,
                                        "ip_frag"     : pkt['IP' ].frag     ,
                                        "ip_ttl"      : pkt['IP' ].ttl      ,
                                        "ip_src"      : pkt['IP' ].src      ,
                                        "ip_dst"      : pkt['IP' ].dst      ,
                                        "tcp_sport"   : pkt['TCP'].sport    ,
                                        "tcp_dport"   : pkt['TCP'].dport    ,
                                        "tcp_seq"     : pkt['TCP'].seq      ,
                                        "tcp_ack"     : pkt['TCP'].ack      ,
                                        "tcp_dataofs" : pkt['TCP'].dataofs  ,
                                        "tcp_reserved": pkt['TCP'].reserved ,
                                        "tcp_flags"   : pkt['TCP'].flags    ,
                                        "tcp_window"  : pkt['TCP'].window  })

            except AttributeError:
                pass

def read_csv(fname=None):
    reader = csv.DictReader(open(fname))

    result = {}
    for row in reader:
        for column, value in row.items():
                result.setdefault(column, []).append(value)
    return result


def csv_keys_type():
    l = [
    {'name': "time"        , 'dtype': np.float64 , 'layer': None , 'attr': 'time'    },
    {'name': "id"          , 'dtype': np.uint64  , 'layer': None , 'attr':  None     },
    {'name': "eth_mac_dst" , 'dtype': np.str_    , 'layer': None , 'attr': 'dst'     },
    {'name': "eth_mac_src" , 'dtype': np.str_    , 'layer': None , 'attr': 'src'     },
    {'name': "ip_ihl"      , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'ihl'     },
    {'name': "ip_tos"      , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'tos'     },
    {'name': "ip_len"      , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'len'     },
    {'name': "ip_id"       , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'id'      },
    {'name': "ip_flags"    , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'flags'   },
    {'name': "ip_frag"     , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'frag'    },
    {'name': "ip_ttl"      , 'dtype': np.uint64  , 'layer': 'IP' , 'attr': 'ttl'     },
    {'name': "ip_src"      , 'dtype': np.str_    , 'layer': 'IP' , 'attr': 'src'     },
    {'name': "ip_dst"      , 'dtype': np.str_    , 'layer': 'IP' , 'attr': 'dst'     },
    {'name': "tcp_sport"   , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'sport'   },
    {'name': "tcp_dport"   , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'dport'   },
    {'name': "tcp_seq"     , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'seq'     },
    {'name': "tcp_ack"     , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'ack'     },
    {'name': "tcp_dataofs" , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'dataofs' },
    {'name': "tcp_reserved", 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'reserved'},
    {'name': "tcp_flags"   , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'flags'   },
    {'name': "tcp_window"  , 'dtype': np.uint64  , 'layer': 'TCP', 'attr': 'window'  },
    ]
    return l

# TCP flags
#FIN = 0x01
#SYN = 0x02
#RST = 0x04
#PSH = 0x08
#ACK = 0x10
#URG = 0x20
#ECE = 0x40
#CWR = 0x80
#CWR – Congestion Window Reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set (added to header by RFC 3168).
#ECE (ECN-Echo) – indicate that the TCP peer is ECN capable during 3-way handshake (added to header by RFC 3168).
#URG – indicates that the URGent pointer field is significant
#ACK – indicates that the ACKnowledgment field is significant (Sometimes abbreviated by tcpdump as ".")
#PSH – Push function
#RST – Reset the connection (Seen on rejected connections)
#SYN – Synchronize sequence numbers (Seen on new connections)
#FIN – No more data from sender (Seen after a connection is closed)

#ihl = Intenet header length
# * tos = type of service
#000 (0) - Routine
#001 (1) - Priority
#010 (2) - Immediate
#011 (3) - Flash
#100 (4) - Flash Override
#101 (5) - Critical
#110 (6) - Internetwork Control
#111 (7) - Network Control
