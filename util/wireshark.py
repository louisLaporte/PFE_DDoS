#!/usr/bin/env python3.4
import pyshark
import extract
import collections
import functools
import sys

def iterfy(iterable):
    if isinstance(iterable, str):
        iterable = [iterable]
    try:
        iter(iterable)

    except TypeError:
        iterable = [iterable]

    return iterable

def file_capture(apath=None, fname=None, extension=None, filters=None):
    ''' Parser for wireshark files type
    :param apath: apath archive path
    :param fname: file name in archive
    :param extension: extension name in archive
    :param filters: wireshark filters
    :type apath: str
    :type fname: str
    :type extension: str
    :type filters: str
    :return: packets filtered
    :rtype: list

    :Example:

    >>> import wireshark as ws
    >>> import extract
    >>> archive = '../datasets/LLS_DDOS_1.0.tar.gz'
    >>> extract.tar(path=archive, extension='.dump')
    >>> wf = 'tcp.flags.reset == 1'
    >>> capture = ws.file_capture(apath=archive, extension='.dump', filters=wf)

    '''

    caps = pyshark.FileCapture(input_file=extract.tar(path=apath, extension=extension),
                                display_filter=filters)

    return caps

def print_layer_info(pkt, layer=None, filters=None):
    ''' Display layer informations
    :param pkt: packet
    :param layer:
    :param filters:
    :type pkt: pyshark.packet.Packet
    :type layer: str
    :type filters: str
    '''

    d = getattr(sys.modules[__name__], layer + '_info')(pkt, filters=filters)

    for k, v in d.items():
        print("{:<25}: {}".format(k, v))


def layer_members(pkt, layer=None):
    ''' Get layer members
    :param pkt: packet
    :param layer:
    :type pkt: pyshark.packet.Packet
    :type layer: str
    :return: members
    :rtype: list
    '''
    try:
        l = getattr(pkt, layer)

    except AttributeError:
        return None

    return l.field_names

def layer_info(pkt, layer=None, filters=None):
    ''' Get layer informations
    :param pkt: packet
    :param layer:
    :param filters:
    :type pkt: pyshark.packet.Packet
    :type layer: str
    :type filters: str
    :return: field names and values
    :rtype: dictionnary
    '''

    info = {}

    try:
        l = getattr(pkt, layer)

        if filters:
            filters = iterfy(filters)

    except AttributeError:
        return None

    for name in l.field_names:
        if not filters:
            info[name] = l.get_field(name)

        elif name in filters:
            info[name] = l.get_field(name)

    return info
################################################################################
# Partial methods creation
################################################################################
layers = ['eth', 'ip', 'tcp']

# TODO: add __doc__
# Available methods are print_ip_info, print_eth_info, print_tcp_info
# ip_info, eth_info, tcp_info
# ip_members, eth_members, tcp_members
for l in layers:
    setattr(sys.modules[__name__],
            'print_'+ l +'_info', functools.partial(print_layer_info, layer=l))

    setattr(sys.modules[__name__],
            l +'_info', functools.partial(layer_info, layer=l))

    setattr(sys.modules[__name__],
            l +'_members', functools.partial(layer_members, layer=l))
