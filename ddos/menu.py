from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

import ddos.dialog
import tarfile
from ddos.network import *

class AttacksMenu(QMenu):

    def __init__(self):
        super().__init__('A&ttacks')
        self.setObjectName('AttacksMenu')
        icmp_action = QAction('&ICMP', self)
        icmp_action.setStatusTip('Send ICMP packet')
        icmp_action.setObjectName('Icmp')

        tcp_action = QAction('&TCP', self)
        tcp_action.setStatusTip('TCP connection')
        tcp_action.setObjectName('Tcp')
        self.addAction(icmp_action)
        self.addAction(tcp_action)

class AnalyzeMenu(QMenu):
    def __init__(self):
        super().__init__('&Analyze')
        self.setObjectName('AnalyzeMenu')

class StatisticsMenu(QMenu):
    def __init__(self):
        super().__init__('&Statistics')
        self.setObjectName('StatisticsMenu')
        #self.setTitle('&Statistics')

class EditMenu(QMenu):
    fileSelected = pyqtSignal(list)
    def __init__(self):
        super().__init__('&Edit')
        self.setObjectName('EditMenu')

        open_action = QAction('&Convert pcap to csv', self)
        open_action.setStatusTip('Convert pcap file to csv file')
        open_action.triggered.connect(self.showDialog)
        self.addAction(open_action)
        self.fileSelected.connect(self.convert)

    def showDialog(self):
        file_dialog = QFileDialog()
        filters = [
                    "All files (*)",
                    "Pcap files (*.pcap)",
                    "Tcpdump files (*.dump)",
                  ]

        file_dialog.setNameFilters(filters)
        ret = file_dialog.exec_()
        print(ret)
        self.fileSelected.emit(file_dialog.selectedFiles())

    @pyqtSlot(list)
    def convert(self, fnames):
        for fname in fnames:
            print(fname)
        return
        name = fname.split('/')[-1]
        util.extract.write_csv(path=fname, fname='./data/' + name + '.csv')

class FileMenu(QMenu):
    fileSelected = pyqtSignal(str)
    def __init__(self):
        super().__init__('&File')
        self.setObjectName('FileMenu')

        open_action = QAction('&Open', self)
        open_action.setShortcut('Ctrl+O')
        open_action.setStatusTip('Open file')
        open_action.setObjectName('open')
        open_action.triggered.connect(self.showFileDialog)
        self.addAction(open_action)

        save_action = QAction('&Save', self)
        save_action.setShortcut('Ctrl+S')
        save_action.setStatusTip('Save file')
        open_action.setObjectName('save')
        self.addAction(save_action)

        quit_action = QAction('&Quit', self)
        quit_action.setShortcut('Ctrl+Q')
        quit_action.setStatusTip('Quit application')
        open_action.setObjectName('quit')
        quit_action.triggered.connect(QApplication.instance().quit)
        self.addAction(quit_action)

        self.tar_dialog = ddos.dialog.TarDialog()

    def showFileDialog(self):
        ''' Show a dialog for common file else it
        '''
        f = QFileDialog.getOpenFileName(self, 'Open file')
        f = f[0]
        print(f)
        if tarfile.is_tarfile(f):
            self.tar_dialog.fromFile(f)
            self.tar_dialog.exec_()
            f = self.tar_dialog.selectedFile()
        print(f)
        return
        self.fileSelected.emit(f)
