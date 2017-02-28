#!/usr/bin/env python3.4
import sys
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

from PyQt5.QtWidgets import QApplication
import pyqtgraph as pg
import app

#import pyqtgraph.exporters

##o, s, t, d, +
#run unit test
if __name__ == '__main__':
    try:
        a = QApplication(sys.argv)
        win = app.MainWindow()
        win.show()
        sys.exit(a.exec_())

    except KeyboardInterrupt:
        sys.exit()

