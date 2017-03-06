#!/usr/bin/env python3
import sys
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

from PyQt5.QtWidgets import QApplication
import ddos.main_window

def main():

    a = QApplication(sys.argv)
    win = ddos.main_window.MainWindow()
    win.show()
    sys.exit(a.exec_())


if __name__ == '__main__':

    try:
        main()

    except KeyboardInterrupt:
        sys.exit()
