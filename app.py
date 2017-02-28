from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

import pyqtgraph as pg
import numpy as np
import pandas as pd
import sys
from menu import *
import util.extract
from network import *
save = False

fname = 'data/summary_inside'

pcap_file='/home/louis/project/PFE_DDoS/util/data_and_labeling/tcpdump_inside/LLS_DDOS_1.0-inside.dump'
#pg.setConfigOption('background', 'w')
#pg.setConfigOption('foreground', 'k')
class MyTableModel(QAbstractTableModel):
    def __init__(self, datain, headerdata, parent=None, *args):
        QAbstractTableModel.__init__(self, parent, *args)
        self.arraydata = datain
        self.headerdata = headerdata

    def rowCount(self, parent):
        return len(self.arraydata)

    def columnCount(self, parent):
        return len(self.arraydata[0])

    def data(self, index, role):
        if not index.isValid():
            return QVariant()
        elif role == Qt.TextAlignmentRole:
            return QVariant(Qt.AlignRight | Qt.AlignVCenter)
        elif role == Qt.DisplayRole:
            return QVariant(str(self.arraydata[index.row()][index.column()]))
        return QVariant()

class MenuBar(QMenuBar):
    def __init__(self):
        super().__init__()

class StatusBar(QStatusBar):
    def __init__(self):
        super().__init__()

class ToolBar(QToolBar):
    playPressed = pyqtSignal()
    pausePressed = pyqtSignal()
    def __init__(self):
        super().__init__()

        action_stop = QAction(QIcon(self.icon_name(name="stop")), "stop", self)
        action_stop.setObjectName('stop')
        self.addAction(action_stop)

        action_play = QAction(QIcon(self.icon_name(name="play_arrow")), "play", self)
        action_stop.setObjectName('play')
        self.addAction(action_play)
        action_play.triggered.connect(self.on_actionPlay)

    @pyqtSlot()
    def on_actionPlay(self):
        s = self.sender()
        if s.objectName() == 'play':
            s.setIcon(QIcon(self.icon_name(name="pause")))
            s.setText('pause')
            self.playPressed.emit()
        else:
            s.setIcon(QIcon(self.icon_name(name="play_arrow")))
            s.setText('play')
            self.pausePressed.emit()

    @staticmethod
    def icon_name(path='./icons', name=None):
        return path + "/ic_" + name + "_black_18px.svg"

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.file_menu       = FileMenu()
        self.edit_menu       = EditMenu()
        self.statistics_menu = StatisticsMenu()
        self.analyze_menu    = AnalyzeMenu()
        self.attacks_menu    = AttacksMenu()

        self.tool_bar = ToolBar()
        self.addToolBar(self.tool_bar)
        self.setStatusBar(StatusBar())
        self.setMenuBar(MenuBar())
        self.menuBar().addMenu(self.file_menu)
        self.menuBar().addMenu(self.edit_menu)
        self.menuBar().addMenu(self.statistics_menu)
        self.menuBar().addMenu(self.analyze_menu)
        self.menuBar().addMenu(self.attacks_menu)

        self.file_menu.fileSelected.connect(self.on_fileSelected)
        #items = util.extract.csv_keys()
        #items.insert(0, "None")
        self.sniffer = Sniffer()

        self.tool_bar.playPressed.connect(self.sniffer.start)
        self.tool_bar.pausePressed.connect(self.on_pausePressed)

        central_widget = QWidget()
        glayout = QGridLayout()
        #self.table_widget = pg.TableWidget()
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(1)
        self.sniffer.summaryUpdated.connect(self.onChangeCell)
        glayout.addWidget(self.table_widget, 0, 0)
        central_widget.setLayout(glayout)
        self.setCentralWidget(central_widget)
        self.attacks_menu.triggered[QAction].connect(self.on_menuTriggered)

    @pyqtSlot(QAction)
    def on_menuTriggered(self, a):
        new_widget = getattr(sys.modules[__name__], a.objectName() + 'Widget')()
        current_widget = self.centralWidget().layout().itemAtPosition(0,0).widget()
        print(current_widget.objectName(), new_widget.objectName())
        current_widget.setEnabled(False)
        current_widget.deleteLater()
        self.centralWidget().layout().addWidget(new_widget, 0, 0)

    @pyqtSlot(str)
    def onChangeCell(self, content):
        self.table_widget.insertRow(self.table_widget.rowCount())
        self.table_widget.setItem(self.table_widget.rowCount() - 1, 0, QTableWidgetItem(content))


    @pyqtSlot()
    def on_playPressed(self):
        self.sniffer.start()

    @pyqtSlot()
    def on_pausePressed(self):
        self.sniffer.stopSniffing.emit()

    @pyqtSlot(str)
    def on_fileSelected(self, fname):
        self.statusBar().showMessage('Ready read {}'.format(fname))
        # /!\ Slow methods
        #self.df = np.genfromtxt(fname,delimiter=',')
        #self.r = util.extract.read_csv(fname)
        self.df = pd.read_csv(fname, header=None,dtype=util.extract.csv_keys_type())
        #print(self.df.dtypes)
        row = self.df.iloc[1:].values

        print(len(row))
        print(self.df.iloc[37000].values)
        self.table_widget.setRowCount(len(row))
        self.table_widget.setColumnCount(20)
        self.table_widget.setHorizontalHeaderLabels(self.df.iloc[0].values)
        if 0:
            for i, r in enumerate(row):
                #self.table_widget.setData(i)
                for j, c in enumerate(r):
                    #print(c)
                    self.table_widget.setItem(i,j,QTableWidgetItem(c))

        self.statusBar().showMessage('Finished reading {}'.format(fname))

#        self.view = pg.GraphicsLayoutWidget()
#        data = np.array(pd.DataFrame(self.df, columns=['tcp_flags'])).flatten()
#        self.view.addPlot(row=0, col=0, title="TCP flags", y=data)
#        params = [
#            {
#            'name': 'graph',
#            'type': 'group',
#            'children': [
#
#                {
#                'name'   : 'x'   ,
#                'type'   : 'list',
#                'values' : items ,
#                'value'  : 'id'  ,
#                'default': 'id'
#                },
#
#                {
#                'name'   : 'y'        ,
#                'type'   : 'list'     ,
#                'values' : items      ,
#                'value'  : 'tcp_flags',
#                'default': 'tcp_flags'
#                },
#
#                {
#                'name'   : 'z'         ,
#                'type'   : 'list'      ,
#                'values' : items       ,
#                'value'  : 'tcp_window',
#                'default': 'tcp_window'
#                },
#
#                {
#                'name': '3D'    ,
#                'type': 'bool'  ,
#                'value': True   ,
#                'tip': "draw 3D"
#                },
#
#                {
#                'name': 'Pen'   ,
#                'type': 'bool'  ,
#                'value': True   ,
#                'tip': "use pen"
#                },
#
#                {
#                'name': 'Color',
#                'type': 'color',
#                'value': "FF0" ,
#                'tip': "Color"
#                },
##                {'name': 'Subgroup', 'type': 'group', 'children': [
##                    {'name': 'Sub-param 1', 'type': 'int', 'value': 10},
##                    {'name': 'Sub-param 2', 'type': 'float', 'value': 1.2e6},
##                ]},
##                {'name': 'Text Parameter', 'type': 'text', 'value': 'Some text...'},
#                {
#                'name': 'Draw',
#                'type': 'action'
#                }]
#            },
#
#            {
#            'name': 'Save/Restore functionality',
#            'type': 'group',
#            'children': [
#                {
#                'name': 'Save State',
#                'type': 'action'
#                },
#
#                {
#                'name': 'Restore State',
#                'type': 'action',
#                'children': [
#                    {
#                    'name': 'Add missing items',
#                    'type': 'bool',
#                    'value': True
#                    },
#                    {
#                    'name': 'Remove extra items',
#                    'type': 'bool', 'value': True
#                    }]
#                }]
#            },
#            ScalableGroup(name="Expandable Parameter Group", children=[
#                {'name': 'ScalableParam 1', 'type': 'str', 'value': "default param 1"},
#                {'name': 'ScalableParam 2', 'type': 'str', 'value': "default param 2"},
#            ]),
#        ]
#
#        self.p = Parameter.create(name='test', type='group', children=params)
#        self.p.param('Save/Restore functionality', 'Save State').sigActivated.connect(self.save)
#        self.p.param('Save/Restore functionality', 'Restore State').sigActivated.connect(self.restore)
#        self.p.param('graph', 'Draw').sigActivated.connect(self.on_draw_btn_clicked)
#i
#
#        self.p.sigTreeStateChanged.connect(self.change)
#        self.tree_wid = ParameterTree()
#        self.tree_wid.setParameters(self.p, showTop=False)
#
#        self.glayout.addWidget(self.tree_wid    , 0, 0)
#        self.glayout.addWidget(self.view        , 0, 1)
#        self.setCentralWidget(self.central_wid)
#        self.draw_btn.clicked.connect(self.on_draw_btn_clicked)
#        self.on_draw_btn_clicked()
#
#
#    @pyqtSlot()
#    def on_draw_btn_clicked(self):
#        print(self.p.param('graph','3D').value())
#        if not self.p.param('graph','3D').value():
#            self.draw2d(self.p.param('graph', 'x').value(), self.p.param('graph', 'y').value())
#        else:
#            self.draw3d(self.p.param('graph', 'x').value(),
#                      self.p.param('graph', 'y').value(),
#                      self.p.param('graph', 'z').value())
#
##    @pyqtSlot(str)
##    def draw2d(self, x, y):
##
##        data_y = np.array(pd.DataFrame(self.df, columns=[x])).flatten()
##        data_x = np.array(pd.DataFrame(self.df, columns=[y])).flatten()
##        self.view.removeItem(self.view.getItem(0, 0))
##        self.view.addPlot(row=0, col=0, title="TCP flags",x=data_x, y=data_y, symbol='+', symbolPen='r')
##        self.glayout.addWidget(self.view, 0,1)
##
##    def draw3d(self, x, y, z):
##
##        data_x = np.array(pd.DataFrame(self.df, columns=[x])).flatten()
##        data_y = np.array(pd.DataFrame(self.df, columns=[y])).flatten()
##        data_z = np.array(pd.DataFrame(self.df, columns=[z])).flatten()
##
##        w = gl.GLViewWidget()
##
##        w.opts['distance'] = 200
##        w.setWindowTitle('pyqtgraph example: GLScatterPlotItem')
##
##        gx = gl.GLGridItem()
##        gx.rotate(90, 0, 1, 0)
##        gx.translate(-100, 0, 0)
##        gx.scale(100,100,100)
##        w.addItem(gx)
##
##        gy = gl.GLGridItem()
##        gy.rotate(90, 1, 0, 0)
##        gy.translate(0, -100, 0)
##        #gy.scale(100,0,100)
##        w.addItem(gy)
##
##        gz = gl.GLGridItem()
##        gz.translate(0, 0, -100)
##        #gz.scale(100,0,100)
##        w.addItem(gz)
##        #gx.setSpacing(x=max(data_x),y=max(data_y))
##        #gy.setSpacing(y=max(data_y),z=max(data_z))
##        #gz.setSpacing(z=max(data_z),x=max(data_x))
##
##
##        ax = gl.GLAxisItem()
##        #
##        #  First example is a set of points with pxMode=False
##        #  These demonstrate the ability to have points with real size down to a very small scale
##        #
##        ax.setSize(x=1, y=1, z=1)
##        w.addItem(ax)
##        pos = np.empty((len(data_x), 3))
##        size = np.empty((len(data_y)))
##        color = np.empty((len(data_z), 4))
##        print(max(data_x),max(data_y),max(data_z))
##        scale = 100
##        for i, (x, y, z) in enumerate(zip(data_x*scale//max(data_x),
##                                            data_y*scale//max(data_y),
##                                            data_z*scale//max(data_z))):
##        #for i, (x, y, z) in enumerate(zip(data_x, data_y, data_z)):
###            pos[i] = (x/max(data_x),y/max(data_y),z/max(data_z))
##            pos[i] = (x,y,z)
##            size[i] = 1;
##            color[i] = (1.0, 0.0, 0.0, 0.5)
##        #sp1 = gl.GLScatterPlotItem(pos=pos, size=size, color=color, pxMode=False)
##        sp1 = gl.GLLinePlotItem(pos=pos, color=color,mode='lines', width=10)
##        #sp1 = gl.GLSurfacePlotItem(pos=pos, color=color)
##
##        #sp1.translate(5,5,0)
##        w.addItem(sp1)
##        self.glayout.addWidget(w , 0, 1)
##        #w.pan(100,100,100)
