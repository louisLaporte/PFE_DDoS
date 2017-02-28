from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *

import tarfile
import util.extract
class TarDialog(QDialog):
    ''' +--------------+
        +   TreeView   +
        +--------------+
        + Ok  | Cancel +
        +--------------+
    '''
    #TODO:  - Create hierarchy
    #       - Fit TableView to parent Widget
    def __init__(self, fname=None):
        super().__init__()

        self.selected_file = None
        self.main_widget = QWidget(self)
        layout = QGridLayout()

        ok_button = QPushButton("Ok")
        ok_button.setObjectName("ok_button")
        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("cancel_button")
        # TODO: change to QTreeWidget
        self.tree_view = QTreeView()
        self.tree_view.setObjectName("tree_view")

        if fname is not None:
            self.fromFile(fname)

        self.tree_view.expandAll()
        self.setGeometry(0,0,500, 500)

        layout.addWidget(self.tree_view, 0, 0, 1, 2)
        layout.addWidget(cancel_button , 1, 0)
        layout.addWidget(ok_button     , 1, 1)

        self.main_widget.setLayout(layout)

        cancel_button.released.connect(self.on_cancelButton)
        ok_button.released.connect(self.close)

    @pyqtSlot()
    def on_cancelButton(self):
        self.selected_file = None
        self.close()

    def selectedFile(self):
        return self.selected_file

    def fromFile(self, fname):
        ''' Create a view model from fname
        '''
        std_model = QStandardItemModel()
        root_node = std_model.invisibleRootItem()

        files = util.extract.tar(path=fname)

        for f in files:
            item = QStandardItem(f.name)
            root_node.appendRow(item)

        self.tree_view.setModel(std_model)
        selection_model = self.tree_view.selectionModel()

        selection_model.selectionChanged.connect(self.selectionChangedSlot)

    @pyqtSlot(QItemSelection, QItemSelection)
    def selectionChangedSlot(self, selected, deselected):
        ''' Get the new selected item
        '''
        index = self.tree_view.selectionModel().currentIndex()
        self.selected_file = str(index.data(Qt.DisplayRole))
        # find out the hierarchy level of the selected item
        hierarchy_level=1;
        seek_root = index;

        while(seek_root.parent() != QModelIndex()):
            seek_root = seek_root.parent()
            hierarchy_level += 1

        #print(hierarchy_level)


