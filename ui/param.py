import pyqtgraph.parametertree.parameterTypes as pTypes
from pyqtgraph.parametertree import Parameter, ParameterTree, ParameterItem, registerParameterType

class ComplexParameter(pTypes.GroupParameter):
    def __init__(self, **opts):
        opts['type'] = 'bool'
        opts['value'] = True
        pTypes.GroupParameter.__init__(self, **opts)

        self.addChild({'name': 'A = 1/B', 'type': 'float', 'value': 7, 'suffix': 'Hz', 'siPrefix': True})
        self.addChild({'name': 'B = 1/A', 'type': 'float', 'value': 1/7., 'suffix': 's', 'siPrefix': True})
        self.a = self.param('A = 1/B')
        self.b = self.param('B = 1/A')
        self.a.sigValueChanged.connect(self.aChanged)
        self.b.sigValueChanged.connect(self.bChanged)

    def aChanged(self):
        self.b.setValue(1.0 / self.a.value(), blockSignal=self.bChanged)

    def bChanged(self):
        self.a.setValue(1.0 / self.b.value(), blockSignal=self.aChanged)

## this group includes a menu allowing the user to add new parameters into its child list
class ScalableGroup(pTypes.GroupParameter):
    def __init__(self, **opts):
        opts['type'] = 'group'
        opts['addText'] = "Add"
        opts['addList'] = ['str', 'float', 'int']
        pTypes.GroupParameter.__init__(self, **opts)

    def addNew(self, typ):
        val = {
            'str': '',
            'float': 0.0,
            'int': 0
        }[typ]
        self.addChild(dict(name="ScalableParam %d" % (len(self.childs)+1),
                        type=typ,
                        value=val,
                        removable=True,
                        renamable=True))

class Create(Parameter):
    def __init__(self,name=None, type_=None, children=None):
        super().__init__()
        self.create(name=name, type=type_, children=children)
    def addChildren(self, children):
        pass

class Tree(ParameterTree):
    def __init__(self):
        super().__init__()
        self.p = Parameter.create(name='test', type='group', children=params)
        self.p.param('Save/Restore functionality', 'Save State').sigActivated.connect(self.save)
        self.p.param('Save/Restore functionality', 'Restore State').sigActivated.connect(self.restore)
        self.p.param('graph', 'Draw').sigActivated.connect(self.on_draw_btn_clicked)

    def change(self, param, changes):
        print("tree changes:")
        for param, change, data in changes:
            path = self.p.childPath(param)
            if path is not None:
                childName = '.'.join(path)
            else:
                childName = param.name()
            print('  parameter: %s'% childName)
            print('  change:    %s'% change)
            print('  data:      %s'% str(data))
            print('  ----------')

    def save(self):
        global state
        state = self.p.saveState()

    def restore(self):
        global state
        add = self.p['Save/Restore functionality', 'Restore State', 'Add missing items']
        rem = self.p['Save/Restore functionality', 'Restore State', 'Remove extra items']
        self.p.restoreState(state, addChildren=add, removeChildren=rem)
