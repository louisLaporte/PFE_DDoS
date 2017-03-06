import pyqtgraph as pg

class GridLayout(pg.GraphicsLayoutWidget):
    def __init__(self):
        super().__init__()

    def addWidget(widget,row=0, col=0)
        w = widget
        self.addPlot(row=row, col=col, title=w.title, x=w.x, y=w.y,
                        symbol=w.symbol, symbolPen=w.symbolPen)

class Plot2d():
    def __init__(self, title=None, x=0, y=0, symbol=None, symbolPen=None ):
        self.title = title
        self.x = x
        self.y = y
        self.symbol = symbol
        self.symbolPen = symbolPen

    def setX(self, x):
        self.x = x

    def setY(self, y):
        self.y = y

    def setSymbol(self, symbol):
        self.symbol = symbol

    def setSymbolPen(self, symbolPen):
        self.symbolPen = symbolPen

class Plot3d(gl.GLViewWidget):
    def __init__(self, title=None, x=0, y=0, z=0, axes=True, grid=True, scale=1):
        super().__init__(title=title)
        self.scale = scale
        self.grid = grid
        self.setWindowTitle(title)

        data_x = np.array(pd.DataFrame(self.df, columns=[x])).flatten()
        data_y = np.array(pd.DataFrame(self.df, columns=[y])).flatten()
        data_z = np.array(pd.DataFrame(self.df, columns=[z])).flatten()

        if self.grid:
            self.gx = gl.GLGridItem()
            self.gx.rotate(90, 0, 1, 0)
            self.gx.translate(-100, 0, 0)
            self.gx.scale(100,100,100)

            self.gy = gl.GLGridItem()
            self.gy.rotate(90, 1, 0, 0)
            self.gy.translate(0, -100, 0)

            self.gz = gl.GLGridItem()
            self.gz.translate(0, 0, -100)

            self.addItem(self.gx)
            self.addItem(self.gy)
            self.addItem(self.gz)

        self.ax = gl.GLAxisItem()
        self.ax.setSize(x=1, y=1, z=1)

        self.pos = np.empty((len(data_x), 3))
        self.size = np.empty((len(data_y)))
        self.color = np.empty((len(data_z), 4))
        print(max(data_x),max(data_y),max(data_z))
        for i, (x, y, z) in enumerate(zip(data_x*scale//max(data_x),
                                            data_y*scale//max(data_y),
                                            data_z*scale//max(data_z))):
            pos[i] = (x,y,z)
            size[i] = 1;
            color[i] = (1.0, 0.0, 0.0, 0.5)
        self.sp1 = gl.GLLinePlotItem(pos=pos, color=color,mode='lines', width=10)
        self.addItem(sp1)
