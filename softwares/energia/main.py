#!/usr/bin/python -tt

import sys
import os
from PyQt4 import QtGui
from gui import Ui_Sembei

class GUI(QtGui.QMainWindow):

    def __init__(self):
        super(GUI, self).__init__()
        self.ui=Ui_Sembei()
        self.ui.setupUi(self)
        self.show()

def main():
    app = QtGui.QApplication(sys.argv)
    ex = GUI()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
