# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created: Mon May  5 23:02:37 2014
#	  by: PyQt4 UI code generator 4.10.3
#
# WARNING! All changes made in this file will be lost!

import os
from PyQt4 import QtCore, QtGui
from SensorMeasure import Handler

try:
	_fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
	def _fromUtf8(s):
		return s

try:
	_encoding = QtGui.QApplication.UnicodeUTF8
	def _translate(context, text, disambig):
		return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
	def _translate(context, text, disambig):
		return QtGui.QApplication.translate(context, text, disambig)

class Ui_MainWindow(object):
	def setupUi(self, MainWindow):
		MainWindow.setObjectName(_fromUtf8("MainWindow"))
		MainWindow.resize(640, 480)
		self.centralwidget = QtGui.QWidget(MainWindow)
		self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
		self.gridLayout = QtGui.QGridLayout(self.centralwidget)
		self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
		self.button_file = QtGui.QPushButton(self.centralwidget)
		self.button_file.setObjectName(_fromUtf8("button_file"))
		self.gridLayout.addWidget(self.button_file, 3, 3, 1, 1)
		self.button_dir = QtGui.QPushButton(self.centralwidget)
		self.button_dir.setObjectName(_fromUtf8("button_dir"))
		self.gridLayout.addWidget(self.button_dir, 5, 3, 1, 1)
		self.title = QtGui.QLabel(self.centralwidget)
		self.title.setObjectName(_fromUtf8("title"))
		self.gridLayout.addWidget(self.title, 1, 1, 1, 2)
		self.label_dir = QtGui.QLabel(self.centralwidget)
		self.label_dir.setObjectName(_fromUtf8("label_dir"))
		self.gridLayout.addWidget(self.label_dir, 5, 1, 1, 1)
		spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem, 2, 0, 2, 1)
		self.zangieff = QtGui.QLabel(self.centralwidget)
		self.zangieff.setObjectName(_fromUtf8("zangieff"))
		spacerItem1 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem1, 2, 1, 1, 1)
		self.input_pathdir = QtGui.QLineEdit(self.centralwidget)
		self.input_pathdir.setObjectName(_fromUtf8("input_pathdir"))
		self.gridLayout.addWidget(self.input_pathdir, 6, 1, 1, 3)
		self.button_start = QtGui.QCommandLinkButton(self.centralwidget)
		self.button_start.setObjectName(_fromUtf8("button_start"))
		self.gridLayout.addWidget(self.button_start, 11, 2, 1, 1)
		spacerItem2 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem2, 10, 2, 1, 1)
		spacerItem3 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem3, 1, 4, 1, 1)
		self.input_pathfile = QtGui.QLineEdit(self.centralwidget)
		self.input_pathfile.setObjectName(_fromUtf8("input_pathfile"))
		self.gridLayout.addWidget(self.input_pathfile, 4, 1, 1, 3)
		self.label_file = QtGui.QLabel(self.centralwidget)
		self.label_file.setObjectName(_fromUtf8("label_file"))
		self.gridLayout.addWidget(self.label_file, 3, 1, 1, 1)
		self.label_nome = QtGui.QLabel(self.centralwidget)
		self.label_nome.setObjectName(_fromUtf8("label_nome"))
		self.gridLayout.addWidget(self.label_nome, 9, 1, 1, 1)
		self.input_nome = QtGui.QLineEdit(self.centralwidget)
		self.input_nome.setObjectName(_fromUtf8("input_nome"))
		self.gridLayout.addWidget(self.input_nome, 9, 2, 1, 1)
		MainWindow.setCentralWidget(self.centralwidget)
		self.menubar = QtGui.QMenuBar(MainWindow)
		self.menubar.setGeometry(QtCore.QRect(0, 0, 640, 25))
		self.menubar.setObjectName(_fromUtf8("menubar"))
		MainWindow.setMenuBar(self.menubar)
		self.statusbar = QtGui.QStatusBar(MainWindow)
		self.statusbar.setObjectName(_fromUtf8("statusbar"))
		MainWindow.setStatusBar(self.statusbar)

		self.retranslateUi(MainWindow)
		QtCore.QObject.connect(self.button_file, QtCore.SIGNAL(_fromUtf8("clicked()")), self.browser_file)
		QtCore.QObject.connect(self.button_dir, QtCore.SIGNAL(_fromUtf8("clicked()")), self.browser_dir)
		QtCore.QObject.connect(self.button_start, QtCore.SIGNAL(_fromUtf8("clicked()")), self.run)
		QtCore.QMetaObject.connectSlotsByName(MainWindow)

	def retranslateUi(self, MainWindow):
		MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow", None))
		self.button_file.setText(_translate("MainWindow", "File", None))
		self.button_dir.setText(_translate("MainWindow", "Dir", None))
		self.title.setText(_translate("MainWindow", "GUI do Bagaraio", None))
		self.label_dir.setText(_translate("MainWindow", "Diretório de saída", None))
		self.button_start.setText(_translate("MainWindow", "Roda, macaco!", None))
		self.label_file.setText(_translate("MainWindow", "Arquivo de entrada", None))
		self.label_nome.setText(_translate("MainWindow", "Nome", None))

	def browser_file(self):
		self.input_pathfile.setText(QtGui.QFileDialog.getOpenFileName())

	def browser_dir(self):
		self.input_pathdir.setText(QtGui.QFileDialog.getExistingDirectory())

	def run(self):
		pathfile = self.input_pathfile.text()
		if not os.path.isfile(pathfile):
			pathfile = None
		pathdir = self.input_pathdir.text()
		if not os.path.exists(pathdir) or os.path.isfile(pathdir):
			pathdir = None
		nome = self.input_nome.text().replace(" ", "")
		if not str(nome):
			none = None
		if pathfile and pathdir and nome:
			if Handler(str(pathfile), os.path.join(str(pathdir), str(nome))).run():
				self.gridLayout.addWidget(self.zangieff, 13, 2, 1, 2)
				self.zangieff.setText(_translate("MainWindow", "RO RO RO!", None))
		
