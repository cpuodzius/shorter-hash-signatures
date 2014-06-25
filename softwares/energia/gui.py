# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created: Sat May 31 01:29:09 2014
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

class Ui_Sembei(object):
	def setupUi(self, Sembei):
		Sembei.setObjectName(_fromUtf8("Sembei"))
		Sembei.resize(640, 480)
		self.centralwidget = QtGui.QWidget(Sembei)
		self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
		self.gridLayout = QtGui.QGridLayout(self.centralwidget)
		self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
		self.idle = QtGui.QDoubleSpinBox(self.centralwidget)
		self.idle.setMaximum(9999999.99)
		self.idle.setSingleStep(0.1)
		self.idle.setProperty("value", 1.2)
		self.idle.setObjectName(_fromUtf8("idle"))
		self.gridLayout.addWidget(self.idle, 11, 2, 1, 1)
		self.label_R = QtGui.QLabel(self.centralwidget)
		self.label_R.setObjectName(_fromUtf8("label_R"))
		self.gridLayout.addWidget(self.label_R, 10, 1, 1, 1)
		self.label_delta_t = QtGui.QLabel(self.centralwidget)
		self.label_delta_t.setObjectName(_fromUtf8("label_delta_t"))
		self.gridLayout.addWidget(self.label_delta_t, 12, 1, 1, 1)
		self.label_idle = QtGui.QLabel(self.centralwidget)
		self.label_idle.setObjectName(_fromUtf8("label_idle"))
		self.gridLayout.addWidget(self.label_idle, 10, 2, 1, 1)
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
		self.gridLayout.addWidget(self.zangieff, 16, 2, 1, 2)
		spacerItem1 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem1, 2, 1, 1, 1)
		self.input_pathfile = QtGui.QLineEdit(self.centralwidget)
		self.input_pathfile.setObjectName(_fromUtf8("input_pathfile"))
		self.gridLayout.addWidget(self.input_pathfile, 4, 1, 1, 3)
		self.button_start = QtGui.QCommandLinkButton(self.centralwidget)
		self.button_start.setObjectName(_fromUtf8("button_start"))
		self.gridLayout.addWidget(self.button_start, 14, 2, 1, 1)
		self.input_pathdir = QtGui.QLineEdit(self.centralwidget)
		self.input_pathdir.setObjectName(_fromUtf8("input_pathdir"))
		self.gridLayout.addWidget(self.input_pathdir, 6, 1, 1, 3)
		self.label_file = QtGui.QLabel(self.centralwidget)
		self.label_file.setObjectName(_fromUtf8("label_file"))
		self.gridLayout.addWidget(self.label_file, 3, 1, 1, 1)
		spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem2, 1, 4, 1, 1)
		self.label_nome = QtGui.QLabel(self.centralwidget)
		self.label_nome.setObjectName(_fromUtf8("label_nome"))
		self.gridLayout.addWidget(self.label_nome, 9, 1, 1, 1)
		self.input_nome = QtGui.QLineEdit(self.centralwidget)
		self.input_nome.setObjectName(_fromUtf8("input_nome"))
		self.gridLayout.addWidget(self.input_nome, 9, 2, 1, 1)
		self.resistencia = QtGui.QSpinBox(self.centralwidget)
		self.resistencia.setMaximum(999999)
		self.resistencia.setProperty("value", 100)
		self.resistencia.setObjectName(_fromUtf8("resistencia"))
		self.gridLayout.addWidget(self.resistencia, 11, 1, 1, 1)
		self.label_delta_v = QtGui.QLabel(self.centralwidget)
		self.label_delta_v.setObjectName(_fromUtf8("label_delta_v"))
		self.gridLayout.addWidget(self.label_delta_v, 12, 2, 1, 1)
		self.delta_t = QtGui.QDoubleSpinBox(self.centralwidget)
		self.delta_t.setMaximum(999999.0)
		self.delta_t.setProperty("value", 5.0)
		self.delta_t.setObjectName(_fromUtf8("delta_t"))
		self.gridLayout.addWidget(self.delta_t, 13, 1, 1, 1)
		self.delta_v = QtGui.QDoubleSpinBox(self.centralwidget)
		self.delta_v.setMaximum(999999.0)
		self.resistencia.setProperty("value", 100)
		self.delta_v.setProperty("value", 2.0)
		self.delta_v.setObjectName(_fromUtf8("delta_v"))
		self.gridLayout.addWidget(self.delta_v, 13, 2, 1, 1)
		Sembei.setCentralWidget(self.centralwidget)
		self.menubar = QtGui.QMenuBar(Sembei)
		self.menubar.setGeometry(QtCore.QRect(0, 0, 640, 25))
		self.menubar.setObjectName(_fromUtf8("menubar"))
		Sembei.setMenuBar(self.menubar)
		self.statusbar = QtGui.QStatusBar(Sembei)
		self.statusbar.setObjectName(_fromUtf8("statusbar"))
		Sembei.setStatusBar(self.statusbar)


		self.retranslateUi(Sembei)
		QtCore.QObject.connect(self.button_file, QtCore.SIGNAL(_fromUtf8("clicked()")), self.browser_file)
		QtCore.QObject.connect(self.button_dir, QtCore.SIGNAL(_fromUtf8("clicked()")), self.browser_dir)
		QtCore.QObject.connect(self.button_start, QtCore.SIGNAL(_fromUtf8("clicked()")), self.run)
		QtCore.QMetaObject.connectSlotsByName(Sembei)

	def retranslateUi(self, Sembei):
		Sembei.setWindowTitle(_translate("Sembei", "Sembei", None))
		self.label_R.setText(_translate("Sembei", "R (Ohms)", None))
		self.label_delta_t.setText(_translate("Sembei", "∆t (ms)", None))
		self.label_idle.setText(_translate("Sembei", "idle (mV)", None))
		self.button_file.setText(_translate("Sembei", "File", None))
		self.button_dir.setText(_translate("Sembei", "Dir", None))
		self.title.setText(_translate("Sembei", "Medição de Energia", None))
		self.label_dir.setText(_translate("Sembei", "Diretório de saída", None))
		#self.zangieff.setText(_translate("Sembei", "RO RO RO!", None))
		self.button_start.setText(_translate("Sembei", "Dá o play, macaco!", None))
		self.label_file.setText(_translate("Sembei", "Arquivo de entrada", None))
		self.label_nome.setText(_translate("Sembei", "Nome", None))
		self.label_delta_v.setText(_translate("Sembei", "∆V idle (mV)", None))

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
			res = float(self.resistencia.text())
			idleVolt = float(self.idle.text())
			tol = float(self.delta_v.text())
			tolT = float(self.delta_t.text())
			if Handler(str(pathfile), os.path.join(str(pathdir), str(nome))).run(res, idleVolt, tol, tolT):
				self.gridLayout.addWidget(self.zangieff, 13, 2, 1, 2)
				self.zangieff.setText(_translate("Sembei", "RO RO RO!", None))
