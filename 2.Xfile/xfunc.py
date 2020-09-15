#!/usr/bin/env
import sys
import os
import binascii
import subprocess
import struct

from mainw import MainWindow
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QFileInfo,QEvent
from PyQt5.QtWidgets import QFileDialog

VERSION = "0.0.5"

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = MainWindow()
    MainWindow.show()
    sys.exit(app.exec_())
