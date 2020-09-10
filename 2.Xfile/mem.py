#!/usr/bin/env
import sys
import os
import binascii
from openpyxl import Workbook
from openpyxl import load_workbook
from fval import ConVerter

class SymToMem(ConVerter):
    def __init__(self,symfile,memfile,ids=[]):
        #super(SymToMem,self).__init__(symfile)
        ConVerter.__init__(self,symfile)
        self.memfile = memfile
        #ids = [8,2,3]

        self.info = ConVerter.databuild(self,ids)

    def toMemaddress(self,symbol):
        mAddr = self.info[symbol][0]
        #print(type((mAddr)))
        if type(mAddr) == int:
            val = int(str(mAddr),base=16)
            #print(val)
        if type(mAddr) == str:
            #for i in range(len(mAddr)):
            #    val = val*16
            #    if '0' <= mAddr[i] <= '9':
            #        val = val+int(mAddr[i])
            #    if 'a' <= mAddr[i] <= 'f':
            #        tmp = ord(mAddr[i])-ord('a')+10
            #        val += tmp
            #    # in general, we don't have this case   
            #    if 'A' <= mAddr[i] <= 'F':
            #        tmp = ord(mAddr[i])-ord('A')+10
            #        val += tmp 
            val = int(mAddr,16)
            #print(type(val))    
            #print(val)
        #if type(mAddr) == int:
        #    val = mAddr
        return val
    
    def toMemSize(self,symbol):
        size = self.info[symbol][1]
        #print(size)
        if(type(size) == str):
            sz = int(size,16)
            return sz
        return size

    def toMemContent(self,mAddr,size):
        #a = self.info[mAddr][0]
        val = mAddr


        dd=[]
        filebin = open(self.memfile,mode='rb')
        #print(filebin)
        filebin.seek(val,0)
        #print(filebin.tell())
        dd = filebin.read(size)
        #for i in range(size):
        #    print(''),
        #    print('%x' % ord(dd[i])),

        filebin.close()
        #print(dd)
        #print(type(dd))
        return dd