#!/usr/bin/env
import sys
import os
import binascii
import subprocess
import struct

from openpyxl import Workbook
from openpyxl import load_workbook
from fval import ConVerter
from mem import SymToMem


def print_mem(data,size,datatype=''):
    val = []
    if datatype == 'U32':
        for i in range(size//4):
            #print(i)
            val += struct.unpack('I',data[i*4:(i*4+4)])
    for i in range(size//4):
        print("0x%x " %val[i]),

if len(sys.argv)<2:
    filename = "sym.xlsx"    
else:
    filename = sys.argv[1]
print(filename)

memfile = 'dump.bin'
#if(sys.argv[3]!=''):
#    memfile = sys.argv[2]
#else:
#    memfile = 'dump.bin'

if len(sys.argv)==4:
    forsym = sys.argv[3]
else:
    forsym = 'g_exc_desc_arr'
print(type(forsym))

#key: val1,val2
ids = [8,2,3]
cvt = SymToMem(filename,memfile,ids)
#symToaddr = cvt.databuild(ids)
address = cvt.toMemaddress(forsym)
size    = cvt.toMemSize(forsym)
data = cvt.toMemContent(address,size)
print_mem(data,size,'U32')
logdata = cvt.toMemContent(73345792,size)
print_mem(logdata,size,'U32')
#for i in range(len(data)):


#cvt.toMemContent('04588c3c',364)

#execute = ['addr2line.exe','-e','L1860-MODEM.axf','-f',str(address)]

#run = subprocess.Popen(execute)


#print data

