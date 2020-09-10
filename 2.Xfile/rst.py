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


f = "sym.xlsx" 
m = 'dump.bin'
forsym = ['g_exc_desc_arr','s_exc_stat']
regsym = ['g_exc_svc_arr', \
        'g_exc_sys_arr', \
        'g_exc_reserve_arr', \
        'g_exc_abort_arr', \
        'g_exc_undef_arr']
RstReason = ['Data Abort', \
            'Address 0x0 Jump Exception', \
            "Prefech Abort ()", \
            'Undefined Instuction Abort (abort Mode)', \
            'TP_OS_ASSERT(0),assert failed (svc/sys Mode)', \
            'Thread stack overflow (SVC Mode)', \
            'unknown reason found !']

stack_flag = [0,0,0,0,0,0,0,4294967295]

def initialize(symfile,dumpfile):
    filename = symfile
    memfile  = dumpfile
    ids = [8,2,3]
    cvt = SymToMem(filename,memfile,ids)
    return cvt    

def get_symbol_meminfo(SymToMem,symbol,datatype=''):
    address = SymToMem.toMemaddress(symbol)
    size    = SymToMem.toMemSize(symbol)
    data = SymToMem.toMemContent(address,size)
    val = []
    if datatype == "U32":
        for i in range(size//4):
            #val += int(struct.unpack('I',data[i*4:(i*4+4)]))
            tmp = int.from_bytes(data[i*4:(i*4+4)],'little')
            #tmp = int(tmp,base=16)
            val.append(tmp)

    result = [address,size,val]
    return result

def print_mem(data,size,datatype=''):
    val = []
    if datatype == 'U32':
        for i in range(size//4):
            #print(i)
            val += struct.unpack('I',data[i*4:(i*4+4)])
    for i in range(size//4):
        print("0x%x " %val[i]),

def get_reset_reason(SymToMem):

    #symToaddr = cvt.databuild(ids)

    #address = SymToMem.toMemaddress(forsym[1])
    #size    = SymToMem.toMemSize(forsym[1])
    #data = SymToMem.toMemContent(address,size)

    #data = struct.unpack('I',data[:size])
    data = get_symbol_meminfo(SymToMem,forsym[1],'U32')

    rstval = data[2][0]
    if rstval != 205:
        reason = "not a reset"
        f = open('xfile.txt','w+')
        f.write('{:0>X}'.format(rstval)+"...not a reset...")
        f.close()
        print('No Reset found ...')
        exit(0) 

    #Step 2: find reset reason
    #address = SymToMem.toMemaddress(forsym[0])
    #size    = SymToMem.toMemSize(forsym[0])
    #data = SymToMem.toMemContent(address,size)
    #data = struct.unpack('III',data[0:size])
    ret = get_symbol_meminfo(SymToMem,forsym[0],'U32')
    print(ret)
    data = ret[2]
    if data[2] == 4:
        reason = RstReason[0]
    elif data[2] == 0:
        reason = RstReason[1]
    elif data[2] == 1:
        reason = RstReason[2]
    elif data[2] == 2:
        reason = RstReason[3]
    elif data[2] == 131:
        reason = RstReason[4]
    elif data[2] == 224:
        reason = RstReason[5]
    else:
        reason = "unknown reason found !"

    print("reset No. is %x : " % data[2]),
    print(reason)
    return reason

def get_CPU_registers(SymToMem):
    #g_exc_svc_arr
    usrval  = get_symbol_meminfo(SymToMem,regsym[0],'U32')
    #g_exc_reserve_arr
    usrresv = get_symbol_meminfo(SymToMem,regsym[2],'U32')
    print(usrval)
    print(usrresv)
    regs=[]
    #r0-r13
    print(rst_reason)
    for i in range(0,13):
        regs.append(usrresv[2][i]) 
    
    regs.append(usrval[2][0]) 
    regs.append(usrval[2][1])   

    if rst_reason == RstReason[0]:
        #g_exc_abort_arr
        abt = get_symbol_meminfo(SymToMem,regsym[3],'U32')
        print(abt)
        regs.append(abt[2][1]-8)     
    elif rst_reason == RstReason[2]:
        #g_exc_abort_arr
        abt = get_symbol_meminfo(SymToMem,regsym[3],'U32')
        print(abt)
        regs.append(usrval[2][1]-4) 
    elif rst_reason == RstReason[3]:
        #g_exc_abort_arr
        und = get_symbol_meminfo(SymToMem,regsym[4],'U32')
        print(und)
        regs.append(und[2][1]) 
    elif rst_reason == RstReason[4]:

        regs.append(usrval[2][1]) 
    else:

        regs.append(usrval[2][2])
    
    for i in range(len(regs)):
        print("Reg[%d] = 0x%x" %(i,regs[i]))
    return regs

def get_stack_content(SymToMem,spaddr):
    block =[0]
    size=0
    while block[size] != 4294967295 and size < 1000:
        #print(spaddr)
        data = SymToMem.toMemContent(spaddr,4)
        spaddr = spaddr+4
        #block += struct.unpack('I',data[:4])
        block.append(int.from_bytes(data,'little'))
        size = size+1
    
    return block[1:]

def get_callstack(stack,pc):
    func_addr = [pc]
    i = 0
    retline=[]
    if(os.path.isfile('addr2line.exe') == False):
        return("add2line not working")
    for i in range(len(stack)):
        if (stack[i]>72351744) and (stack[i]<73400320):
            func_addr.append(stack[i])
    print(func_addr)

    for i in range(len(func_addr)):
        execute = ['addr2line.exe','-e','L1860-MODEM.axf','-f','-s',hex(func_addr[i])]
        run = subprocess.Popen(execute,stdout=subprocess.PIPE,bufsize=0)
        out = run.communicate()
        retline.append(out)
        print(out)
        #for line in iter(run.stdout.readline, b''):
        #    print line,
    return retline

stm = initialize(f,m)

f = open('xfile.txt','w+')

rst_reason = get_reset_reason(stm)
f.write('-----------Reset Type-----------\n'+'\n')
f.write('Reason : '+rst_reason+'\n'+'\n'+'\n')
f.write('-----------Current Registers-----\n'+'\n')
Reg = get_CPU_registers(stm)
for i in range(len(Reg)):
    f.write("Reg["+'{:>2d}'.format(i)+"] = "+'0x'+'{:0>8x}'.format(Reg[i])+'\n' )
   

#content = stm.toMemContent(75747296,100)
#print_mem(content,100,"U32")
f.write('\n')
f.write('-----------Memory of Stack------------\n'+'\n')
cnt = get_stack_content(stm,Reg[13])
f.write('SP point at 0x%x : \n\n' %Reg[13])
for i in range(len(cnt)//4):
    f.write('0x'+'{0:0>8x} '.format(cnt[0+i*4]))
    f.write('0x'+'{0:0>8x} '.format(cnt[1+i*4]))
    f.write('0x'+'{0:0>8x} '.format(cnt[2+i*4]))
    f.write('0x'+'{0:0>8x} '.format(cnt[3+i*4]))
    f.write('\n')
for i in range(len(cnt) % 4):
    f.write('0x'+'{0:0>8x} '.format(cnt[len(cnt)//4*4+i]))
f.write('\n')
#run = get_callstack(cnt,72491386)
f.write('\n')
f.write('-----------Possible Callstack-----------\n'+'\n')
run = get_callstack(cnt,Reg[15])
print(run)
if run == "add2line not working":
    f.write(run)
    f.close()
    sys.exit(1)

for i in range(len(run)):
    f.write("%d : " %i),
    #f.write(run[i][0].replace('\r',''))
    f.write(run[i][0].decode().replace('\r',''))
f.write('\n---------------End of Xfile---------------\n')
f.close()

