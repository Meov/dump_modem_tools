# -*- coding: utf-8 -*-   
import tarfile
import os
import sys
import bz2
import re
import getopt

name_format = ".tar.bz2" #"tar.bz2" 
class BinCreat(object):

    def __init__(self,parent=None):
        self.file_path_source_entered = ""
        self.file_path_dest_entered = ""
        self.file_name_entered = ""

    def get_file_dir(self,file_dir_opt):
        if file_dir_opt:
            if not (os.path.isdir(file_dir_opt) or (os.path.exists(file_dir_opt))):
                print("you entered: %s cannot find!"%file_dir_opt)
                return
            else:
                file_dir = file_dir_opt
        else:
            file_dir = os.path.split(os.path.realpath(__file__))[0]#current path defualt
        return file_dir
    
    def files_name_get(self,file_dir):   
        target_file=[]   
        name_str = ""
       
        has_tar_file = False
        for files in os.listdir(file_dir):  
            if ((name_str in files) and (name_format in files)):   #ensure "name" and "name_format" are included in the file
                #print("name:"+name+"file+"+files)
                file_ = files.split('-',2)
                target_file.append( file_[0]+'-'+file_[1])  #get data string name
                has_tar_file = True
        if not has_tar_file:
            print("path :%s has no dumped file-----> end up with %s"%(file_dir,name_format))
            #exit(0)
        return list(set(target_file))   #duplicate removal
        
    def sort_key(self,s):
        if s:
            try:
                suffix = re.search('\\d+$', s)
                num = int(suffix.group())
            except:
                num = -1
            return num
 
    def file_extract(self,file_source_dir,target_name,file_target_dir):
        for files_ in os.listdir(file_source_dir):
            if ((str(target_name) in files_) and (name_format in files_)):
                data_to_extrat = os.path.join(file_source_dir,files_)
                bin_file_path = data_to_extrat.replace('\\','/')  
                print(bin_file_path)  
                try:
                    tar = tarfile.open(data_to_extrat,"r:*",encoding='utf-8')
                except IOError as e:
                    print(e)
                    exit(1)
                tar.extractall(path=file_target_dir)
                file_target_path = os.path.join(file_target_dir,tar.getnames()[0])
                tar.close()
                file_data_save = os.path.join(file_target_dir,target_name+'.bin')
                #open file and write files at the end  
                #ref：https://blog.51cto.com/14320361/2486142
                with open(file_data_save,'ab') as f:   #Open a file in binary format and change the file to append mode
                    f.write(open(file_target_path,'rb').read())  #Reads a file in binary format and writes it to the destination folder 
                os.remove(file_target_path)

    def binary_file_name_get(self,file_path_source_entered):
        self.file_path_source_entered = file_path_source_entered 
        if (os.path.isdir(self.file_path_source_entered)):
            files_names = self.files_name_get(self.file_path_source_entered)   #get names
            return files_names
        return

    def binary_file_create(self,file_source_dir,file_path_dest,file_name): 
        self.file_extract(file_source_dir,file_name,file_path_dest)
        