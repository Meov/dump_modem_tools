
pre-check:

1> dump.bin及L1860-MODEM.axf为必须提供的必要文件
2> 使用前，请确认同目录下，addr2line.exe和readelf.exe存在，工具方可正常运行

usage:

1>首先生成sym.xlsx：
	ASF->SelectFile,选择asf文件，然后选择ASF->ToSymsTbl载入readelf.exe，
	当输出“new symbols file generated!”，应当生成sym.xlsx文件
2>载入addr2line文件:
	Add2line->selectExe,载入addr2line.exe

3>载入刚生成的symbol file：
	浏览->载入sym.xlsx

4>载入dump file：
	浏览->载入dump.bin

5>点击button，生成Xfile

输出界面，应当生成相关crash现场。