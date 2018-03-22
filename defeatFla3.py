import idaapi
import idautils
import idc
from define import *
from xxxProject import XXXProject

filename = 'xxx'
output = 'xxx_recovered4'

project = XXXProject(filename, 0x4000)
flaFuncs = []
flaFunc1 = {}
flaFunc1[flaFunc_param_addr] = 0x76556C
flaFunc1[flaFunc_param_type] = flaFunc_type_common
flaFuncs.append(flaFunc1)
project.load_flaFuncs(flaFuncs)
project.recover(output)
