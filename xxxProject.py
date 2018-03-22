import define
from define import flaFunc_type_common, flaFunc_type_aliSDK
from flaFunc import FlaFunc
from iosXXXFlaRecover import IOSXXXFlaRecover
from llvmIOSThumb2SymbolicExec import LLVMIOSThumb2SymbolicExec
from project import Project


class XXXProject(Project):
    def __init__(self, filename, offset):
        Project.__init__(self, filename, offset)
        self.flaFuncs = []
        self.symbolicExec = LLVMIOSThumb2SymbolicExec()
        self.flaRecover = None

    #funcs:[{"addr":0x1234, "type":"common"}, {"addr":0x2346, "type":"aliSDK", "table_start":0x3346, "table_end":0x3446}]
    def load_flaFuncs(self, funcs_heads):
        for func_head in funcs_heads:
            if func_head[define.flaFunc_param_type] == flaFunc_type_common:
                flaFunc = FlaFunc()
                flaFunc.load(func_head)
                self.flaFuncs.append(flaFunc)
            else:
                continue

    def load_file(self):
        origin = open(self.filename, 'rb')
        self.origin_data = list(origin.read())
        origin.close()

    def save(self, save_filename):
        recovery = open(save_filename, 'wb')
        recovery.write(''.join(self.origin_data))
        recovery.close()

        print 'Successful! The recovered file: %s' % (save_filename)

    def recover_flaFuncs(self):
        #symbolic exe
        self.symbolicExec.load(self.filename)
        self.symbolicExec.run_flaFuncs(self.flaFuncs)

        #fix
        self.flaRecover = IOSXXXFlaRecover(self.origin_data, self.base_offset)
        self.flaRecover.fix_fla_funcs(self.flaFuncs)

    def recover(self, save_filename):
        self.load_file()

        #do recover
        #flaFuncs
        self.recover_flaFuncs()

        self.save(save_filename)
