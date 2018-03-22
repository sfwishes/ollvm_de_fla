
import sys

from ida_allins import *
from ida_range import *
from ida_auto import *
from ida_bytes import *
from ida_dbg import *
from ida_diskio import *
from ida_entry import *
from ida_enum import *
from ida_expr import *
from ida_fixup import *
from ida_fpro import *
from ida_frame import *
from ida_funcs import *
from ida_gdl import *
from ida_graph import *
from ida_hexrays import *
from ida_ida import *
from ida_idaapi import *
from ida_idd import *
from ida_idp import *
from ida_kernwin import *
from ida_lines import *
from ida_loader import *
from ida_moves import *
from ida_nalt import *
from ida_name import *
from ida_netnode import *
from ida_offset import *
from ida_pro import *
from ida_problems import *
from ida_registry import *
from ida_search import *
from ida_segment import *
from ida_segregs import *
from ida_strlist import *
from ida_struct import *
from ida_typeinf import *
from ida_tryblks import *
from ida_ua import *
from ida_xref import *
from ida_idc import *

class idaapi_Cvar(object):
    def __init__(self):
        # prevent endless recursion
        object.__setattr__(self, "modules", "allins,range,auto,bytes,dbg,diskio,entry,enum,expr,fixup,fpro,frame,funcs,gdl,graph,hexrays,ida,idaapi,idd,idp,kernwin,lines,loader,moves,nalt,name,netnode,offset,pro,problems,registry,search,segment,segregs,strlist,struct,typeinf,tryblks,ua,xref,idc".split(","))
        object.__setattr__(self, "cvars_entries", dict())

    def _get_module_cvar(self, modname):
        mod = sys.modules["ida_%s" % modname]
        cv, entries = None, None
        if hasattr(mod, "cvar"):
            cv = getattr(mod, "cvar")
            entries = []
            if cv:
                if modname in self.cvars_entries.keys():
                    entries = self.cvars_entries[modname]
                else:
                    # Parse 'str' version of cvar. Although this is braindeader than
                    # braindead, I'm not sure there's another way to do it.
                    entries_s = str(cv)
                    entries = entries_s[1:len(entries_s)-1].split(", ")
                    self.cvars_entries[modname] = entries
        return cv, entries

    def __getattr__(self, attr):
        for mod in self.modules:
            cv, entries = self._get_module_cvar(mod)
            if cv and attr in entries:
                return getattr(cv, attr)

    def __setattr__(self, attr, value):
        for mod in self.modules:
            cv, entries = self._get_module_cvar(mod)
            if cv and attr in entries:
                setattr(cv, attr, value)


cvar = idaapi_Cvar()
