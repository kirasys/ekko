#!/usr/bin/python
# coding: utf-8
#
# Ekko - by @kirasys
#

import os
import sys
import idaapi
import ida_kernwin

from ekko.core import EkkoCore
from ekko.ui.menu import MenuUI

# -----------------------------------------------------------------------
class EkkoPlugin(idaapi.plugin_t):
    PLUGNAME = "Ekko"

    flags = idaapi.PLUGIN_HIDE
    comment = ""
    help = ""
    wanted_name = PLUGNAME
    wanted_hotkey = ""

    def init(self):
        # Version check
        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or (int(kv[1]) < 6):
            ida_kernwin.warning(f"{self.PLUGNAME} need IDA version >= 7.6. Skipping")
            return idaapi.PLUGIN_SKIP
            
        try:
            self.core = EkkoCore()
            self.core.load()

            self.menu_ui = MenuUI(self.core)
            self.menu_ui.install()
        except Exception as e:
            ida_kernwin.warning(f"{self.PLUGNAME} : {str(e)}")
            return idaapi.PLUGIN_SKIP

        idaapi.msg(f"{self.PLUGNAME} initialized successfully.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ida_kernwin.warning(f"{self.PLUGNAME} cannot be run as a script in IDA.")

    def term(self):
        try:
            self.core.unload()
            self.menu_ui.uninstall()
        except Exception as e:
            ida_kernwin.warning(f"{self.PLUGNAME} : {str(e)}")
            
        idaapi.msg("{self.PLUGNAME} terminated\n")

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return EkkoPlugin()

# -----------------------------------------------------------------------