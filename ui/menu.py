import idaapi
import ida_kernwin
from ekko.ui.dialog.create_vm import VMCreateDialog
from ekko.ui.dialog.open_vm import VMOpenDialog

class MenuUI:
    ACTION_CREATE_VM    = "ekko:create_vm"
    ACTION_OPEN_VM      = "ekko:open_vm"

    def __init__(self, core):
        self.core = core

    def _install_create_vm(self):
        def handler():
            dialog = VMCreateDialog()
            dialog.exec_()

        act_name = self.ACTION_CREATE_VM
        act_desc = ida_kernwin.action_desc_t(
            act_name,                       # The action name. Must be unique
            "New Virtual Machine...",       # Action Text
            IDACtxEntry(handler),           # Action handler
            None,                           # Optional shortcut
            'Create new QEMU instance',     # Action tooltip
            -1                              # Icon
        )
        
        result = ida_kernwin.register_action(act_desc)
        assert result, f"Failed to register '{act_name}' action with IDA"

        result = ida_kernwin.attach_action_to_menu(
            'Ekko/',
            act_name,
            idaapi.SETMENU_APP
        )
        assert result, f"Failed action attach {act_name}"
    
    def _uninstall_create_vm(self):
        idaapi.unregister_action(self.ACTION_CREATE_VM)

    def _install_open_vm(self):
        def handler():
            dialog = VMOpenDialog()
            dialog.exec_()

        act_name = self.ACTION_OPEN_VM
        act_desc = ida_kernwin.action_desc_t(
            act_name,                           # The action name. Must be unique
            "Open...",       # Action Text
            IDACtxEntry(handler),     # Action handler
            None,                               # Optional shortcut
            'Open QEMU profile',         # Action tooltip
            -1                                  # Icon
        )

        result = ida_kernwin.register_action(act_desc)
        assert result, f"Failed to register '{act_name}' action with IDA"

        result = ida_kernwin.attach_action_to_menu(
            'Ekko/',
            act_name,
            idaapi.SETMENU_APP
        )
        assert result, f"Failed action attach {act_name}"
    
    def _uninstall_open_vm(self):
        idaapi.unregister_action(self.ACTION_OPEN_VM)

    def install(self):
        ida_kernwin.create_menu("Ekko", "Ekko")

        self._install_create_vm()
        self._install_open_vm()

    def uninstall(self):
        self._uninstall_create_vm()
        self._uninstall_open_vm()

class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS