import threading

from ekko.store.profile import ProfileStore

class StdioStore:
    lock = threading.Lock()

    @staticmethod
    def get_stdio_file(vm_name, offset=0):
        profile = ProfileStore.get_vm_profile(vm_name)

        with StdioStore.lock:
            with open(profile.stdio_file, "rb") as f:
                if offset:
                    f.seek(offset)
                return f.read()

    @staticmethod
    def update_stdio_file(vm_name, data):
        profile = ProfileStore.get_vm_profile(vm_name)

        with StdioStore.lock:
            with open(profile.stdio_file, "ab") as f:
                f.write(data)
    
    @staticmethod
    def truncate_stdio_file(vm_name):
        profile = ProfileStore.get_vm_profile(vm_name)

        with StdioStore.lock:
            open(profile.stdio_file, 'wb').close()
