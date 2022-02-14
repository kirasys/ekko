import json

from ekko.store.profile import ProfileStore
from ekko.utils import generate_random_hexstring

class SnapshotStore:

    @staticmethod
    def get_snapshots_info(vm_name):
        profile = ProfileStore.get_vm_profile(vm_name)

        with open(profile.snapshots_info_file, 'r') as f:
            return json.load(f)
    
    @staticmethod
    def create_snapshot_info(vm_name, **info):
        profile = ProfileStore.get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)

        # Generate tag
        info['tag'] = tag = generate_random_hexstring()

        # Save to file
        snapshots_info[tag] = info

        with open(profile.snapshots_info_file, 'w') as f:
            json.dump(snapshots_info, f, indent=4)

    @staticmethod
    def update_snapshot_info(vm_name, tag, **info):
        profile = ProfileStore.get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)

        if tag in snapshots_info:
            snapshots_info[tag].update(info)

            with open(profile.snapshots_info_file, 'w') as f:
                json.dump(snapshots_info, f, indent=4)

    @staticmethod
    def delete_snapshot_info(vm_name, tag):
        profile = ProfileStore.get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)
        
        if tag in snapshots_info:
            del snapshots_info[tag]

            with open(profile.snapshots_info_file, 'w') as f:
                json.dump(snapshots_info, f, indent=4)