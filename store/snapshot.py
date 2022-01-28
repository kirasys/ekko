import os
import json

from ekko.store.profile import *

class SnapshotStore:
    SNAPSHOTS_INFO_FILE_NAME = 'snapshots_info.json'

    def __init__(self):
        pass

    @staticmethod
    def get_snapshots_info(vm_name):
        profile = get_vm_profile(vm_name)
        snapshot_info_path = os.path.join(profile.work_dir, SnapshotStore.SNAPSHOTS_INFO_FILE_NAME)

        if not os.path.isfile(snapshot_info_path):
            return {}

        with open(snapshot_info_path, 'r') as f:
            snapshots_info = json.load(f)
        return snapshots_info
    
    @staticmethod
    def create_snapshot_info(vm_name, **info):
        profile = get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)

        # Generate tag
        tag = f"{profile.vm_name}_{len(snapshots_info)}"
        info['tag'] = tag

        # Save to file
        snapshots_info[tag] = info

        with open(os.path.join(profile.work_dir, SnapshotStore.SNAPSHOTS_INFO_FILE_NAME), 'w') as f:
            json.dump(snapshots_info, f)

    @staticmethod
    def update_snapshot_info(vm_name, tag, **info):
        profile = get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)

        if tag in snapshots_info:
            snapshots_info[tag].update(info)

            with open(os.path.join(profile.work_dir, SnapshotStore.SNAPSHOTS_INFO_FILE_NAME), 'w') as f:
                json.dump(snapshots_info, f)

    @staticmethod
    def delete_snapshot_info(vm_name, tag):
        profile = get_vm_profile(vm_name)
        snapshots_info = SnapshotStore.get_snapshots_info(vm_name)
        
        if tag in snapshots_info:
            del snapshots_info[tag]

            with open(os.path.join(profile.work_dir, SnapshotStore.SNAPSHOTS_INFO_FILE_NAME), 'w') as f:
                json.dump(snapshots_info, f)

