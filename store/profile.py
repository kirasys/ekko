import os
import json
import copy

PROFILE_FILE_NAME        = 'vm.profile'
LOG_FILE_NAME            = 'log.txt'
SNAPSHOTS_INFO_FILE_NAME = 'snapshots_info.json'
STDIO_FILE_NAME          = 'stdio.txt'

class VMProfile:
    def __init__(self, profile=None):
        if profile is None:
            profile = {}
        self.profile = copy.deepcopy(profile)
    
    def update(self, new_profile):
        self.profile.update(new_profile)

    def save(self):
        with open(os.path.join(self.profile['work_dir'], PROFILE_FILE_NAME), 'w') as f:
            json.dump(self.profile, f, indent=4)

    ################## VM Configuration ##################
    @property
    def work_dir(self):
        if 'work_dir' not in self.profile:
            return None
        return self.profile['work_dir']

    @work_dir.setter
    def work_dir(self, vm_path):
        self.profile['work_dir'] = vm_path
    
    @property
    def qemu_path(self):
        if 'qemu_path' not in self.profile:
            return None
        return self.profile['qemu_path']

    @qemu_path.setter
    def qemu_path(self, qemu_binary_path):
        self.profile['qemu_path'] = qemu_binary_path
    
    @property
    def vm_name(self):
        if 'vm_name' not in self.profile:
            return None
        return self.profile['vm_name']
    
    @vm_name.setter
    def vm_name(self, name):
        self.profile['vm_name'] = name

    @property
    def os_type(self):
        if 'os_type' not in self.profile:
            return None
        return self.profile['os_type']
    
    @os_type.setter
    def os_type(self, os_type_):
        self.profile['os_type'] = os_type_
    
    ################## Hardware ##################
    @property
    def cpu_architecture(self):
        if 'cpu_architecture' not in self.profile:
            return None
        return self.profile['cpu_architecture']

    @cpu_architecture.setter
    def cpu_architecture(self, cpu):
        self.profile['cpu_architecture'] = cpu

    @property
    def number_of_processors(self):
        if 'number_of_processors' not in self.profile:
            return None
        return self.profile['number_of_processors']
    
    @number_of_processors.setter
    def number_of_processors(self, processors):
        self.profile['number_of_processors'] = processors
    
    @property
    def memory_capacity(self):
        if 'memory_capacity' not in self.profile:
            return None
        return self.profile['memory_capacity']
    
    @memory_capacity.setter
    def memory_capacity(self, memory):
        self.profile['memory_capacity'] = memory

    @property
    def disk_capacity(self):
        if 'disk_capacity' not in self.profile:
            return None
        return self.profile['disk_capacity']
    
    @disk_capacity.setter
    def disk_capacity(self, disk):
        self.profile['disk_capacity'] = disk
    
    @property
    def disk_file(self):
        if 'disk_file' not in self.profile:
            return None
        return self.profile['disk_file']
    
    @disk_file.setter
    def disk_file(self, disk):
        self.profile['disk_file'] = disk
    
    @property
    def cdrom(self):
        if 'cdrom' not in self.profile:
            return ""
        return self.profile['cdrom']
    
    @cdrom.setter
    def cdrom(self, cdrom_path):
        self.profile['cdrom'] = cdrom_path
    
    ################## Advanced Configuration ##################
    @property
    def acceleration(self):
        if 'acceleration' not in self.profile:
            return None
        return self.profile['acceleration']

    @acceleration.setter
    def acceleration(self, accel):
        self.profile['acceleration'] = accel
    
    ################## Logging ##################
    @property
    def log_level(self):
        if 'log_level' not in self.profile:
            return None
        return self.profile['log_level']

    @log_level.setter
    def log_level(self, level):
        self.profile['log_level'] = level

    @property
    def log_file(self):
        if 'log_file' not in self.profile:
            return None
        return self.profile['log_file']

    @log_file.setter
    def log_file(self, filepath):
        self.profile['log_file'] = filepath
    
    ################## Debug ##################

    @property
    def stdio_file(self):
        if 'stdio_file' not in self.profile:
            return None
        return self.profile['stdio_file']

    @stdio_file.setter
    def stdio_file(self, filepath):
        self.profile['stdio_file'] = filepath

    ################## Snapshot ##################

    @property
    def snapshots_info_file(self):
        if 'snapshots_info_file' not in self.profile:
            return None
        return self.profile['snapshots_info_file']

    @snapshots_info_file.setter
    def snapshots_info_file(self, filepath):
        self.profile['snapshots_info_file'] = filepath

class ProfileStore:
    profiles = {}

    @staticmethod
    def create_vm_profile(**profile):
        profile = VMProfile(profile)
        ProfileStore.profiles[profile.vm_name] = profile
        
        # create an empty log file
        profile.log_file = os.path.join(profile.work_dir, LOG_FILE_NAME)
        open(profile.log_file, 'w').close()

        # create an empty stdio file
        profile.snapshots_info_file = os.path.join(profile.work_dir, SNAPSHOTS_INFO_FILE_NAME)
        with open(profile.snapshots_info_file, 'w') as f:
            f.write("{}")
        
        # create an empty stdio file
        profile.stdio_file = os.path.join(profile.work_dir, STDIO_FILE_NAME)
        open(profile.stdio_file, 'wb').close()

        profile.save()

    @staticmethod
    def read_vm_profile(work_dir_):
        with open(os.path.join(work_dir_, PROFILE_FILE_NAME), 'r') as f:
            profile = VMProfile(json.load(f))
            profile.work_dir = work_dir_

        profile.save()

        ProfileStore.profiles[profile.vm_name] = profile
        return profile

    @staticmethod
    def update_vm_profile(vm_name, **new_profile):
        ProfileStore.profiles[vm_name].update(new_profile)
        ProfileStore.profiles[vm_name].save()

    @staticmethod
    def get_vm_profile(vm_name):
        if vm_name in ProfileStore.profiles:
            return ProfileStore.profiles[vm_name]

