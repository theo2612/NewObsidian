#!/usr/bin/env python3
##
## -----------------------------------------------------------------
##    This file is part of WAPT Software Deployment
##    Copyright (C) 2012 - 2024  Tranquil IT https://www.tranquil.it
##    All Rights Reserved.
##
##    WAPT helps systems administrators to efficiently deploy
##    setup, update and configure applications.
## ------------------------------------------------------------------
##
import glob
import locale
import logging
import os
import platform
import shutil
import socket
import sys
import time
import psutil
import json
import ctypes
import base64
import chardet
from typing import Any, Optional, List, Union
from iniparse import RawConfigParser
from waptutils import (Version, __version__, all_files, dateof, currentdatetime,
                       currentdate, error, networking,
                       datetime2isodate, ensure_list, ensure_unicode,
                       fileisodate, find_all_files, get_disk_free_space,
                       hours_minutes, httpdatetime2isodate, isodate2datetime,
                       time2display, wget, wgets, makepath, killtree, isfile, isdir,
                       remove_file, mkdirs, get_main_ip, get_local_IPs,
                       killalltasks, isrunning, get_sha256, CustomZipFile,
                       run,run_notfatal,CalledProcessError,RunOutput,RunReader,listening_sockets,
                       TimeoutExpired,ensure_dir,
                       copytree2,default_skip,default_overwrite,default_oncopy,default_overwrite_older)

from urllib.request import getproxies

try:
    from waptlicences import rsa_encrypt,rsa_decrypt,x509_fingerprint,get_battery_infos
except ImportError:
    rsa_encrypt = None
    rsa_decrypt = None
    x509_fingerprint = None

    def get_battery_infos():
        return {}

__all__ = []

__all__.extend([
    'CalledProcessError',
    'Version',
    '__version__',
    'all_files',
    'application_data',
    'copytree2',
    'currentdate',
    'currentdatetime',
    'dateof',
    'datetime2isodate',
    'default_gateway',
    'default_oncopy',
    'default_overwrite',
    'default_overwrite_older',
    'default_skip',
    'dir_is_empty',
    'dmi_info',
    'ensure_dir',
    'ensure_list',
    'ensure_unicode',
    'error',
    'file_is_locked',
    'filecopyto',
    'fileisodate',
    'find_all_files',
    'find_processes',
    'get_battery_infos',
    'get_computer_groups',
    'get_computername',
    'get_current_user',
    'get_default_gateways',
    'get_disk_free_space',
    'get_dns_servers',
    'get_fqdn',
    'get_hostname',
    'get_host_architecture',
    'get_language',
    'get_last_logged_on_user',
    'get_local_IPs',
    'get_loggedinusers',
    'get_os_name',
    'get_main_ip',
    'get_os_version',
    'get_proxies',
    'get_sha256',
    'glob',
    'host_info',
    'host_info_networking',
    'host_metrics',
    'hours_minutes',
    'httpdatetime2isodate',
    'inifile_deleteoption',
    'inifile_deletesection',
    'inifile_hasoption',
    'inifile_hassection',
    'inifile_readstring',
    'inifile_writestring',
    'installed_softwares',
    'is64',
    'is32',
    'isARM',
    'isARM64',
    'isdir',
    'isfile',
    'isodate2datetime',
    'isrunning',
    'json_write_file',
    'json_load_file',
    'killalltasks',
    'killtree',
    'listening_sockets',
    'logger',
    'makepath',
    'mkdirs',
    'networking',
    'os',
    'processes_for_file',
    'remove_file',
    'remove_tree',
    'rsa_decrypt',
    'rsa_encrypt',
    'rsa_encrypt_data',
    'rsa_encrypted_data_str',
    'run',
    'run_notfatal',
    'running_on_ac',
    'service_list',
    'shell_launch',
    'shutil',
    'sys',
    'time',
    'time2display',
    'unzip',
    'user_home_directory',
    'wget',
    'wgets',
])


# Conditionnal imports for setuphelpers
if platform.system() == 'Windows':

    from setuphelpers_windows import get_file_properties,get_domain_fromregistry
    from setuphelpers_windows import *
    from waptutils import replace_at_next_reboot,delete_at_next_reboot,reg_closekey

    __all__.extend([
        'EnsureWUAUServRunning',
        'HKEY_CLASSES_ROOT',
        'HKEY_CURRENT_CONFIG',
        'HKEY_CURRENT_USER',
        'HKEY_LOCAL_MACHINE',
        'HKEY_USERS',
        'InstallerTypes',
        'KEY_ALL_ACCESS',
        'KEY_READ',
        'KEY_WRITE',
        'REG_SZ',
        'REG_MULTI_SZ',
        'REG_DWORD',
        'REG_QWORD',
        'REG_EXPAND_SZ',
        'REG_BINARY',
        'RunOutput',
        'RunReader',
        'TimeoutExpired',
        'WindowsVersions',
        'add_shutdown_script',
        'add_to_system_path',
        'add_user_to_group',
        'adjust_current_privileges',
        'battery_lifetime',
        'battery_percent',
        'bookmarks',
        'common_desktop',
        'create_daily_task',
        'create_desktop_shortcut',
        'create_group',
        'create_onetime_task',
        'create_programs_menu_shortcut',
        'create_shortcut',
        'create_user',
        'create_user_desktop_shortcut',
        'create_user_programs_menu_shortcut',
        'critical_system_pending_updates',
        'default_user_appdata',
        'default_user_local_appdata',
        'delete_at_next_reboot',
        'delete_group',
        'delete_task',
        'delete_user',
        'desktop',
        'disable_file_system_redirection',
        'disable_task',
        'enable_task',
        'fix_wmi',
        'get_all_scheduled_tasks',
        'get_antivirus_info',
        'get_app_install_location',
        'get_app_path',
        'get_appath',
        'get_computer_description',
        'get_computer_domain',
        'get_default_app',
        'get_domain_fromregistry',
        'get_file_properties',
        'get_file_association',
        'get_installer_defaults_win',
        'get_language_code',
        'get_local_profiles',
        'get_msi_properties',
        'get_powershell_str',
        'get_product_props',
        'get_profile_path',
        'get_profiles_users',
        'get_shortcut_properties',
        'get_service_start_mode',
        'get_task',
        'get_user_from_sid',
        'get_version_from_binary',
        'getsilentflags',
        'getscreens',
        'install_exe_if_needed',
        'install_location',
        'install_msi_if_needed',
        'installed_windows_updates',
        'InstallerTypes',
        'iswin64',
        'is_kb_installed',
        'is_pending_reboot',
        'list_local_printers',
        'local_admins',
        'local_desktops',
        'local_drives',
        'local_group_members',
        'local_group_memberships',
        'local_groups',
        'local_users',
        'local_users_profiles',
        'memory_status',
        'messagebox',
        'my_documents',
        'need_install',
        'pending_reboot_reasons',
        'programdata',
        'programfiles',
        'programfiles32',
        'programfiles64',
        'programs',
        'win32com_ensure_dispatch_patch',
        'reboot_machine',
        'recent',
        'reg_closekey',
        'reg_delvalue',
        'reg_delete_subkeys',
        'reg_enum_subkeys',
        'reg_enum_values',
        'reg_getvalue',
        'reg_key_exists',
        'reg_openkey_noredir',
        'reg_setvalue',
        'reg_value_exists',
        'register_dll',
        'register_ext',
        'register_uninstall',
        'register_windows_uninstall',
        'registered_organization',
        'registry_delete',
        'registry_deletekey',
        'registry_readstring',
        'registry_set',
        'registry_setstring',
        'add_netfirewallrule',
        'remove_netfirewallrule',
        'remove_appx',
        'remove_user_appx',
        'remove_desktop_shortcut',
        'remove_from_system_path',
        'remove_metroapp',
        'remove_printer',
        'remove_programs_menu_folder',
        'remove_programs_menu_shortcut',
        'remove_shutdown_script',
        'remove_user_desktop_shortcut',
        'remove_user_from_group',
        'remove_user_programs_menu_folder',
        'remove_user_programs_menu_shortcut',
        'replace_at_next_reboot',
        'run_as_administrator',
        'run_notfatal',
        'run_powershell',
        'run_powershell_from_file',
        'run_powershell_script',
        'run_task',
        'running_as_admin',
        'running_as_system',
        'sendto',
        'service_delete',
        'service_installed',
        'service_is_running',
        'service_is_stopped',
        'service_restart',
        'service_start',
        'service_stop',
        'set_computer_description',
        'set_environ_variable',
        'set_file_hidden',
        'set_file_visible',
        'set_service_start_mode',
        'showmessage',
        'shutdown_scripts_ui_visible',
        'start_menu',
        'startup',
        'system32',
        'systemdrive',
        'task_exists',
        'taskscheduler',
        'uac_enabled',
        'uninstall_cmd',
        'uninstall_key_exists',
        'unregister_dll',
        'unregister_uninstall',
        'unset_environ_variable',
        'user_appdata',
        'user_desktop',
        'user_local_appdata',
        'wait_uninstallkey_absent',
        'wait_uninstallkey_present',
        'win_startup_info',
        'wincomputername',
        'windomainname',
        'windows_version',
        'winshell',
        'wmi_as_struct',
        'wmi_info',
        'wmi_info_basic',
        'wua_agent_version',
        'getscreens',
        'pin_to_taskbar',
        'unpin_from_taskbar',
        'list_taskbar_pins',
    ])


else:
    # UNIX functions
    from setuphelpers_unix import get_domain_from_socket
    from setuphelpers_unix import *

    __all__.extend([
        'application_data',
        'default_gateway',
        'dmi_info',
        'get_computername',
        'get_computername',
        'get_current_user',
        'get_default_gateways',
        'get_dns_servers',
        'get_domain_from_socket',
        'get_domain_info',
        'get_file_properties',
        'get_groups',
        'get_kernel_version',
        'get_last_logged_on_user',
        'get_loggedinusers',
        'host_info_common_unix',
        'host_metrics',
        'is_valid_ipv4_address',
        'local_drives',
        'networking',
        'user_appdata',
        'user_local_appdata',
        'local_group_members',
        'local_group_memberships',
        'local_groups'
    ])

    if platform.system() == 'Darwin':

        from setuphelpers_macos import *

        __all__.extend([
            'brew_install',
            'brew_uninstall',
            'get_applications_info_files',
            'get_info_plist_path',
            'get_installed_pkgs',
            'get_pkg_info',
            'get_plist_obj',
            'install_app',
            'install_dmg',
            'install_pkg',
            'is_dmg_installed',
            'is_local_app_installed',
            'is_local_pkg_installed',
            'mount_dmg',
            'need_install',
            'uninstall_app',
            'uninstall_pkg',
            'unmount_dmg',
            'uninstall_key_exists',
            'get_release_name',
            'get_os_version'
        ])

    elif platform.system() == 'Linux':

        from setuphelpers_linux import get_distrib_version,get_hostname
        from setuphelpers_linux import *

        __all__.extend([
            'is_debian_based',
            'is_redhat_based',
            'is_rhel_based',
            'is_linux64',
            'isLinux64',
            'install_apt',
            'uninstall_apt',
            'install_deb',
            'purge_deb',
            'get_code_name_version',
            'get_distrib_version',
            'get_distrib_linux',
            'install_package_if_needed',
            'install_required_dependencies_apt',
            'autoremove_apt',
            'install_yum',
            'uninstall_yum',
            'autoremove_yum',
            'update_apt',
            'upgrade_apt',
            'update_yum',
            'upgrade_yum',
            'type_debian',
            'type_redhat',
            'install_rpm',
            'systemd_start_service',
            'systemd_stop_service',
            'systemd_restart_service',
            'systemd_status_service',
            'systemd_enable_start_service',
            'systemd_enable_service',
            'systemd_disable_service',
            'systemd_daemon_reload',
            'is_debian',
            'get_debian_version'
        ])

logger = logging.getLogger('waptcore')


def detect_file_encoding(file_path):
    """Detect the encoding of a file.

    Args:
        file_path (str): The path to the file to be analyzed.

    Returns:
        str: The detected character encoding of the file.

    >>> detect_file_encoding(file_path)
    'UTF-8-SIG'

    """
    with open(file_path, "rb") as file:
        raw_data = file.read()
        result = chardet.detect(raw_data)
        return result["encoding"]


def get_host_architecture():
    if isARM64():
        return "arm64"
    elif isARM():
        return "arm"
    elif is64():
        return "x64"
    elif is32():
        return "x86"


def user_home_directory():
    return os.path.expanduser("~")


def get_os_name():
    r"""Get the name of the current running operating system

    Returns:
        str: Windows, Linux, Darwin

    >>> get_os_name()
    'Windows'

    """
    return platform.system()


def json_load_file(json_file: str, encoding: str = "utf-8") -> Union[list, dict]:
    """Load content from a JSON file.

    Args:
        json_file: Path to the JSON file.
        encoding: File encoding.

    Returns:
        Loaded JSON content as a dictionary or a list.
    """
    with open(json_file, encoding=encoding) as read_file:
        return json.load(read_file)


def json_write_file(json_file: str, data: Union[list, dict], indent: int = 4, sort_keys: bool = False, encoding: str = "utf-8", newline: str = "\n"):
    """Write dictionary or list to a JSON file.

    Args:
        json_file: Path to the JSON file.
        data: Dictionary or list content to be written.
        indent: Tabulation size for indentation.
        sort_keys: Sort the keys alphabetically or not.
        encoding: File encoding.
        newline: Newline character(s) to use, default is Line Feed (LF).
    """
    with open(json_file, "w", encoding=encoding, newline=newline) as write_file:
        json.dump(data, write_file, sort_keys=sort_keys, indent=indent)


def get_proxies():
    r"""Return system proxy with the urllib python library

    >>> get_proxies()
    {'http': 'http://srvproxy.ad.domain.lan:8080',
    'https': 'http://srvproxy.ad.domain.lan:8080'}

    """
    return getproxies()


def get_language(full_locale=False, separator='_'):
    """Get the os default locale (example: fr, en, pl, etc.)

    >>> get_language()
    'fr'
    >>> get_language(full_locale=True)
    'fr_FR'
    >>> get_language(full_locale=True, separator='-').lower()
    'fr-fr'

    """
    if sys.platform == 'win32':
        lang = locale.windows_locale[ctypes.windll.kernel32.GetUserDefaultUILanguage()]
    else:
        lang = locale.getdefaultlocale()[0]
    if lang==None:
        lang='en_US'
    if full_locale:
        return lang.replace('_', separator)
    return lang.split('_')[0]


def filecopyto(filename: str, target: str):
    """Copy file from absolute or package temporary directory to target directory

    If file is dll or exe, logs the original and new version.

    Args:
        filename (str): absolute path to file to copy,
                        or relative path to temporary package install content directory.

        target (str) : absolute path to target directory where to copy file.

        target is either a full filename or a directory name
        if filename is .exe or .dll, logger prints version numbers

    >>> if not os.path.isfile('c:/tmp/fc.test'):
    ...     with open('c:/tmp/fc.test','wb') as f:
    ...         f.write('test')
    >>> if not os.path.isdir('c:/tmp/target'):
    ...    os.mkdir('c:/tmp/target')
    >>> if os.path.isfile('c:/tmp/target/fc.test'):
    ...    os.unlink('c:/tmp/target/fc.test')
    >>> filecopyto('c:/tmp/fc.test','c:/tmp/target')
    >>> os.path.isfile('c:/tmp/target/fc.test')
    True
    """
    if not filename or not os.path.isfile(filename):
        raise FileNotFoundError('filecopyto: Cannot copy file %s: file not found' % filename)
    if os.path.isdir(target):
        target = os.path.join(target, os.path.basename(filename))
    existing = os.path.isfile(target)
    action = 'Replacing' if existing else 'Copying'
    if os.path.splitext(target)[1] in ('.exe', '.dll'):
        try:
            nv = get_file_properties(filename)['FileVersion']
            if existing:
                ov = get_file_properties(target)['FileVersion']
                logger.info('%s %s (%s) -> %s' % (action, ensure_unicode(target), ov, nv))
            else:
                logger.info('%s %s (%s)' % (action, ensure_unicode(target), nv))
        except:
            logger.info('%s %s' % (action, target))
    else:
        logger.info('%s %s' % (action, target))
    shutil.copy(filename, target)


def dir_is_empty(path: str) -> bool:
    """Check if a directory is empty"""
    return isdir(path) and len(os.listdir(path)) == 0


def file_is_locked(path: str, timeout: int = 5) -> bool:
    """Check if a file is locked. waits timout seconds  for the release"""
    count = timeout
    while count > 0:
        try:
            f = open(path, 'ab')
            f.close()
            return False
        except IOError as e:
            if e.errno == 13:
                count -= 1
                if count < 0:
                    return True
                else:
                    print('Waiting for %s to be released...' % path)
                    time.sleep(1)
            else:
                raise
    return True



def shell_launch(cmd):
    """Launch a command (without arguments) but doesn't wait for its termination

    >>> with open('c:/tmp/test.txt','w') as f:
    ...     f.write('Test line')
    >>> shell_launch('c:/tmp/test.txt')
    """
    os.startfile(cmd)


def processes_for_file(filepath, open_files=True, dll=True):
    """Generator returning processes currently having a open file descriptor for filepath

    If not running as System account, can not access system processes.

    Args:
        filepath (str): file path or pattern (glob *)

    Returns:
        iterator psutil.Process

    """
    for process in psutil.process_iter():
        if dll:
            try:
                for dllproc in process.memory_maps():
                    if glob.fnmatch.fnmatch(dllproc.path, filepath):
                        yield process
                        break
            except Exception:
                # often : psutil.AccessDenied
                pass
        if open_files:
            try:
                for open_file in process.open_files():
                    if glob.fnmatch.fnmatch(open_file.path, filepath):
                        yield process
                        break
            except Exception:
                # often : psutil.AccessDenied
                pass


def find_processes(process_name):
    """Return list of Process names process_name

    Args:
        process_name (str): process name to lookup

    Returns:
        list: list of processes (Process) named process_name or process_name.exe

    >>> [p.pid for p in find_processes('explorer')]
    [2756, 4024]
    """
    process_name = process_name.lower()
    result = []
    for p in psutil.process_iter():
        try:
            if p.name().lower() in [process_name, process_name+'.exe']:
                result.append(p)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    return result


def get_domain():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_fromregistry()
    u'tranquilit.local'
    """
    if sys.platform == 'win32':
        return get_domain_fromregistry()
    elif sys.platform.startswith('linux'):
        return get_domain_from_socket()


def inifile_hasoption(inifilename: str, section: str, key: str) -> bool:
    """Check if an option is present in section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section
        key (str): value key to check

    Returns:
        boolean : True if the key exists

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    True
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','dontexist')
    False

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section) and inifile.has_option(section, key)


def inifile_hassection(inifilename: str, section: str) -> bool:
    """Check if an option is present in section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section

    Returns:
        boolean : True if the key exists

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hassection('c:/tranquilit/wapt/tests/test.ini','global')
    True

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    return inifile.has_section(section)


def inifile_deleteoption(inifilename: str, section: str, key: str):
    """Remove a key within the section of the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section
        key (str): value key of option to remove

    Returns:
        boolean : True if the key/option has been removed

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_hasoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    True
    >>> print inifile_deleteoption('c:/tranquilit/wapt/tests/test.ini','global','version')
    False

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    inifile.remove_option(section, key)
    with open(inifilename, 'w') as f:
        inifile.write(f)
    return inifile.has_section(section) and not inifile.has_option(section, key)

def is64():
    return platform.machine().endswith('64')

def is32():
    return platform.machine().endswith('86')

def isARM():
    return 'arm' in platform.machine().lower()

def isARM64():
    return 'aarch64' in platform.machine().lower()

def inifile_deletesection(inifilename: str, section: str):
    """Remove a section within the inifile

    Args:
        inifilename (str): Path to the ini file
        section (str): section to remove

    Returns:
        boolean : True if the section has been removed

    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    inifile.remove_section(section)
    with open(inifilename, 'w') as f:
        inifile.write(f)
    return not inifile.has_section(section)


def inifile_readstring(inifilename: str, section: str, key: str, default: Optional[str] = None):
    """Read a string parameter from inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.2')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.2
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','undefaut','defvalue')
    defvalue
    """

    inifile = RawConfigParser()
    inifile.read(inifilename)
    if inifile.has_section(section) and inifile.has_option(section, key):
        return inifile.get(section, key)
    else:
        return default


def inifile_writestring(inifilename: str, section: str, key: str, value: str):
    r"""Write a string parameter to inifile

    >>> inifile_writestring('c:/tranquilit/wapt/tests/test.ini','global','version','1.1.1')
    >>> print inifile_readstring('c:/tranquilit/wapt/tests/test.ini','global','version')
    1.1.1
    """
    inifile = RawConfigParser()
    inifile.read(inifilename)
    if not inifile.has_section(section):
        inifile.add_section(section)
    inifile.set(section, key, value)
    with open(inifilename, 'w') as f:
        inifile.write(f)


def get_fqdn():
    return ensure_unicode(get_hostname()) if os.name == 'nt' else ensure_unicode(socket.getfqdn()).lower()


def unzip(zipfn: str, target: Optional[str] = None, filenames: List[str] = None, extract_with_full_paths: bool = True):
    r"""Unzip the files from zipfile with patterns in filenames to target directory

    Args:
        zipfn (str) : path to zipfile. (can be relative to temporary unzip location of package)
        target (str) : target location. Defaults to dirname(zipfile) + basename(zipfile)
        filenames (str or list of str): list of filenames / glob patterns (path sep is normally a slash)
        extract_with_full_paths (bool): keeping or not the subfolders of the archive as is

    Returns:
        list : list of extracted files

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt')
    ['C:\\example\\tis-7zip_9.2.0-15_all\\7z920-x64.msi',
     'C:\\example\\tis-7zip_9.2.0-15_all\\7z920.msi',
     'C:\\example\\tis-7zip_9.2.0-15_all\\setup.py',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/control',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/wapt.psproj',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/manifest.sha256',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/signature']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', filenames=['*.msi','*.py'])
    ['C:\\example\\tis-7zip_9.2.0-15_all\\7z920-x64.msi',
     'C:\\example\\tis-7zip_9.2.0-15_all\\7z920.msi',
     'C:\\example\\tis-7zip_9.2.0-15_all\\setup.py']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', target='test', filenames=['*.msi','*.py'])
    ['C:\\example\\test\\7z920-x64.msi',
     'C:\\example\\test\\7z920.msi',
     'C:\\example\\test\\setup.py']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', filenames='WAPT/*')
    ['C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/control',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/wapt.psproj',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/manifest.sha256',
     'C:\\example\\tis-7zip_9.2.0-15_all\\WAPT/signature']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', filenames='WAPT/control')
    ['C:\\example\\tis-7zip_9.2.0-15_all\\WAPT\\control']

    >>> unzip('tis-7zip_9.2.0-15_all.wapt', target='.', filenames='WAPT/control')
    ['.\\WAPT\\control']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', target=r'C:\example\', filenames='WAPT/control')
    ['C:\\example\\WAPT\\control']

    >>> unzip('tis-7zip_9.2.0-15_all.wapt', target=basedir, filenames='WAPT/control')
    ['C:\\example\\WAPT\\control']

    >>> unzip(r'C:\example\tis-7zip_9.2.0-15_all.wapt', filenames='WAPT/control', extract_with_full_paths=False)
    ['C:\\example\\control']

    .. versionadded:: 1.3.11

    .. versionchanged:: 2.2
        added extract_with_full_paths parameter

    """
    if not zipfn or not os.path.isfile(zipfn):
        raise Exception('unzip: Invalid zip filename "%s"' % zipfn)
    zipf = CustomZipFile(zipfn, allowZip64=True)
    if target is None:
        target = makepath(os.path.dirname(os.path.abspath(zipfn)), os.path.splitext(os.path.basename(zipfn))[0])

    if filenames is not None:
        filenames = [pattern.replace('\\', '/') for pattern in ensure_list(filenames)]

    def match(fn, filenames):
        # return True if fn matches one of the pattern in filenames
        for pattern in filenames:
            if glob.fnmatch.fnmatch(fn, pattern):
                return True
        return False

    if filenames is not None:
        files = [fn for fn in zipf.namelist() if match(fn, filenames)]
        members = files
    else:
        files = zipf.namelist()
        members = None

    if sys.platform != 'darwin' and extract_with_full_paths:
        zipf.extractall(target, members)
    elif not extract_with_full_paths:
        files_to_extract = files
        files = []
        os.makedirs(target, exist_ok=True)
        for fn in files_to_extract:
            filename = os.path.basename(fn)
            # skip directories
            if not filename:
                continue

            # copy file (taken from zipfile's extract)
            source = zipf.open(fn)
            files.append(os.path.join(filename))
            with open(os.path.join(target, filename), "wb") as dest:
                with source, dest:
                    shutil.copyfileobj(source, dest)
    else: # the zipfile module doesn't support symlinks, and it's used in macOS packages
        try:
            members_str = " ".join('"{0}"'.format(m) for m in members) if members else ""
            unzip_cmd = 'unzip -qq {zipfile} {members_str} -d {destination_dir}'.format(
                                            zipfile=zipfn,
                                            members_str=members_str,
                                            destination_dir=target)
            run(unzip_cmd)
        except:
            print('Error : couldn\'t unzip {}'.format(zipfn))
            return []

    return [makepath(target, fn.replace('/', os.sep)) for fn in files]

def rsa_encrypt_data(txt: str, list_crt: List[str]):
    if not rsa_encrypt:
        raise Exception('rsa_encrypt function is not avalable in python waptlicences.pyd')
    if isinstance(list_crt, str):
        list_crt = [list_crt]
    dict_encrypt = {}
    for crt in list_crt:
        crt_files = None
        if os.path.isfile(crt):
            crt_files = [crt]
        elif os.path.isdir(crt):
            crt_files = glob.glob(os.path.join(crt, '*.crt'))
        if not crt_files:
            raise Exception("No .crt certificate file found in {} . Unable to encrypt data.".format(crt))
        for crt_file in crt_files:
            try:
                with open(crt_file,'rb') as f:
                    crt_pem = f.read()
                encrypttxt= rsa_encrypt(txt.encode('utf-8'),crt_pem)
                dict_encrypt[x509_fingerprint(crt_pem,'sha256')] = base64.b64encode(encrypttxt).decode('utf-8')
            except:
                pass
    if not dict_encrypt:
        raise Exception('No valid certificate provided to encrypt data')
    return dict_encrypt

def rsa_encrypted_data_str(txt: str, list_crt: List[str]):
    if rsa_encrypt:
        return '-----BEGIN WAPT ENCRYPTION-----' + json.dumps(rsa_encrypt_data(txt,list_crt)) + '-----END WAPT ENCRYPTION-----'
    else:
        return None

# Specific implicit names for install scripts
# declared here for automatic completion in PyScripter and VSCode
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from waptpackage import PackageEntry
    from common import Wapt

    control = PackageEntry # package currently installed, uninstalled, audited

    params = {} # persistent params goven as json string in command arguments
    force = False # if action has been launched
    WAPT = Wapt # core running Wapt instance
    language = 'en'
    user = 'nobody'
    usergroups = []
    persistent_source_dir = '' # <package-tmpdir>/WAPT/persistent or <package-waptdev>/WAPT/persistent
    persistent_dir = '' # <wapt>/private/persistent>/<package_uuid> of package being installed
    basedir = '' # base directory where package is unzipped (or <package-waptdev> if in dev mode)
    uninstallkey = [] # list of uninstall keys which will be stored in db for uninstall steps (windows)

if __name__ == '__main__':
    pass
