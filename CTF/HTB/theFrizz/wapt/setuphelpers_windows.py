#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
import codecs
import types
import ctypes
import datetime
import glob
import logging
import msilib
import os
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import json
import base64
import tempfile
import pyedid
import getpass
from typing import Literal

from ctypes import wintypes

import pythoncom
import pywintypes
import win32com
import win32com.client
from win32com.shell import shell, shellcon
from win32com.taskscheduler import taskscheduler
from win32com.client import GetObject
from waptutils import (Version, makepath, isfile, isdir, killalltasks, CalledProcessErrorOutput,
                       remove_file, currentdate, ensure_dir, _lower, ini2winstr,
                       error, find_all_files, get_main_ip, get_local_IPs, networking,
                       run, run_notfatal, ensure_unicode, ensure_list
                       )

# registry
from waptutils import ( reg_openkey_noredir,reg_delvalue,reg_enum_subkeys, reg_delete_subkeys,
                        reg_enum_values,reg_setvalue,reg_getvalue,reg_key_exists,reg_value_exists)

import xml.etree.ElementTree as ET

# import only for windows
import winreg
import active_directory
import keyfinder
import netifaces
import psutil
import win32api
import win32con
import win32gui
import win32net
import win32netcon
import win32print
import win32process
import win32security
import win32service
import win32serviceutil
import winshell
from iniparse import RawConfigParser

try:
    from waptlicences import uptime,pin_to_taskbar,unpin_from_taskbar,list_taskbar_pins
except ImportError:
    uptime = None
    pin_to_taskbar=None
    unpin_from_taskbar=None
    list_taskbar_pins=None

try:
    import wmi
except:
    wmi = None

_cache_dict_user_from_sid={}

logger = logging.getLogger('waptcore')


# be sure to be able to load win32api.pyd dll
dlls = [os.path.join(os.path.dirname(__file__), dllloc) for dllloc in ['DLLs', r'lib\site-packages\win32', '']]
dlls.append(os.environ['PATH'])
os.environ['PATH'] = os.pathsep.join(dlls)

# common windows diectories
desktop = winshell.desktop
application_data = winshell.application_data
bookmarks = winshell.bookmarks
start_menu = winshell.start_menu
programs = winshell.programs
startup = winshell.startup
my_documents = winshell.my_documents
recent = winshell.recent
sendto = winshell.sendto

###########
# root key
HKEY_CLASSES_ROOT = winreg.HKEY_CLASSES_ROOT
HKEY_CURRENT_USER = winreg.HKEY_CURRENT_USER
HKEY_LOCAL_MACHINE = winreg.HKEY_LOCAL_MACHINE
HKEY_USERS = winreg.HKEY_USERS
HKEY_CURRENT_CONFIG = winreg.HKEY_CURRENT_CONFIG

# Access modes when opening registry keys
KEY_WRITE = winreg.KEY_WRITE
KEY_READ = winreg.KEY_READ
KEY_ALL_ACCESS = winreg.KEY_ALL_ACCESS

# Types of value
REG_SZ = winreg.REG_SZ
REG_MULTI_SZ = winreg.REG_MULTI_SZ
REG_DWORD = winreg.REG_DWORD
REG_QWORD = winreg.REG_QWORD
REG_EXPAND_SZ = winreg.REG_EXPAND_SZ
REG_BINARY = winreg.REG_BINARY

# aliases
wincomputername = win32api.GetComputerName
windomainname = win32api.GetDomainName


GetSystemPowerStatus = ctypes.windll.kernel32.GetSystemPowerStatus

GetSystemPowerStatus.restype = wintypes.BOOL

_computername_expire = None
_computername = None

_hostname_expire = None
_controler_domain_ip = None
_controler_domain_ip_expire = None
_hostname = None
_fake_hostname = None

_dns_cache_ttl = 10*60  # ttl in secs for caching hostname
_dns_sid_ttl = 10*60

# be sure to be able to load win32apu.pyd dll
dlls = [os.path.join(os.path.dirname(__file__), dllloc) for dllloc in ['DLLs', r'lib\site-packages\win32', '']]
dlls.append(os.environ['PATH'])
os.environ['PATH'] = os.pathsep.join(dlls)


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ('ACLineStatus', wintypes.BYTE),
        ('BatteryFlag', wintypes.BYTE),
        ('BatteryLifePercent', wintypes.BYTE),
        ('Reserved1', wintypes.BYTE),
        ('BatteryLifeTime', wintypes.DWORD),
        ('BatteryFullLifeTime', wintypes.DWORD),
    ]


SYSTEM_POWER_STATUS_P = ctypes.POINTER(SYSTEM_POWER_STATUS)
GetSystemPowerStatus.argtypes = [SYSTEM_POWER_STATUS_P]

###############################################################

def add_netfirewallrule(
    rule_name,
    app_path,
    group=None,
    direction="Inbound",
    profile=None,
    enabled=True,
    action="Allow",
    protocol=None,
):
    """
    Add a Windows Firewall rule using New-NetFirewallRule cmdlet in PowerShell for Windows 10 and newer,
    or netsh advfirewall for older Windows versions.

    https://learn.microsoft.com/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior
    https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule

    Args:
        rule_name (str): Display name for the firewall rule.
        app_path (str): Path to the program for which the rule is being created.
        group (str, optional): Group name for the firewall rule (only works with PowerShell).
        direction (str): Direction of the rule (Inbound or Outbound). Default: Inbound.
        profile (str or list, optional): Profile(s) to which the rule should apply (e.g., "Domain,Private"). Default: Any.
        enabled (bool): Specify if the created rule's state is Enabled (True) or not (False). Default: True.
        action (str): Action for the rule (Allow or Block). Default: Allow.
        protocol (str, optional): Protocol by name or number (e.g., "TCP", "UDP", "ICMPv4", or "ICMPv6"). Default: Any.

    Returns:
        waptutils.RunOutput: The result of the command execution.

    .. versionadded:: 2.5

    """
    if not isinstance(profile, list):
        profile = ensure_list(profile)
    profile = ",".join(profile)

    message = f"Adding Firewall Rule: {rule_name}"
    if direction:
        message += f" ({direction})"
    if protocol:
        message += f" ({protocol})"
    if action:
        message += f" ({action})"
    print(message)
    if windows_version() < WindowsVersions.Windows10:
        direction = "out" if direction.lower() == "Outbound".lower() else "in"
        enabled = "no" if not enabled else "yes"
        cmd_command = f'netsh advfirewall firewall add rule name="{rule_name}" dir={direction} action={action} program="{app_path}" enable={enabled}'
        if profile:  # any and all are working
            cmd_command += f' profile="{profile}"'
        if protocol:
            cmd_command += f' protocol="{protocol}"'
        result = run_notfatal(cmd_command)
    else:
        pwsh_command = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction {direction} -Action {action} -Program "{app_path}" -Enabled {str(enabled)}'
        )
        if group:
            pwsh_command += f' -Group "{group}"'
        if profile:
            pwsh_command += f' -Profile "{profile}"'
        if protocol:
            pwsh_command += f' -Protocol "{protocol}"'
        result = run_powershell(pwsh_command, output_format="text")

    return result


def remove_netfirewallrule(rule_name):
    """
    Remove Windows Firewall rule using New-NetFirewallRule cmdlet in PowerShell for Windows 10 and newer,
    or netsh advfirewall for older Windows versions.

    Args:
        rule_name (str): Display name of the firewall rule to remove.

    Returns:
        waptutils.RunOutput: The result of the command execution.

    .. versionadded:: 2.5

    """
    print(f"Removing Firewall Rule: {rule_name}")
    if windows_version() < WindowsVersions.Windows10:
        result = run_notfatal(f'netsh advfirewall firewall delete rule name="{rule_name}"')
    else:
        result = run_powershell(
            f'Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue', output_format="text", accept_returncodes=[0, 1, 3010]
        )

    return result


def get_os_version():
    return windows_version()


def get_powershell_str(powershell_cmd: str, value: str = None) -> str:
    r"""Get a value as string from the output of a powershell command
    WARNING: Adding -AllUsers parameter may be necessary to make sure WAPT is enable to get the request value

    Args:
        powershell_cmd (str): Powershell command
        value (str)         : Value to get as string

    .. versionadded:: 2.2

    """
    # we catch stderr as there is progress infos we don't need.
    err = []
    if value:
        return str(run_powershell('$ProgressPreference = "SilentlyContinue"\n%s | Select-Object -ExpandProperty %s | Write-Host -NoNewline' % (powershell_cmd, value), output_format='text', return_stderr=err))
    else:
        return str(run_powershell('$ProgressPreference = "SilentlyContinue"\n%s | Write-Host -NoNewline' % powershell_cmd, output_format='text', return_stderr=err))


def running_as_system():
    """Dirty way to check if current process is running as system user
    """
    user = getpass.getuser()
    return user.endswith('$') and user[:-1].upper() == get_computername().upper()


def remove_appx(package, default_user=True):
    """Remove Windows AppX package from the computer environment, excluding NonRemovable packages.

    Args:
        package (str): AppX package name. You can use an asterisk (*) as a wildcard.
        default_user (bool): Remove AppX package from the Windows image to prevent installation for new users.

    .. versionadded:: 2.2

    .. versionchanged:: 2.5
        No longer try to remove NonRemovable AppX package

    """
    if running_as_admin() or running_as_system():
        if default_user:
            run_powershell(
                f'Get-AppXProvisionedPackage -Online | Where-Object DisplayName -Like "{package}" | Remove-AppxProvisionedPackage -Online -AllUsers',
                output_format="text",
            )
        run_powershell(
            r'Get-AppxPackage -Name "%s" -AllUsers | Where-Object {{ -not ($_.NonRemovable) }} | Remove-AppxPackage -AllUsers' % package,
            output_format="text",
        )
    else:
        run_powershell(r'Get-AppxPackage -Name "%s" | Where-Object {{ -not ($_.NonRemovable) }} | Remove-AppxPackage' % package, output_format="text")


def remove_user_appx(package):
    r"""Remove Windows AppX package from user environment, excluding NonRemovable packages.

    Args:
        package (str): AppX Package name, asterisk character (*) can be used as wildcard

    .. versionadded:: 2.3

    """
    run_powershell(r'Get-AppxPackage -Name "%s" | Where-Object {{ -not ($_.NonRemovable) }} | Remove-AppxPackage' % package, output_format="text")


def get_language_code():
    r"""Return the current Windows language code

    Returns:
        integer

    >>> get_language_code()
    1036

    """
    return ctypes.windll.kernel32.GetUserDefaultUILanguage()


def is_kb_installed(hotfixid):
    r"""Check whether the Windows KB is installed

    Returns:
        boolean

    >>> is_kb_installed('3216755')
    True
    >>> is_kb_installed('KB3216755')
    True

    """
    if not hotfixid.upper().startswith('KB'):
        hotfixid = 'KB' + hotfixid
    installed_update = installed_windows_updates()
    if [kb for kb in installed_update if kb['HotFixID'].upper() == hotfixid.upper()]:
        return True
    return False


def is_pending_reboot():
    r"""Check whether operating system is on pending reboot

    Returns:
        boolean

    >>> is_pending_reboot()
    True

    """
    if reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') or \
        reg_key_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') or \
        reg_value_exists(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager', 'PendingFileRenameOperations') or \
        reg_value_exists(HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\Session Manager', 'PendingFileRenameOperations2') or \
        reg_value_exists(HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Updates', 'UpdateExeVolatile'):
        return True
    return False


def get_file_association(ext):
    r"""Return the associated application for a file extension (example : '.doc')

    >>> get_file_association('.pptx')
    'LibreOffice.Pptx'

    """
    try:
        return winreg.QueryValue(winreg.HKEY_CLASSES_ROOT, ext)
    except:
        return None


def get_default_app(suffix):
    r"""Return application path associated to a file extension (example: .pptx)

    >>> get_default_app('.pptx')
    'C:\\Program Files\\LibreOffice\\program\\simpress.exe'

    """
    try:
        class_root = winreg.QueryValue(winreg.HKEY_CLASSES_ROOT, suffix)
    except:
        return None
    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r'{}\shell\open\command'.format(class_root)) as key:
        command = winreg.QueryValueEx(key, '')[0]
        return shlex.split(command)[0]


def set_service_start_mode(service_name, start_mode, change_state=True, raise_error=False):
    r"""Changing start mode of a service and changing his running status accordingly
    Usable values: 'Auto', 'Manual', 'Disabled'
    Informations: https://msdn.microsoft.com/en-us/library/aa384896(v=vs.85).aspx

    .. versionchanged:: 2.2
        Now interact on the running state
    .. versionchanged:: 2.5
        Add raise_error flag

    """
    if not service_installed(service_name):
        if raise_error:
            error(f'"{service_name}" service is not installed.')
        else:
            print(f'WARNING: "{service_name}" service is not installed, skipped.')
            return
    to_start = False
    to_stop = False
    if start_mode == "Auto":
        start_mode = "Automatic"
        to_start = True
    elif start_mode == "Disabled" or start_mode == "Manual":
        to_stop = True
    elif start_mode == "Boot" or start_mode == "System":
        # Handle driver services but it do not seems to work
        pass
    else:
        raise Exception("Start mode value specified is incorrect")

    try:
        c = wmi.WMI()
        for svc in c.Win32_Service(Name=service_name):
            if svc.StartMode != start_mode:
                svc.ChangeStartMode(StartMode=start_mode)
                if to_start and change_state:
                    if not service_is_running(service_name):
                        try:
                            service_start(service_name)
                        except:
                            print("Unable to start the service: %s" % service_name)
                elif to_stop and change_state:
                    if service_is_running(service_name):
                        try:
                            service_stop(service_name)
                        except:
                            print("Unable to stop the service: %s" % service_name)
    except Exception as e:
        if raise_error:
            # WMI is broken...
            error('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))
        else:
            print('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))


def get_service_start_mode(service_name):
    r"""Getting actual start mode of a service
    Returned values: 'Auto', 'Manual', 'Disabled'

    """
    c = wmi.WMI()
    for svc in c.Win32_Service(Name=service_name):
        return svc.StartMode


def iswin64():
    """Check whether operating system is 64bits

    Returns:
        boolean

    >>> iswin64()
    True
    """

    # could be
    # return platform.machine()=='AMD64'
    # wapt runs as win32 process. If windows system is win64, IsWow64Process is True
    return win32process.IsWow64Process()
    # return 'PROGRAMW6432' in os.environ and 'ProgramFiles(x86)' in os.environ and os.environ['PROGRAMW6432'] != os.environ['ProgramFiles(x86)']


def get_all_scheduled_tasks(enable_only=False):
    scheduler = win32com_ensure_dispatch_patch("Schedule.Service")

    scheduler.Connect()
    objTaskFolder = scheduler.GetFolder("\\")
    colTasks = objTaskFolder.GetTasks(1)

    dict_tasks = {}

    for task in colTasks:
        if enable_only:
            if task.Enabled == False:
                continue
        dict_tasks[task.Name] = {'Name': task.Name,
                                 'Enabled': task.Enabled,
                                 'LastRunTime': task.LastRunTime,
                                 'LastTaskResult': task.LastTaskResult,
                                 'NextRunTime': task.NextRunTime,
                                 'NumberOfMissedRuns': task.NumberOfMissedRuns,
                                 'State': task.State,
                                 'Path': task.Path}

    return dict_tasks


class disable_file_system_redirection(object):
    r"""Context manager to disable temporarily the wow3264 file redirector

    >>> with disable_file_system_redirection():
    ...     winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
    u'C:\\Program Files (x86)'
    """
    if iswin64():
        _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    else:
        _disable = None
        _revert = None

    def __enter__(self):
        if self._disable:
            self.old_value = ctypes.c_long()
            self.success = self._disable(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self._revert and self.success:
            self._revert(self.old_value)


def system32() -> str:
    r"""returns the path of system32directory

    Returns:
        str: path to system32 directory

    >>> print(system32())
    C:\WINDOWS\system32

    """
    return win32api.GetSystemDirectory()


def set_file_visible(path: str):
    """Unset the hidden attribute of file located at path

    Utility function for shutdown gpo script

    Args:
        path (str): path to the file
    """
    set_file_hidden(path, hidden=False)

def set_file_hidden(path: str, hidden: bool = True):
    """Set the hidden attribute of file located at path
    Utility function for shutdown gpo script

    Args:
        path (str): path to the file
        hidden (bool): Whether the hidden attribute must be set or not
    """
    FILE_ATTRIBUTE_HIDDEN = 0x02
    old_att = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if hidden:
        ret = ctypes.windll.kernel32.SetFileAttributesW(str(path), old_att | FILE_ATTRIBUTE_HIDDEN)
    else:
        ret = ctypes.windll.kernel32.SetFileAttributesW(str(path), old_att & ~FILE_ATTRIBUTE_HIDDEN)
    if not ret:
        raise ctypes.WinError()

def is_file_hidden(path: str) -> bool:
    FILE_ATTRIBUTE_HIDDEN = 0x02
    ret = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if ret == -1:
        raise ctypes.WinError()
    return bool(ret & FILE_ATTRIBUTE_HIDDEN)


def programfiles64():
    """Return 64 bits program folder

    Warning: This function is evaluated once at module load (see __CallableStr usages)

    >>> programfiles64
    'C:\\Program Files'
    """
    if 'PROGRAMW6432' in os.environ:
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']


def programfiles():
    """Return native program directory, ie C:\Program Files for both 64 and 32 bits

    Warning: This function is evaluated once at module load (see __CallableStr usages)
    """
    # return winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
    if 'PROGRAMW6432' in os.environ:
        return os.environ['PROGRAMW6432']
    else:
        return os.environ['PROGRAMFILES']


def programfiles32():
    """Return 32bits applications folder.

    Warning: This function is evaluated once at module load (see __CallableStr usages)

    Returns:
        str: path of programs files (x86) (on win64) or programs files (on 32bits)

    >>> programfiles32
    'C:\\Program Files (x86)'
    """
    if 'PROGRAMW6432' in os.environ and 'PROGRAMFILES(X86)' in os.environ:
        return os.environ['PROGRAMFILES(X86)']
    else:
        return os.environ['PROGRAMFILES']


def programdata():
    """Return ProgramData folder

    Warning: This function is evaluated once at module load (see __CallableStr usages)

    >>> programdata
    'C:\\ProgramData'
    """
    return os.environ['PROGRAMDATA']


def systemdrive():
    """Return System drive

    Warning: This function is evaluated once at module load (see __CallableStr usages)

    >>> systemdrive
    'C:'
    """
    return os.environ['SYSTEMDRIVE']


class __CallableStr(str):
    """A string which can be called or not...
       to preserve packages compatibility.
    """
    def __call__(self):
        return self

# some const - DO NOT ADD SIMILAR FUNCTIONS
# kept here for backward compatibility
programfiles = __CallableStr(programfiles())
programfiles32 = __CallableStr(programfiles32())
programfiles64 = __CallableStr(programfiles64())
programdata = __CallableStr(programdata())
systemdrive = __CallableStr(systemdrive())


def remove_from_system_path(path):
    r"""Remove a path from the global search PATH environment variable if it is set"""
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", sam=KEY_READ | KEY_WRITE) as key:
        system_path = reg_getvalue(key, "Path").split(";")
        if path.lower() in [p.lower() for p in system_path] or path.lower() + "\\" in [p.lower() for p in system_path]:
            for p in system_path:
                if p.lower() == path.lower() or p.lower() == path.lower() + "\\":
                    system_path.remove(p)
                    break
            reg_setvalue(key, "Path", ";".join(system_path), type=REG_EXPAND_SZ)
            win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000)
    return system_path


def set_environ_variable(name, value, type=REG_EXPAND_SZ, user=False):
    r"""Add or update a system wide persistent environment variable

    .>>> set_environ_variable('WAPT_HOME','c:\\wapt')
    .>>> import os
    .>>> os.environ['WAPT_HOME']
    'c:\\wapt'
    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE if not user else HKEY_CURRENT_USER, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' if not user else r'Environment',
                             sam=KEY_READ | KEY_WRITE) as key:
        reg_setvalue(key, name, value, type=type)
    # force to get new environ variable, as it is not reloaded immediately.
    os.environ[name] = value
    win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000)


def user_local_appdata():
    r"""Return the local appdata profile of current user

    Returns:
        str: path like u'C:\\Users\\user\\AppData\\Local'
    """
    return ensure_unicode((winshell.get_path(shellcon.CSIDL_LOCAL_APPDATA)))


def get_current_user():
    r"""Get the login name for the current user.

    >>> get_current_user()
    u'htouvet'
    """
    import ctypes
    MAX_PATH = 260                  # according to a recent WinDef.h
    name = ctypes.create_unicode_buffer(MAX_PATH)
    namelen = ctypes.c_int(len(name))  # len in chars, NOT bytes
    if not ctypes.windll.advapi32.GetUserNameW(name, ctypes.byref(namelen)):
        raise ctypes.WinError()
    return ensure_unicode(name.value)


def get_domain_fromregistry():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_fromregistry()
    u'tranquilit.local'
    """
    if _fake_hostname is not None:
        host_domain = _fake_hostname.split('.', 1)
        if len(host_domain) > 1:
            return host_domain[1]

    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
    try:
        (domain, atype) = winreg.QueryValueEx(key, 'NV Domain')
        if domain == '':
            (domain, atype) = winreg.QueryValueEx(key, 'Domain')
        if domain == '':
            (domain, atype) = winreg.QueryValueEx(key, 'DhcpDomain')
    except:
        try:
            (domain, atype) = winreg.QueryValueEx(key, 'DhcpDomain')
        except:
            domain = None
    return domain


def get_hostname():
    """Return host fully qualified domain name in lower case

    If a main domain is set in registry, use this domain (faster)
    If not, use value returned from main connection (ie DHCP)

    Result is cached because Windows 10 is sometimes slow to return when there are multiple network interfaces.
    """
    global _fake_hostname
    global _hostname
    global _hostname_expire

    if _fake_hostname is not None:
        return _fake_hostname

    # Use
    nv_hostname = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\Tcpip\Parameters', 'NV Hostname')

    domain = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\Tcpip\Parameters', 'NV Domain')

    if not domain :
        domain = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History', 'NetworkName', None)

    if nv_hostname and domain:
        return '%s.%s' % (nv_hostname.lower(), domain.lower())

    if _hostname is None or time.time() >= _hostname_expire:
        _hostname = socket.getfqdn().lower()
        if not '.' in _hostname:
            try:
                domain = win32security.DsGetDcName().get('DomainName', None)
            except:
                pass
            if domain:
                _hostname = _hostname + '.' + domain
        _hostname_expire = time.time() + _dns_cache_ttl
    return _hostname


def installed_windows_updates(**queryfilter):
    """Return list of installed updates, indepently from WUA agent
        Example :
             [...
             {u'CSName': u'WSDCARDON',
              u'Caption': u'http://support.microsoft.com/?kbid=3207752',
              u'Description': u'Security Update',
              u'FixComments': u'',
              u'HotFixID': u'KB3207752',
              u'InstallDate': None,
              u'InstalledBy': u'TRANQUILIT\\dcardon-adm',
              u'InstalledOn': u'12/28/2016',
              u'Name': None,
              u'ServicePackInEffect': u'',
              u'Status': None}
             ...]

    Args:
        queryfilter (dict)

    Returns:
        list

    .. versionadded:: 1.3.3

    """
    try:
        return wmi_as_struct(wmi.WMI().Win32_QuickFixEngineering.query(**queryfilter))
    except Exception as e:
        # WMI is broken...
        logger.critical('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))
        return None


def wmi_info(keys=['Win32_ComputerSystem',
                   'Win32_ComputerSystemProduct',
                   'Win32_BIOS',
                   'Win32_NetworkAdapter',
                   'Win32_Printer',
                   'Win32_VideoController',
                   'Win32_LogicalDisk',
                   'Win32_OperatingSystem',
                   'Win32_DesktopMonitor',
                   # 'Win32_FloppyController',
                   # 'Win32_IDEController',
                   # 'Win32_SCSIController',
                   # 'Win32_InfraredDevice',
                   'Win32_USBController',
                   # 'Win32_1394Controller',
                   # 'Win32_PCMCIAController',
                   # 'CIM_LogicalDevice',
                   'Win32_DiskDrive',
                   'Win32_Volume'],
             exclude_subkeys=['OEMLogoBitmap'], **where):
    """Get WMI machine informations as dictionaries

    """
    result = {}
    if wmi:
        try:
            wm = wmi.WMI()
            for key in keys:
                try:
                    wmiclass = getattr(wm, key)
                    if where:
                        cs = wmiclass.query(**where)
                    else:
                        cs = wmiclass()
                    if len(cs) > 1:
                        na = result[key] = []
                        for cs2 in cs:
                            na.append({})
                            for k in cs2.properties.keys():
                                if not k in exclude_subkeys:
                                    prop = cs2.wmi_property(k)
                                    if prop:
                                        na[-1][k] = prop.Value
                    elif len(cs) > 0:
                        result[key] = {}
                        if cs:
                            for k in cs[0].properties.keys():
                                if not k in exclude_subkeys:
                                    prop = cs[0].wmi_property(k)
                                    if prop:
                                        result[key][k] = prop.Value
                except Exception as e:
                    logger.warning('error reading WMI key %s : %s' % (key,ensure_unicode(e)))

        except Exception as e:
            # WMI is broken...
            logger.critical('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))

    return result


def wmi_as_struct(wmi_object, exclude_subkeys=['OEMLogoBitmap']):
    """Convert a wmi object to a simple python list/dict structure"""
    result = []
    if wmi_object :
        na = result = []
        for cs2 in wmi_object:
            na.append({})
            for k in cs2.properties.keys():
                if not k in exclude_subkeys:
                    prop = cs2.wmi_property(k)
                    if prop:
                        na[-1][k] = prop.Value
    return result

def wmi_info_basic():
    """Return uuid, serial, model, vendor from WMI

    Returns:
        dict: minimal informations for wapt registration

    >>> r = wmi_info_basic()
    >>> 'System_Information' in r
    True
    """
    try:
        result = {'System_Information':
                  wmi_as_struct(wmi.WMI().Win32_ComputerSystemProduct.query(fields=['UUID', 'IdentifyingNumber', 'Name', 'Vendor']))
                  }
    except Exception as e:
        # WMI is broken...
        logger.critical('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))
        result = {'System_Information':
                    [{'UUID': '', 'IdentifyingNumber': '', 'Name': '', 'Vendor': ''}]}
    return result


def default_gateway():
    """Returns default ipv4 current gateway"""
    gateways = netifaces.gateways()
    if gateways:
        default_gw = gateways.get('default', None)
        if default_gw:
            default_inet_gw = default_gw.get(netifaces.AF_INET, None)
        else:
            default_inet_gw = None
    if default_inet_gw:
        return default_inet_gw[0]
    else:
        return None


def host_info():
    """Read main workstation informations, returned as a dict

    Returns:
        dict: main properties of host, networking and windows system

    .. versionchanged:: 1.4.1
         returned keys changed :
           dns_domain -> dnsdomain

    >>> hi = host_info()
    >>> 'computer_fqdn' in hi and 'connected_ips' in hi and 'computer_name' in hi and 'mac' in hi
    True
    """
    global _controler_domain_ip
    global _controler_domain_ip_expire
    info = {}
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', 'srvcomment')

    #info['serial_nr'] = dmi_info.get('System_Information',{}).get('Serial_Number','')
    info['system_manufacturer'] = registry_readstring(HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemManufacturer')
    info['system_productname'] = registry_readstring(HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\BIOS', 'SystemProductName')

    global _fake_hostname
    if _fake_hostname is not None:
        info['computer_name'] = get_computername()
    else:
        info['computer_name'] = ensure_unicode(wincomputername())
    info['computer_fqdn'] = ensure_unicode(get_hostname())

    info['workgroup_name'] = ensure_unicode(windomainname())
    info['monitors'] = getscreens()

    #disable for antivirus probleme
    #info['antivirus'] = get_antivirus_info()

    info['domain_name'] = get_domain_fromregistry()
    info['domain_controller'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History', 'DCName', None)

    if info['domain_controller']:
        if _controler_domain_ip is None or time.time() >= _controler_domain_ip_expire:
            try:
                info['domain_controller_address'] = '\\\\' + str(socket.gethostbyname(info['domain_controller'].rsplit('\\')[-1]))
            except:
                info['domain_controller_address'] = ""
            _controler_domain_ip = info['domain_controller_address']
            _controler_domain_ip_expire = time.time() + _dns_cache_ttl
        else:
            info['domain_controller_address'] = _controler_domain_ip
    else:
        info['domain_controller_address'] = None
    info['domain_info_source'] = 'history'

    info['win64'] = iswin64()
    info['description'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', 'srvcomment')

    info['registered_organization'] = ensure_unicode(registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'RegisteredOrganization'))
    info['registered_owner'] = ensure_unicode(registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'RegisteredOwner'))
    info['windows_version'] = windows_version()
    info['windows_version_full'] = windows_version(members_count=4)
    info['windows_product_infos'] = keyfinder.windows_product_infos()
    info['os_version'] = windows_version()
    info['windows_version_prettyname'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'DisplayVersion')
    info['windows_version_releaseid'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ReleaseId')

    if not info['windows_version_releaseid']:
        if Version(windows_version(),3) == Version('10.0.10240',3):
            info['windows_version_releaseid'] = "1507"
        if Version(windows_version(),3) == Version('10.0.10586',3):
            info['windows_version_releaseid'] = "1511"

    if not info['windows_version_prettyname']:
        info['windows_version_prettyname'] = info['windows_version_releaseid']
    info['os_release_name'] = info['windows_version_prettyname']
    info['windows_version_ubr'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR')
    info['os_name'] = keyfinder.windows_product_infos()['version']

    if windows_version() >= WindowsVersions.Windows11 :
        info['os_name'] = info['os_name'].replace('indows 10', 'indows 11')
        info['windows_product_infos']["os_name"] = info['os_name']

    info['installation_date'] = datetime.datetime.fromtimestamp(int(registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'InstallDate', '0'))).isoformat()

    info['uac_level'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA')

    info['cpu_name'] = registry_readstring(HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0', 'ProcessorNameString', '').strip()
    info['cpu_identifier'] = registry_readstring(HKEY_LOCAL_MACHINE, r'HARDWARE\DESCRIPTION\System\CentralProcessor\0', 'Identifier', '').strip()

    info['profiles_users'] = get_profiles_users()
    info['local_profiles'] = get_local_profiles()
    info['local_administrators'] = local_admins()
    info['local_groups'] = {g: local_group_members(g) for g in local_groups()}
    info['local_users'] = local_users()
    info['platform'] = platform.system()

    info['windows_startup_items'] = win_startup_info()

    info['wua_agent_version'] = wua_agent_version()

    # empty if computer is not in a AD domain... status from last gpupdate
    # could be win32api.GetComputerObjectName(1) if computer is connected to network
    info['computer_ad_dn'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine', 'Distinguished-Name')
    info['computer_ad_site'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine', 'Site-Name')

    info['environ'] = {k: ensure_unicode(v) for k, v in os.environ.items()}

    return info

def host_info_networking():
    info = {}
    # networking infos
    info['interfaces'] = networking()

    try:
        info['gateways'] = get_default_gateways()
        info['dns_servers'] = get_dns_servers()
    except:
        info['gateways'] = [default_gateway()]

    info['dnsdomain'] = ensure_unicode(get_domain_fromregistry())

    info['connected_ips'] = get_local_IPs()
    list_mac = {}
    for c in info['interfaces']:
        if 'mac' in c and 'addr' in c:
            for m in c['addr']:
                if m['addr'] in info['connected_ips']:
                    list_mac[c['mac']] = None

    info['mac'] = list(list_mac)
    info['main_ip'] = get_main_ip()
    return info

def get_user_from_sid(sid, controller=None,fallback_profpath=True):
    """Returns domain\\user for the given sid
    sid is either a string or a PySID
    """
    global _cache_dict_user_from_sid
    if sid in _cache_dict_user_from_sid and time.time() < _cache_dict_user_from_sid[sid]['expire'] :
        return _cache_dict_user_from_sid[sid]['samaccountname']
    try:
        if isinstance(sid, pywintypes.SIDType):
            pysid = sid
        else:
            if not(isinstance(sid, str)):
                sid = str(sid)
            pysid = win32security.ConvertStringSidToSid(sid)
        name, domain, type = win32security.LookupAccountSid(controller, pysid)
        username= "%s\\%s" % (domain, name)
    except win32security.error as e:
        _cache_dict_user_from_sid[sid]={"samaccountname":"","expire": time.time() + _dns_sid_ttl}
        if not fallback_profpath:
            raise
        logger.debug('Unable to GET username from SID %s : %s, using profile directory instead' % ("%s" % sid, e))
        # try from directory
        username=get_user_from_profpath(sid)

    _cache_dict_user_from_sid[sid]={"samaccountname":username,"expire": time.time() + _dns_sid_ttl}

    return username

def list_local_printers():
    """Return a list of local printers
    .. versionadded:: 1.7.1
    """
    return json.dumps(win32print.EnumPrinters(2))


def remove_printer(name):
    """Remove a printer by its name

    Args:
        name (str) : name of local printer to be deleted

    .. versionadded:: 1.7.1

    >>> remove_printer('Brother QL-1060')
    """
    try:
        if name in list_local_printers():
            print('Deleting local printer : %s' % name)
            run('"RUNDLL32" printui.dll,PrintUIEntry /n "%s" /dl' % name)
        else:
            error('Printer %s does not exists on this computer' % name)
    except Exception as e:
        logger.critical('Error deleting printer : %s' % ensure_unicode(e))


def battery_percent():
    """Return battery level in percent

    .. versionadded:: 1.4.2

    """
    status = SYSTEM_POWER_STATUS()
    if not GetSystemPowerStatus(ctypes.pointer(status)):
        raise ctypes.WinError()
    return status.BatteryLifePercent


def uac_enabled():
    """Return True if UAC is enabled

    .. versionadded:: 1.3.9

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') as k:
        return winreg.QueryValueEx(k, 'EnableLUA')[1] == 0


def running_on_ac():
    """Return True if computer is connected to AC power supply

    .. versionadded:: 1.3.9

    """
    status = SYSTEM_POWER_STATUS()
    if not GetSystemPowerStatus(ctypes.pointer(status)):
        raise ctypes.WinError()
    return status.ACLineStatus == 1


def battery_lifetime():
    """Return battery life in seconds

    .. versionadded:: 1.4.2

    """
    status = SYSTEM_POWER_STATUS()
    if not GetSystemPowerStatus(ctypes.pointer(status)):
        raise ctypes.WinError()
    return status.BatteryLifeTime


def run_powershell(cmd: str, output_format : Literal['json', 'text', 'xml'] = 'json', **kwargs):
    """Run a command/script (possibly multiline) using powershell, return output in text format
    If format is 'json', the result is piped to ConvertTo-Json and converted back to a python dict for convenient use

    WARNING: This works only with powershell >= 3

    Args:
        output_format (str): set output format as json (default) or xml (ElementTree object) or text

    Returns:
        str or dict or list

    .. versionadded:: 1.3.9
    """
    if output_format not in ('json','text','xml'):
        raise ValueError("Input parameter output_format not correct (json/text/xml expected: %s" % output_format)

    ps_path = makepath(system32(),'WindowsPowerShell','v1.0','powershell.exe')

    output_version = run('"%s" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command "$PSVersionTable.PSVersion.Major"' % ps_path).strip()

    try:
        if int(output_version)<3 :
            raise Exception('run_powershell need powershell version >=3, please install tis-powershell package first')
    except:
        pass

    cmd = ensure_unicode(cmd)

    if output_format == 'json':
        output_format_ps = 'text'
        cmd = '$ProgressPreference = "SilentlyContinue"\n%s  | ConvertTo-Json ' % cmd
    else:
        output_format_ps = output_format
    # command is a utf16 without bom encoded with base64 without \n
    # we should not get stderr so that ouput can be decoded as json. stderr get progress report...
    try:
        with disable_file_system_redirection():
            cmd = '"%s" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -OutputFormat %s -EncodedCommand "%s" ' %  (ps_path, output_format_ps,  base64.b64encode(cmd.encode('utf-16le')).decode('utf-8'))
            logger.debug("running powershell command : \n%s" % cmd)
            result = run(cmd,
                         **kwargs)
    except CalledProcessErrorOutput as e:
        raise CalledProcessErrorOutput(e.returncode, cmd, e.output)

    # remove comments...
    if output_format.lower() == 'xml':
        lines = [l for l in result.splitlines() if not l.strip().startswith('#') and l.strip()]
        import xml.etree.ElementTree as ET
        return ET.fromstringlist(lines)
    elif output_format.lower() == 'json':
        lines = [l for l in ensure_unicode(result).splitlines() if not l.strip().startswith('#')]
        if not lines:
            return None
        else:
            try:
                return json.loads('\n'.join(lines))
            except ValueError as e:
                raise ValueError('%s returned non json data:\n%s\n%s' % (cmd, result, e))
    else:
        return result


def run_powershell_from_file(file, output_format='json', **kwargs):
    """Run a command/script from file using powershell, return output in text format
    If format is 'json', the result is piped to ConvertTo-Json and converted back to a python dict for convenient use

    .. versionadded:: 1.3.9
    """
    with open(file, 'r') as content_file:
        content = content_file.read()
        return run_powershell(content, output_format, **kwargs)

def run_powershell_script(script_filename, output_format : Literal['json', 'text', 'xml'] = 'json', **kwargs):
    """Run a script file using powershell, return output in text format
    If format is 'json', the result is piped to ConvertTo-Json and converted back to a python dict for convenient use

    Args:
        output_format (str): set output format as json (default) or xml (ElementTree object) or text

    Returns:
        str or dict or list

    .. versionadded:: 2.6.0
    """
    return run_powershell('(invoke-expression -Command "%s")' % script_filename, output_format, **kwargs)

def remove_metroapp(package):
    """Uninstall and remove a metro package from the computer

    .. versionadded:: 1.3.9
    """
    run_powershell('Get-AppxPackage %s --AllUsers| Remove-AppxPackage' % package)
    run_powershell("""Get-AppXProvisionedPackage -Online |
            where DisplayName -EQ %s |
            Remove-AppxProvisionedPackage -Online""" % package)


def running_as_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def run_as_administrator(afile, params=None):
    """Launch with a runas verb to trigger a privileges elevation.
    """
    # pylint: disable=no-name-in-module,import-error
    ret = shell.ShellExecuteEx(
        lpVerb='runas',
        lpFile=afile,
        lpParameters=params)
    return ret


def local_users_profiles():
    """Return a list of all local user's profile paths

    Returns:
        list : list of desktop path

    >>> local_desktops()
    [u'C:\\Windows\\ServiceProfiles\\LocalService',
     u'C:\\Windows\\ServiceProfiles\\NetworkService',
     u'C:\\Users\\install',
     u'C:\\Users\\UpdatusUser',
     u'C:\\Users\\administrateur',
     u'C:\\Users\\htouvet-adm']

    .. versionadded:: 1.3.9

    """
    result = []
    profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, profiles_path)

    i = 0
    while True:
        try:
            profid = winreg.EnumKey(key, i)
            prof_key = reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, "%s\\%s" % (profiles_path, profid))
            image_path = reg_getvalue(prof_key, 'ProfileImagePath', '')
            if isdir(image_path):
                result.append(image_path)
            i += 1
        except WindowsError as e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                break
            else:
                raise
    return result


def getsilentflags(installer_path):
    """Detect the type of installer and returns silent silent install flags

    Args:
        installer_path (str): filepath to installer

    Returns:
        str: detected command line flags to append to installer

    >>> getsilentflags(r'C:\tranquilit\wapt\tests\7z920.msi')
    '/q /norestart'
    """
    return get_installer_defaults_win(installer_path)['silentflags']


def get_product_props(installer_path):
    """get the properties (product, version, description...) of an exe file or a msi file

    Args:
        installer_path (str): filepath to exe or msi file

    Returns:
        dict: {'product','description','version','publisher'}

    """
    (product_name, ext) = os.path.splitext(installer_path.lower())
    product_name = os.path.basename(product_name)
    product_desc = product_name
    version = '0.0.0'
    publisher = ''

    if ext == '.exe':
        props = get_file_properties(installer_path)
        product_name = props['ProductName'] or product_desc
    elif ext == '.msi':
        props = get_msi_properties(installer_path)
        product_name = props['ProductName'] or props['FileDescription'] or product_desc
    else:
        props = {}

    if 'Manufacturer' in props and props['Manufacturer']:
        publisher = props['Manufacturer']
    elif 'CompanyName' in props and props['CompanyName']:
        publisher = props['CompanyName']

    if publisher:
        product_desc = "%s (%s)" % (product_name, publisher)
    else:
        product_desc = "%s" % (product_name,)

    if 'FileVersion' in props and props['FileVersion']:
        version = props['FileVersion']
    elif 'ProductVersion' in props and props['ProductVersion']:
        version = props['ProductVersion']

    props['product'] = product_name
    props['description'] = product_desc
    props['version'] = version
    props['publisher'] = publisher
    return props


def wait_uninstallkey_present(key=None, max_loop=120, keywords=None, name=None, raise_on_timeout=False):

    if len([f for f in [key, keywords, name] if f]) > 1:
        error("Arguments conflict key: %s keywords: %s name: %s" % (key, keywords, name))

    if key:
        searchparam = "key: %s" % str(key)
    elif name:
        searchparam = "name: %s" % str(name)
    else:
        searchparam = "keywords: %s" % str(keywords)

    print("Waiting for %s to appear in Windows registry" % searchparam)
    loop = 0
    while not uninstall_key_exists(key, keywords=keywords, name=name):
        loop += 1
        if loop > max_loop:
            if raise_on_timeout:
                error("timeout after %s seconds" % max_loop)
            else:
                return "timeout after %s seconds" % max_loop
        time.sleep(1)


def wait_uninstallkey_absent(key=None, max_loop=120, keywords=None, name=None, raise_on_timeout=False):

    if len([f for f in [key, keywords, name] if f]) > 1:
        error("Arguments conflict key: %s keywords: %s name: %s" % (key, keywords, name))

    if key:
        searchparam = "key: %s" % str(key)
    elif name:
        searchparam = "name: %s" % str(name)
    else:
        searchparam = "keywords: %s" % str(keywords)
    print("Waiting for the removal of %s from Windows registry" % searchparam)
    loop = 0
    while uninstall_key_exists(key, keywords=keywords, name=name):
        loop += 1
        if loop > max_loop:
            if raise_on_timeout:
                error("timeout after %s seconds" % max_loop)
            else:
                return "timeout after %s seconds" % max_loop
        time.sleep(1)


def need_install(key=None, min_version=None, force=False, get_version=None, keywords=None, name=None,higher_version_warning=True):
    """Return True if the software with key can be found in uninstall registry
    and the registred version is equal or greater than min_version

    Args:
        key (str): uninstall key
        min_version (str): minimum version or None if don't check version (like when key is specific for each soft version)
        get_version (callable): optional func to get installed software version from one installed_softwares item
            if not provided, version is taken from 'version' attribute in uninstall registry
        keywords (str or list): string to lookup in key, display_name or publisher fields
        name (str regexp) : filter on a regular expression on software name

    Returns:
        boolean

    .. versionchanged:: 2.1
        added keywords and name

    """

    if force or ((not key) and (not keywords) and (not name)):
        return True

    if len([f for f in [key,keywords,name] if f]) > 1:
        error('Arguments conflict key: %s keywords: %s name: %s' % (key,keywords,name))

    current = []
    if key:
        current = installed_softwares(uninstallkey=key)
    elif name:
        current = installed_softwares(name=name)
    elif keywords:
        current = installed_softwares(keywords=keywords)

    if min_version:
        min_version = Version(min_version,4)

    for soft in current:
        if min_version is None:
            return False
        if get_version is not None:
            installed_version = get_version(soft)
        else:
            installed_version = soft['version']
        installed_version = Version(installed_version,4)
        if min_version <= installed_version:
            if higher_version_warning:
                if min_version < installed_version:
                    print("WARNING the installed version (%s) is higher than the requested version (%s)" % (installed_version,min_version))
            return False
    return True


def remove_previous_version(key=None, max_version=None, keywords=None, name=None):
    """Launch uninstalling the key if its version is inferior of the version supplied as parameter

    Args:
        key (str) : uninstall key to check in registry and to add to uninstallkey global list
        max_version (str) : if installed version is inferior, Launch of uninstalling the key
                            if not provided (None) launch of uninstalling the key

    Returns:
        None

    """
    if len([f for f in [key,keywords,name] if f]) > 1:
        error('Arguments conflict key: %s keywords: %s name: %s' % (key,keywords,name))

    if (not key) and (not keywords) and (not name):
        error("Give at least a key a name or a keyword")

    for uninstall in installed_softwares(uninstallkey=key,name=name,keywords=keywords):
        if max_version:
            if Version(uninstall['version'],4) < Version(max_version,4):
                run(uninstall_cmd(uninstall['key']))
        else:
            run(uninstall_cmd(uninstall['key']))


def install_msi_if_needed(msi, min_version=None, killbefore=None, accept_returncodes=[0, 3010], timeout=300, properties=None, get_version=None, remove_old_version=False,
                          force=False, uninstallkeylist=None, pidlist=None, key=None, keywords=None, name=None,time_wait_uninstallkey_present=300):
    """Install silently the supplied msi file, and add the uninstall key to
    uninstallkeylist list

    uninstall key, min_version and silent flags are guessed from msi file.

    Raises an error if, after the msi install, the uninstall key is not found in registry.

    The matching is done on key

    Args:
        msi (str) : path to the MSI file
        min_version (str) : if installed version is equal or gretaer than this, don't install
                            if not provided (None), guess it from exe setup file properties.
                            if == '': ignore version check.
        kill_before (list of str) : processes to kill before setup, to avoid file locks
                                    issues.
        accept_returncodes (list of int) : return codes which are acceptable and don't raise exception
        timeout int) : maximum run time of command in seconds bfore the child is killed and error is raised.
        properties (dict) : map (key=value) of properties for specific msi installation.
        remove_old_version (bool) : If True, uninstall the old version explicitely before installing the new one.

    These 3 args are set automatically when run from install() :

        force            (bool) : Value is set automatically when run from install(). install even if already at the right version
        uninstallkeylist (list) : if the installation is run, add the msi unsinstall key to this list
        pidlist          (list) : if a process is created, add the pid to this list. (useful for external watchdogs in case of abort)

    Returns:
        None

    .. versionadded:: 1.3.2

    .. versionchanged:: 1.3.10
          added get_version callback for non conventional setup.exe

    .. versionchanged:: 1.4.1
          error code 1603 is no longer accepted by default.

    .. versionchanged:: 1.5
          added remove_old_version to explicitly remove old version


    """
    if len([f for f in [key,keywords,name] if f]) > 1:
        error('Arguments conflict key: %s keywords: %s name: %s' % (key,keywords,name))

    if not isfile(msi):
        error('msi file %s not found in package' % msi)

    if (key is None) and (name is None) and (not bool(keywords)):
        key = get_msi_properties(msi)['ProductCode']

    if min_version is None:
        min_version = get_product_props(msi)['version']

    if remove_old_version:
        if killbefore:
            killalltasks(killbefore)
        remove_previous_version(max_version=min_version, key=key, keywords=keywords, name=name)

    if need_install(key, min_version=min_version or None, force=force, get_version=get_version, keywords=keywords, name=name):
        if killbefore:
            killalltasks(killbefore)
        if isinstance(properties, dict):
            props = ' '.join(["%s=%s" % (k, v) for (k, v) in properties.items()])
        elif isinstance(properties, str):
            props = properties
        else:
            props = ''

        print(r"Installing: %s (%s)" % (msi, min_version))
        run(r'msiexec /norestart /q /i "%s" %s' % (msi, props), accept_returncodes=accept_returncodes, timeout=timeout, pidlist=pidlist)

        if key or bool(keywords) or name:

            wait_uninstallkey_present(key,time_wait_uninstallkey_present,keywords=keywords, name=name)

            if need_install(key, min_version=min_version or None, force=False, get_version=get_version, keywords=keywords, name=name):

                if key:
                    searchparam = 'key %s' % str(key)
                elif name:
                    searchparam = 'name %s' % str(name)
                else:
                    searchparam = 'keywords %s' % str(keywords)

                if need_install(key, None, force=False, get_version=get_version, keywords=keywords, name=name):
                    error('MSI %s has been installed but the %s can not be found' % (msi,searchparam))
                else:
                    error('MSI %s has been executed and %s has been found in the registry, but version in registry does not match requirements of min_version=%s' % (msi, searchparam , min_version))
    else:
        print('MSI %s already installed. Skipping msiexec' % msi)

    if (not key) and (name or bool(keywords)):
        if name:
            key = installed_softwares(name=name)[0]["key"]
        elif bool(keywords):
            key = installed_softwares(keywords=keywords)[0]["key"]

    # add the key to the caller uninstallkeylist
    if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
        uninstallkeylist.append(key)


def install_exe_if_needed(exe, silentflags=None, key=None, min_version=None, killbefore=[], accept_returncodes=[0, 3010], timeout=300, get_version=None, remove_old_version=False,
                          force=False, uninstallkeylist=None, pidlist=None, keywords=None, name=None,time_wait_uninstallkey_present=300):
    """Install silently the supplied setup executable file, and add the uninstall key to
    global uninstallkey list if it is defined.

    Check if already installed at the supllied min_version.

    Kill the processes in killbefore list before launching the setup.

    Raises an error if, after the setup install, the uninstall key is not found in registry.

    Args:
        exe (str) : path to the setup exe file
        silentflags (str) : flags to append to the exe command line for silent install
                            if not provided, tries to guess them.
        key (str) : uninstall key to check in registry and to add to uninstallkey global list
        min_version (str) : if installed version is equal or gretaer than this, don't install
                            if not provided (None), guess it from exe setup file properties.
                            if == '': ignore version check.
        kill_before (list of str) : processes to kill before setup, to avoid file locks
                                    issues.
        get_version (callable) : optional func to get installed software version from one entry retunred by installed_softwares
            if not provided, version is taken from 'version' attribute in uninstall registry

        remove_old_version (bool) : If True, uninstall the old version matching the provided key explicitely before installing the new one.

    Returns:
        None


    .. versionadded:: 1.3.2

    .. versionchanged:: 1.3.10
          added get_version callback for non conventional setup.exe

    .. versionchanged:: 1.4.1
          error code 1603 is no longer accepted by default.

    .. versionchanged:: 1.5
          added remove_old_version to explicitly remove old version

    """
    if len([f for f in [key,keywords,name] if f]) > 1:
        error('Arguments conflict key: %s keywords: %s name: %s' % (key,keywords,name))

    if not isfile(exe):
        error('setup exe file %s not found in package' % exe)
    if silentflags is None:
        silentflags = getsilentflags(exe)
    # use empty string to ignore version checking
    if min_version is None:
        min_version = get_product_props(exe)['version']

    if remove_old_version:
        if killbefore:
            killalltasks(killbefore)
        remove_previous_version(max_version=min_version, key=key, keywords=keywords, name=name)

    if need_install(key, min_version=min_version or None, force=force, get_version=get_version,keywords=keywords, name=name):
        if killbefore:
            killalltasks(killbefore)
        print(r"Installing: %s (%s)" % (exe, min_version))
        run(r'"%s" %s' % (exe, silentflags), accept_returncodes=accept_returncodes, timeout=timeout, pidlist=pidlist)
        if key or bool(keywords) or name:
            wait_uninstallkey_present(key,time_wait_uninstallkey_present,keywords=keywords, name=name)

            if need_install(key, min_version=min_version or None, force=False, get_version=get_version, keywords=keywords, name=name):

                if key:
                    searchparam = 'key %s' % str(key)
                elif name:
                    searchparam = 'name %s' % str(name)
                else:
                    searchparam = 'keywords %s' % str(keywords)

                if need_install(key, None, force=False, get_version=get_version, keywords=keywords, name=name):
                    error('Setup %s has been installed but the %s can not be found' % (exe,searchparam))
                else:
                    error('Setup %s has been executed and %s has been found in the registry, but version in registry does not match requirements of min_version=%s' % (exe, searchparam , min_version))
    else:
        print('Exe setup %s already installed. Skipping' % exe)

    if (not key) and (name or bool(keywords)):
        if name:
            key = installed_softwares(name=name)[0]["key"]
        elif bool(keywords):
            key = installed_softwares(keywords=keywords)[0]["key"]

    # add the key to the caller uninstallkeylist
    if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
        uninstallkeylist.append(key)


def local_desktops():
    """Return a list of all local user's desktops paths

    Args:
        None

    Returns:
        list : list of desktop path

    >>> local_desktops()
    [u'C:\\Windows\\ServiceProfiles\\LocalService\\Desktop',
     u'C:\\Windows\\ServiceProfiles\\NetworkService\\Desktop',
     u'C:\\Users\\install\\Desktop',
     u'C:\\Users\\UpdatusUser\\Desktop',
     u'C:\\Users\\administrateur\\Desktop',
     u'C:\\Users\\htouvet-adm\\Desktop']

    .. versionadded:: 1.2.3

    """
    result = []
    profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    key = reg_openkey_noredir(HKEY_LOCAL_MACHINE, profiles_path)

    i = 0
    while True:
        try:
            profid = winreg.EnumKey(key, i)
            prof_key = reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, "%s\\%s" % (profiles_path, profid))
            image_path = reg_getvalue(prof_key, 'ProfileImagePath', '')
            if isdir(makepath(image_path, 'Desktop')):
                result.append(makepath(image_path, 'Desktop'))
            if isdir(makepath(image_path, 'Bureau')):
                result.append(makepath(image_path, 'Bureau'))

            i += 1
        except WindowsError as e:
            # WindowsError: [Errno 259] No more data is available
            if e.winerror == 259:
                break
            else:
                raise
    return result


def get_app_path(exename):
    r"""Get the registered application location from registry given its executable name

    >>> get_app_path('firefox.exe')
    u'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'
    >>> get_app_path('wapt-get.exe')
    u'C:\\wapt\\wapt-get.exe'
    """
    result = None
    try:
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename) as key:
            result = reg_getvalue(key, '')
    except WindowsError as e:
        if e.winerror == 2:
            result = None
        else:
            raise
    if iswin64() and not result:
        try:
            with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s' % exename, noredir=False) as key:
                result = reg_getvalue(key, '')
        except WindowsError as e:
            if e.winerror == 2:
                result = None
            else:
                raise
    return result


# legacy
get_appath = get_app_path


def get_app_install_location(uninstallkey):
    r"""Get the registered application install location from registry given its uninstallkey

    >>> get_app_install_location('wapt_is1')
    u'C:\\wapt\\'
    """

    result = None
    try:
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s' % uninstallkey) as key:
            result = reg_getvalue(key, 'InstallLocation')
    except WindowsError as e:
        if e.winerror == 2:
            result = None
        else:
            raise
    if iswin64() and not result:
        try:
            with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s' % uninstallkey, noredir=False) as key:
                result = reg_getvalue(key, 'InstallLocation')
        except WindowsError as e:
            if e.winerror == 2:
                result = None
            else:
                raise
    return result


class InstallerTypes(object):
    MSI = 'MSI'
    InnoSetup = 'InnoSetup'
    InstallShield = 'InstallShield'
    SFXCab = 'SFXCab'
    SevenZIPSFX = 'SevenZIPSFX'
    NSIS = 'NSIS'
    MSU = 'MSU'
    ExeWinUpdates = 'ExeWindowsUpdate'  # exe with wextract
    WExtract = 'WExtract'
    APPX = 'WExtract'
    GenericInstaller = 'GenericInstaller'
    UnknownInstaller = 'UnknownInstaller'
    UnknownExeInstaller = 'UnknownExeInstaller'
    MozillaInstaller = 'MozillaInstaller'


def get_installer_defaults_exe(result_format, installer_path):
    """See get_installer_defaults(). Specific to .exe files"""

    result = result_format
    exe_props = get_file_properties(installer_path)

    if exe_props.get('InternalName', '').lower() == 'sfxcab.exe':
        result.update(dict(type=InstallerTypes.SFXCab, silentflags='/quiet'))
    elif exe_props.get('InternalName', '').lower() == '7zs.sfx':
        result.update(dict(type=InstallerTypes.SFXCab, silentflags='/s'))
    elif exe_props.get('InternalName', '').lower() == 'setup launcher':
        result.update(dict(type=InstallerTypes.InstallShield, silentflags='/s'))
    elif exe_props.get('InternalName', '').lower() == 'wextract':
        result.update(dict(type=InstallerTypes.WExtract, silentflags='/Q'))
    else:
        with open(installer_path, 'rb') as f:
            content = f.read(600000)
        (product_name, ext) = os.path.splitext(installer_path)
        if b'Inno.Setup' in content:
            result.update(dict(type=InstallerTypes.InnoSetup, silentflags='/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'))
        elif b'Quiet installer' in content:
            result.update(dict(type=InstallerTypes.GenericInstaller, silentflags='-q'))
        elif b'nsis.sf.net' in content or b'Nullsoft.NSIS' in content:
            result.update(dict(type=InstallerTypes.NSIS, silentflags='/S'))
        elif ('Firefox Setup' in product_name) or ('Thunderbird Setup' in product_name):
            result.update(dict(type=InstallerTypes.MozillaInstaller, silentflags='-ms'))
        else:
            result.update(dict(type=InstallerTypes.UnknownExeInstaller, silentflags='/VERYSILENT'))
    return result


def get_installer_defaults_win(installer_path):
    """Returns guessed default values for package templates based on installer binary

    Args:
        installer_path (str): filepath to installer

    Returns:
        dict:

    >>> get_installer_defaults(r'c:\tranquilit\wapt\tests\SumatraPDF-3.1.1-install.exe')
    {'description': u'SumatraPDF Installer (Krzysztof Kowalczyk)',
     'filename': 'SumatraPDF-3.1.1-install.exe',
     'silentflags': '/VERYSILENT',
     'simplename': u'sumatrapdf-installer',
     'type': 'UnknownExeInstaller',
     'version': u'3.1.1'}

    >>> get_installer_defaults(r'c:\tranquilit\wapt\tests\7z920.msi')
    {'description': u'7-Zip 9.20 (Igor Pavlov)',
     'filename': '7z920.msi',
     'silentflags': '/q /norestart',
     'simplename': u'7-zip-9.20',
     'type': 'MSI',
     'version': u'9.20.00.0'}

    """
    (product_name, ext) = os.path.splitext(installer_path)
    ext = ext.lower()
    props = get_product_props(installer_path)
    simplename = re.sub(r'[\s\(\)]+', '-', props['product'].lower())
    description = props['description']
    publisher = props['publisher']
    version = props['version'] or '0.0.0'

    result = dict(filename=os.path.basename(installer_path),
                  simplename=simplename,
                  version=version,
                  description=description,
                  silentflags='',
                  type=None,
                  uninstallkey=None,
                  publisher=publisher,
                  architecture='all')

    if ext == '.exe':
        result = get_installer_defaults_exe(result, installer_path)
    elif ext == '.msi':
        #result = get_msi_properties(installer_path)
        result.update(dict(type=InstallerTypes.MSI, silentflags='/q /norestart', uninstallkey=props['ProductCode']))
    elif ext == '.msu':
        result.update(dict(type=InstallerTypes.MSU, silentflags='/quiet /norestart'))
    else:
        result.update(dict(type=InstallerTypes.UnknownInstaller, silentflags='/VERYSILENT'))
    return result


def run_task(name):
    """Launch immediately the Windows Scheduled task

    """
    return ensure_unicode(run(r'schtasks /Run /TN "%s"' % name))


def task_exists(name):
    """Return true if a sheduled task names 'name.job' is defined

    """
    try:
        run(r'schtasks /Query /TN "%s"' % name)
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return False
        raise e

    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    return '%s.job' % name in ts.Enum()
    """


def delete_task(name):
    """Removes a Windows scheduled task

    Args:
        name (str) : name of the tasks as created in create_daily_task
    """
    try:
        return ensure_unicode(run(r'schtasks /Delete /F /TN "%s"' % name))
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return ensure_unicode(e)
        raise e
    # old task sheduler interface deprecated by microsoft.
    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    if '%s.job' % name not in ts.Enum():
        raise KeyError("%s doesn't exists" % name)
    ts.Delete(name)
    """


def disable_task(name):
    """Disable a Windows scheduled task"""
    return ensure_unicode(run(r'schtasks /Change /TN "%s" /DISABLE' % name))
    """
    task = get_task(name)
    task.SetFlags(task.GetFlags() | taskscheduler.TASK_FLAG_DISABLED)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    return task
    """


def enable_task(name):
    """Enable (start of) a Windows scheduled task

    Args:
        name (str) : name of the tasks as created in create_daily_task
    """
    return ensure_unicode(run('schtasks /Change /TN "%s" /ENABLE' % name))

    """
    task = get_task(name)
    task.SetFlags(task.GetFlags() & ~taskscheduler.TASK_FLAG_DISABLED)
    pf = task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None,1)
    return task
    """


def create_daily_task(name, cmd, parameters, max_runtime=10, repeat_minutes=None, start_hour=None, start_minute=None):
    """creates a Windows scheduled daily task and activate it.

    Args:
        name (str): name of task for reference
        cmd(str) :  command line
        parameters (str) : arguments to append to cmd
        max_runtime (int): maximum running time in minutes
        repeat_minutes (int): interval in minutes between run
        start_hour   (int): hour time of start
        start_minute (int): minute time of start

    Returns:
        PyITask: scheduled task
    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler, None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)

    if '%s.job' % name not in ts.Enum():
        task = ts.NewWorkItem(name)

        task.SetApplicationName(cmd)
        task.SetParameters(parameters)
        task.SetAccountInformation('', None)
        if max_runtime:
            task.SetMaxRunTime(max_runtime * 60*1000)
        #task.SetFlags(task.GetFlags() | taskscheduler.TASK_FLAG_)
        ts.AddWorkItem(name, task)
        run_time = time.localtime(time.time() + 300)
        tr_ind, tr = task.CreateTrigger()
        tt = tr.GetTrigger()
        tt.Flags = 0
        tt.BeginYear = int(time.strftime('%Y', run_time))
        tt.BeginMonth = int(time.strftime('%m', run_time))
        tt.BeginDay = int(time.strftime('%d', run_time))
        if start_minute is None:
            tt.StartMinute = int(time.strftime('%M', run_time))
        else:
            tt.StartMinute = start_minute
        if start_hour is None:
            tt.StartHour = int(time.strftime('%H', run_time))
        else:
            tt.StartHour = start_hour
        tt.TriggerType = int(taskscheduler.TASK_TIME_TRIGGER_DAILY)
        if repeat_minutes:
            tt.MinutesInterval = repeat_minutes
            tt.MinutesDuration = 24*60
        tr.SetTrigger(tt)
        pf = task.QueryInterface(pythoncom.IID_IPersistFile)
        pf.Save(None, 1)
        # task.Run()
    else:
        raise KeyError("%s already exists" % name)

    task = ts.Activate(name)
    #exit_code, startup_error_code = task.GetExitCode()
    return task


def windows_version_from_WMI(members_count=3):
    """see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx

    .. versionadded:: 1.3.5

    .. versionchanged:: 1.6.2.5
          members_count (int) : default to 3.
    """
    try:
        version = Version(platform.win32_ver()[1], members_count)
    except:
        version = Version(platform.win32_ver()[1])
    if version >= '10':
        try:
            version = Version(wmi.WMI().Win32_OperatingSystem()[0].version, members_count)
        except:
            version = Version(wmi.WMI().Win32_OperatingSystem()[0].version)
    return version


def windows_version(members_count=3):
    """Same than windows_version_from_WMI() but get information for windows 10 in registry (it's faster)

    .. versionadded:: 1.3.5

    .. versionchanged:: 1.6.2.5
        members_count (int) : default to 3

    .. versionchanged:: 2.3
        now getting the correct UBR (Update Build Revision) shown with "winver" command

    """
    ubr_version = str(registry_readstring(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR"))
    if ubr_version:
        version = Version("%s.%s.%s." % win32api.GetVersionEx()[0:3] + ubr_version, members_count)
    else:
        version = Version("%s.%s.%s.%s" % win32api.GetVersionEx()[0:4], members_count)
    return version


class WindowsVersions(object):
    r"""Helper class to get numbered windows version from windows name version

    Sources:
    https://msdn.microsoft.com/en-us/library/windows/desktop/dn481241(v=vs.85).aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
    https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions

    ... versionadded:: 1.3.5

    .. versionchanged:: 1.9
        Adding Windows 10.0 and newer versions

    .. versionchanged:: 2.0
        Adding Windows 10 version 20H1 and newer versions

    .. versionchanged:: 2.2
        Adding Windows 11/2023 versions

    """

    Windows11v23H2 = Version("10.0.22631", 3)
    Windows11v22H2 = Version("10.0.22621", 3)
    Windows11 = Version("10.0.22000", 3)

    Windows10v22H2 = Version("10.0.19045", 3)
    Windows10v21H2 = Version("10.0.19044", 3)
    Windows10v21H1 = Version("10.0.19043", 3)
    Windows10v20H2 = Version("10.0.19042", 3)
    Windows10v2009 = Version("10.0.19042", 3)
    Windows10v20H1 = Version("10.0.19041", 3)
    Windows10v2004 = Version("10.0.19041", 3)
    Windows10v1909 = Version("10.0.18363", 3)
    Windows10v1903 = Version("10.0.18362", 3)
    Windows10v1809 = Version("10.0.17763", 3)
    Windows10v1803 = Version("10.0.17134", 3)
    Windows10v1709 = Version("10.0.16299", 3)
    Windows10v1703 = Version("10.0.15063", 3)
    Windows10v1607 = Version("10.0.14393", 3)
    Windows10v1511 = Version("10.0.10586", 3)
    Windows10v1507 = Version("10.0.10240", 3)
    Windows10 = Version("10.0", 2)

    WindowsServer2022 = Version("10.0.20348", 3)
    WindowsServer2019 = Version("10.0.17763", 3)
    WindowsServer2016 = Version("10.0.14393", 3)

    Windows81 = Version("6.3", 2)
    WindowsServer2012R2 = Version("6.3", 2)

    Windows8 = Version("6.2", 2)
    WindowsServer2012 = Version("6.2", 2)

    Windows7SP1 = Version("6.1.7601", 3)
    Windows7 = Version("6.1", 2)
    WindowsServer2008R2 = Version("6.1", 2)

    WindowsServer2008 = Version("6.0", 2)
    WindowsVistaSP2 = Version("6.0.6002", 3)
    WindowsVista = Version("6.0", 2)

    WindowsServer2003R2 = Version("5.2", 2)
    WindowsServer2003 = Version("5.2", 2)
    WindowsXP64 = Version("5.2", 2)
    WindowsXP = Version("5.1", 2)

    Windows2000 = Version("5.0", 2)


def create_onetime_task(name, cmd, parameters=None, delay_minutes=2, max_runtime=10, retry_count=3, retry_delay_minutes=1):
    """creates a one time Windows scheduled task and activate it.
    """
    run_time = time.localtime(time.time() + delay_minutes*60)
    # task
    hour_min = time.strftime('%H:%M:%S', run_time)
    try:
        return ensure_unicode(run('schtasks /Create /SC ONCE /TN "%s" /TR "\'%s\' %s" /ST %s /RU SYSTEM /F /V1 /Z' % (name, cmd, parameters, hour_min)))
    except:
        # windows xp doesn't support one time startup task /Z nor /F
        try:
            run('schtasks /Delete /TN "%s" /F' % name)
        except:
            pass
        return ensure_unicode(run('schtasks /Create /SC ONCE /TN "%s" /TR  "%s %s" /ST %s /RU SYSTEM' % (name, cmd, parameters, hour_min)))


def register_dll(dllpath):
    """Register a COM/OLE server DLL in registry (similar to regsvr32)

    """
    dll = ctypes.windll[dllpath]
    result = dll.DllRegisterServer()
    logger.info('DLL %s registered' % dllpath)
    if result:
        raise Exception('Register DLL %s failed, code %i' % (dllpath, result))


def unregister_dll(dllpath):
    """Unregister a COM/OLE server DLL from registry

    """
    dll = ctypes.windll[dllpath]
    result = dll.DllUnregisterServer()
    logger.info('DLL %s unregistered' % dllpath)
    if result:
        raise Exception('Unregister DLL %s failed, code %i' % (dllpath, result))


def add_to_system_path(path):
    """Add path to the global search PATH environment variable if it is not yet

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', sam=KEY_READ | KEY_WRITE) as key:
        system_path = reg_getvalue(key, 'Path').split(';')
        if not path.lower() in [p.lower() for p in system_path]:
            system_path.append(path)
            reg_setvalue(key, 'Path', ';'.join(system_path), type=REG_EXPAND_SZ)
            win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000)
    return system_path


def unset_environ_variable(name, user=True):
    r"""Remove a system wide persistent environment variable if it exist. Fails silently if it doesn't exist

    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE if not user else HKEY_CURRENT_USER, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' if not user else r'Environment',
                             sam=KEY_READ | KEY_WRITE) as key:
        result = reg_delvalue(key, name)
    # force to get new environ variable, as it is not reloaded immediately.
    if name in os.environ:
        del(os.environ[name])
        win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000)
    return result


def get_task(name):
    """Return an instance of PyITask given its name (without .job)

    """
    ts = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler, None,
                                    pythoncom.CLSCTX_INPROC_SERVER,
                                    taskscheduler.IID_ITaskScheduler)
    if '%s.job' % name not in ts.Enum():
        raise KeyError("%s doesn't exists" % name)

    task = ts.Activate(name)
    return task


def user_desktop():
    r"""Return path to current logged in user desktop

    >>> user_desktop()
    u'C:\\Users\\htouvet\\Desktop'
    """
    return str(desktop(0))


def common_desktop():
    r"""Return path to public desktop (visible by all users)

    >>> common_desktop()
    u'C:\\Users\\Public\\Desktop'
    """
    return str(desktop(1))


def service_installed(service_name):
    """Return True if the service is installed"""
    try:
        service_is_running(service_name)
        return True
    except win32service.error as e:
        if e.winerror == 1060:
            return False
        else:
            raise


def service_delete(service_name):
    if service_is_running(service_name):
        service_stop(service_name)
        time.sleep(2)

    hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    try:
        hs = win32serviceutil.SmartOpenService(hscm, service_name, win32service.SERVICE_ALL_ACCESS)
        win32service.DeleteService(hs)
        win32service.CloseServiceHandle(hs)
    finally:
        win32service.CloseServiceHandle(hscm)

    if service_installed(service_name):
        killalltasks(['mmc.exe', 'procexp.exe', 'procexp64.exe'])
        if service_installed(service_name):
            error('Service %s not delete' % service_name)


def service_start(service_name, timeout=15):
    """Start a service by its service name
    """
    logger.debug('Starting service %s' % service_name)
    win32serviceutil.StartService(service_name)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=timeout)


def service_stop(service_name, timeout=15):
    """Stop a service by its service name
    """
    logger.debug('Stopping service %s' % service_name)
    win32serviceutil.StopService(service_name)
    win32api.Sleep(2000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_STOPPED, waitSecs=timeout)


def service_restart(service_name, timeout=15):
    """Restart a service by its service name
    """
    logger.debug('Restarting service %s' % service_name)
    win32serviceutil.RestartService(service_name)
    win32api.Sleep(2000)
    return win32serviceutil.WaitForServiceStatus(service_name, win32service.SERVICE_RUNNING, waitSecs=timeout)


def service_is_running(service_name):
    """Return True if the service is running

    >>> state = service_is_running('waptservice')
    """
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_RUNNING


def service_is_stopped(service_name):
    """Return True if the service is running

    >>> state = service_is_running('waptservice')
    """
    return win32serviceutil.QueryServiceStatus(service_name)[1] == win32service.SERVICE_STOPPED



def service_list():
    result = {}
    accessSCM = win32con.GENERIC_READ

    #Open Service Control Manager
    hscm = win32service.OpenSCManager(None, None, accessSCM)

    #Enumerate Service Control Manager DB
    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL
    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)

    for (short_name, desc, status) in statuses:
        s = win32service.OpenService(hscm, short_name, win32service.SERVICE_QUERY_CONFIG)
        try:
            #s = win32service.OpenService(hscm, short_name, win32service.SERVICE_ALL_ACCESS)
            cfg = win32service.QueryServiceConfig(s)
            startup = ('Boot', 'System', 'Automatic', 'Manual', 'Disabled')[cfg[1]]
        except:
            startup = 'Unknown'

        result[short_name] = {"description":desc,'running':status[1] == win32service.SERVICE_RUNNING,'startup':startup}

    return result

def user_appdata():
    r"""Return the roaming appdata profile of current user

    Returns:
        str: path like u'C:\\Users\\username\\AppData\\Roaming'
    """
    return ensure_unicode((winshell.get_path(shellcon.CSIDL_APPDATA)))


def default_user_appdata():
    r"""Return the roaming appdata profile of default user

    Returns:
        str: path like u'C:\\Users\\Default\\AppData\\Roaming'
    """
    return ensure_unicode(makepath(registry_readstring(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', 'Default'), 'AppData', 'Roaming'))


def default_user_local_appdata():
    r"""Return the local appdata profile of current user

    Returns:
        str: path like u'C:\\Users\\Default\\AppData\\Local'
    """
    return ensure_unicode(makepath(registry_readstring(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', 'Default'), 'AppData', 'Local'))


def remove_tree(*args, **kwargs):
    r"""Convenience function to delete a directory tree, with any error
    not ignored by default.  Pass ignore_errors=False to access possible
    errors.

    Args:
        path (str): path to directory to remove
        ignore_errors (boolean) : default to False. Set it to True to ignore exceptions on children deletion
        onerror (func) : hook called with (func, path, exc)
                         on each delete exception. Should raise if stop is required.

    >>> def print_error(func, path, error):
    >>>     print(u'Error when "%s" for "%s": "%s"' % (func.__name__, path, repr(error[1])))
    >>>
    >>> remove_tree(r'c:\tmp\target', onerror=print_error)

    .. versionchanged:: 1.5.1.17
        ignore_errors default to False
    """
    def set_rw(operation, name, exc):
        # access denied... retry after removing readonly flag
        if isinstance(exc[1], WindowsError) and exc[1].winerror == 5:
            os.chmod(name, stat.S_IWRITE)
            os.unlink(name)
            return True
        else:
            raise exc

    if 'ignore_errors' not in kwargs:
        kwargs['ignore_errors'] = False
    if 'onerror' not in kwargs:
        kwargs['onerror'] = set_rw

    return shutil.rmtree(*args, **kwargs)


def add_user_to_group(user, group):
    """Add membership to a local group for a user

    """
    user_group_info = dict(
        domainandname=user
    )
    try:
        win32net.NetLocalGroupAddMembers(None, group, 3, [user_group_info])
    except win32net.error as e:
        # pass if already member of the group
        if e.winerror != 1378:
            raise
        else:
            logger.debug('add_user_to_group %s %s : %s' % (user, group, ensure_unicode(e)))


def remove_user_from_group(user, group):
    """Remove membership from a local group for a user

    """
    try:
        win32net.NetLocalGroupDelMembers(None, group, [user])
    except win32net.error as e:
        # pass if not member of the group
        if e.winerror != 1377:
            raise
        else:
            logger.debug('remove_user_from_group %s %s : %s' % (user, group, ensure_unicode(e)))


def delete_user(user):
    """Delete a local user

    """
    try:
        win32net.NetUserDel(None, user)
    except win32net.error as error:
        if error.winerror != 2221:
            raise


def delete_group(group):
    """Delete a local user group

    """

    try:
        win32net.NetLocalGroupDel(None, group)
    except win32net.error as error:
        if error.winerror != 2220:
            raise


def local_users():
    """Returns local users

    >>> local_users()
    [u'Administrateur',
     u'ASPNET',
     u'cyg_user',
     u'install',
     u'Invit\xe9',
     u'newadmin',
     u'sshd',
     u'toto',
     u'UpdatusUser']
    >>>
    """
    return [u['name'] for u in win32net.NetUserEnum(None, 2)[0]]


def local_groups():
    """Returns local groups

    >>> local_groups()
    [u'Administrateurs',
     u'Duplicateurs',
     u'IIS_IUSRS',
     u'Invit\xe9s',
     u'Lecteurs des journaux d\\u2019\xe9v\xe9nements',
     u'Op\xe9rateurs de chiffrement',
     u'Op\xe9rateurs de configuration r\xe9seau',
     u'Op\xe9rateurs de sauvegarde',
     u'Utilisateurs',
     u'Utilisateurs avec pouvoir',
     u'Utilisateurs de l\\u2019Analyseur de performances',
     u'Utilisateurs du Bureau \xe0 distance',
     u'Utilisateurs du journal de performances',
     u'Utilisateurs du mod\xe8le COM distribu\xe9',
     u'IIS_WPG',
     u'test']
     """
    return [g['name'] for g in win32net.NetLocalGroupEnum(None, 0)[0]]


def local_admins():
    """List local users who are local administrators

    >>> local_admins()
    [u'Administrateur', u'cyg_user', u'install', u'toto']    """
    return [g['name'] for g in win32net.NetUserEnum(None, 2)[0] if g['priv'] == win32netcon.USER_PRIV_ADMIN]


def local_group_memberships(username):
    """List the local groups a user is member Of"""
    return win32net.NetUserGetLocalGroups(None, username)


def local_group_members(groupname):
    result = []
    memberdata, total, memberresume = win32net.NetLocalGroupGetMembers(None, groupname, 0, 0)
    for member in memberdata:
        sidmember = str(member['sid']).split(':')[1]
        try:
            samaccountname = get_user_from_sid(sidmember,fallback_profpath=False)
        except:
            samaccountname = sidmember
        result.append(samaccountname)

    return result


def adjust_current_privileges(priv, enable=1):
    # Get the process token.
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ALL_ACCESS)
    # Get the ID for the system shutdown privilege.
    id = win32security.LookupPrivilegeValue(None, priv)
    # Now obtain the privilege for this process.
    # Create a list of the privileges to be added.
    if enable:
        new_privileges = [(id, win32con.SE_PRIVILEGE_ENABLED)]
    else:
        new_privileges = [(id, 0)]
    # and make the adjustment.
    return win32security.AdjustTokenPrivileges(htoken, False, new_privileges)


def reboot_machine(message="Machine Rebooting", timeout=30, force=0, reboot=1):
    r"""Reboot the current host within specified timeout, display a message to the user
    This can not be cancelled bu the user.

    Args:
        message (str) : displayed to user to warn him
        timeout (int) : timeout in seconds before proceeding
        force (int) : If this parameter is 1, applications with unsaved changes
                        are to be forcibly closed.
                      If this parameter is 0, the system displays a dialog box instructing
                        the user to close the applications.
        reboot (int) : 1 to reboot after shutdown; If 0, the system halt.

    """
    adjust_current_privileges(win32con.SE_SHUTDOWN_NAME)
    try:
        win32api.InitiateSystemShutdown(None, message, timeout, force, reboot)
    finally:
        # Now we remove the privilege we just added.
        adjust_current_privileges(win32con.SE_SHUTDOWN_NAME, 0)


def dmi_info():
    """Hardware System information from BIOS estracted with dmidecode
    Convert dmidecode -q output to python dict

    Returns:
        dict

    >>> dmi = dmi_info()
    >>> 'UUID' in dmi['System_Information']
    True
    >>> 'Product_Name' in dmi['System_Information']
    True
    """

    result = {}
    try:
        dmidecode_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dmidecode.exe')
        if os.path.isfile(dmidecode_exe):
            dmiout = ensure_unicode(run('"%s" -q' % dmidecode_exe, shell=False))
            new_section = True
            for l in dmiout.splitlines():
                if not l.strip() or l.startswith('#'):
                    new_section = True
                    continue

                if not l.startswith('\t') or new_section:
                    currobject = {}
                    key = l.strip().replace(' ', '_')
                    # already here... so add as array...
                    if (key in result):
                        if not isinstance(result[key], list):
                            result[key] = [result[key]]
                        result[key].append(currobject)
                    else:
                        result[key] = currobject
                else:
                    if not l.startswith('\t\t'):
                        currarray = []
                        if ':' in l:
                            (name, value) = l.split(':', 1)
                            currobject[name.strip().replace(' ', '_')] = value.strip()
                        else:
                            logger.warning("Error in line : %s" % l)
                    else:
                        # first line of array
                        if not currarray:
                            currobject[name.strip().replace(' ', '_')] = currarray
                        currarray.append(l.strip())
                new_section = False

    except Exception as e:
        # dmidecode fails on some BIOS.
        # TODO : fall back to wmi for most important parameters
        logger.critical('Unable to get dmi info: %s' % e)
        result = {}
    return result


def win_startup_info():
    """Return the applications started at boot or login

    Returns:
        dict : {'common_startup': [{'command': '',
                                    'name': ''},]
               'run':            [{'command': '',
                                   'name': ''},]
    """
    result = {'run': [], 'common_startup': []}
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE, makepath('Software', 'Microsoft', 'Windows', 'CurrentVersion', 'Run')) as run_key:
        for (name, value, _type) in reg_enum_values(run_key):
            result['run'].append({'name': name, 'command': value})
    try:
        for lnk in glob.glob(makepath(startup(1), '*.lnk')):
            sc = winshell.shortcut(lnk)
            result['common_startup'].append({'name': ensure_unicode(lnk), 'command': '"%s" %s' % (ensure_unicode(sc.path), ensure_unicode(sc.arguments))})
    except Exception as e:
        # we got a bug report with a windows client failing to get the stratip(1) folder : pywintypes.com_error: (-2147024893) Path does not exist.
        logger.debug('Unable to get common startup folder content: %s' % e)
        pass

    return result


def set_computer_description(description):
    """Change the computer descrption"""
    global _fake_hostname
    if _fake_hostname is not None:
        logger.warning('Skipping set_computer_description for fake host')
    elif wmi:
        registry_setstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', 'srvcomment', description)
        for win32_os in wmi.WMI().Win32_OperatingSystem():
            win32_os.Description = description
    else:
        raise Exception('WMI not available')


def get_computer_description():
    """Get the computer descrption"""
    try:
        for win32_os in wmi.WMI().Win32_OperatingSystem():
            return win32_os.Description
    except Exception as e:
        # WMI is broken...
        logger.critical('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))
        return registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\LanmanServer\Parameters', 'srvcomment', '')


class EnsureWUAUServRunning(object):
    """Contextual object to ensure that wauserv service is running (in manual mode)
    Restores previous state at context exit.
    """
    # https://msdn.microsoft.com/en-us/library/aa394418(v=vs.85).aspx#properties

    def __enter__(self):
        print("Ensure wuauserv Auto Update option is disabled")
        if wmi:
            # we disable the autoupdate option to ensure automtic windows update behaviour will not take place during our own work
            self.old_au_options = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', 0)
            c = wmi.WMI()
            for service in c.Win32_Service(Name='wuauserv'):
                # we store old service start mode and whether service is crurrently started
                self.wuaserv_start_mode = service.StartMode
                self.wuaserv_started = service.Started
                # we put in manual start mode and try to start the service
                service.ChangeStartMode(StartMode="manual")
                service.StartService()

            start = time.time()
            for service in c.Win32_Service(Name='wuauserv'):
                # we wait 10s until it is actually started.
                while not service.Started and time.time() - start < 10:
                    time.sleep(1)
                if not service.Started:
                    raise Exception('Unable to start wuauserv')

        return self

    def __exit__(self, type, value, tb):
        if wmi:
            print("re-enabling wuauserv previous state: %s" % self.old_au_options)
            registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', self.old_au_options)
            self.old_au_options = None
            c = wmi.WMI()
            for service in c.Win32_Service(Name='wuauserv'):
                # if service was not started before, we stop it
                if not self.wuaserv_started:
                    service.StopService()
                # we restore the previous start mode of the service
                service.ChangeStartMode(StartMode=self.wuaserv_start_mode)

            # if service was not started before, we wait 10s until it is actually stopped.
            if not self.wuaserv_started:
                start = time.time()
                for service in c.Win32_Service(Name='wuauserv'):
                    while service.Started and time.time() - start < 10:
                        time.sleep(1)


def critical_system_pending_updates(severities=['Critical']):
    """Return list of not installed critical updates

    Returns:
        list: list of title of WSUS crititcal updates not applied

    """
    with EnsureWUAUServRunning():
        updateSession = win32com_ensure_dispatch_patch("Microsoft.Update.Session")
        updateSearcher = updateSession.CreateUpdateSearcher()
        searchResult = updateSearcher.Search("IsInstalled=0 and Type='Software'")
        return [dict(update_id="%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber), title=update.Title) for update in searchResult.Updates if update.MsrcSeverity in severities]


def pending_reboot_reasons():
    """Return the list of reasons requiring a pending reboot the computer
    If list is empty, no reboot is needed.

    Returns:
        list : list of Windows Update, CBS Updates or File Renames
    """
    result = []
    reboot_required = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'RebootRequired', 0)
    if reboot_required:
        result.append('Windows Update: %s' % reboot_required)
    reboot_pending = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing', 'RebootPending', 0)
    if reboot_pending:
        result.append('CBS Updates: %s' % reboot_pending)
    update_exe_volatile = reg_key_exists(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Updates\UpdateExeVolatile')
    if update_exe_volatile:
        result.append('Update Exe Volatile: %s' % update_exe_volatile)
    renames_pending = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager', 'PendingFileRenameOperations', None)
    if renames_pending:
        result.append('File renames: %s' % renames_pending)
    return result


def get_default_gateways():
    result = []
    if wmi:
        wmi_obj = wmi.WMI()
        connections = wmi_obj.query("select IPAddress,DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE")
        for connection in connections:
            if connection.DefaultIPGateway:
                result.append(connection.DefaultIPGateway[0])
    return result


def get_dns_servers():
    result = []
    if wmi:
        wmi_obj = wmi.WMI()
        connections = wmi_obj.query("select IPAddress,DefaultIPGateway,DNSServerSearchOrder from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE")
        for connection in connections:
            if connection.DNSServerSearchOrder:
                result.extend(connection.DNSServerSearchOrder)
    return result


def wua_agent_version():
    try:
        return Version(get_file_properties(makepath(system32(), 'wuapi.dll'))['ProductVersion'])
    except Exception:
        return Version('0.0.0')


def get_profile_path(sid):
    """Return the filesystem path to profile of user with SID sid"""
    return os.path.expandvars(
        registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\%s' % sid, 'ProfileImagePath'))


def get_user_from_profpath(sid):
    """extrapolate user from the profile directory path"""
    try:
        if not isinstance(sid, str):
            sid = ("%s" % sid).split(':')[1]
        profpath = get_profile_path(sid)
        user = os.path.basename(profpath)
        return user
    except:
        return None


def get_profiles_users(domain_sid=None):
    """Return list of locally created profiles usernames"""
    result = []
    profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    for profsid in reg_enum_subkeys(reg_openkey_noredir(HKEY_LOCAL_MACHINE, profiles_path)):
        if not domain_sid or (profsid.startswith('S-') and profsid.rsplit('-', 1)[0] == domain_sid) and isdir(get_profile_path(profsid)):
            result.append(get_user_from_sid(profsid))
    return result


def get_local_profiles(domain_sid=None):
    """Return list of locally created profiles usernames"""
    result = []
    profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    for profsid in reg_enum_subkeys(reg_openkey_noredir(HKEY_LOCAL_MACHINE, profiles_path)):
        if not domain_sid or (profsid.startswith('S-') and profsid.rsplit('-', 1)[0] == domain_sid) and isdir(get_profile_path(profsid)):
            result.append({'sid': profsid, 'user': get_user_from_sid(profsid), 'profile_path': get_profile_path(profsid)})
    return result


def get_last_logged_on_user():
    last_logged_on_user = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI', 'LastLoggedOnUser', '')
    return last_logged_on_user


def local_drives():
    result = {}
    try:
        w = wmi.WMI()
        keystr = ['Caption', 'DriveType', 'Description', 'FileSystem', 'Name', 'VolumeSerialNumber']
        keyint = ['FreeSpace', 'Size']
        for disk in w.Win32_LogicalDisk(fields=keystr+keyint):
            details = {}
            for key in keystr:
                details[key] = getattr(disk, key)
            for key in keyint:
                val = getattr(disk, key)
                if val is not None:
                    details[key] = int(getattr(disk, key))
                else:
                    details[key] = None
            if details.get('Size') and details.get('Size', 0) > 0:
                details['FreePercent'] = int(details.get('FreeSpace', 0) * 100 / details['Size'])
            letter = disk.Caption
            result[letter.replace(':', '')] = details
    except Exception as e:
        # WMI is broken...
        logger.critical('WMI is broken on this computer. See https://techcommunity.microsoft.com/t5/ask-the-performance-team/wmi-rebuilding-the-wmi-repository/ba-p/373846 : %s' % ensure_unicode(e))
    return result


def host_metrics():
    """Frequently updated host data
    """
    result = {}
    # volatile...
    result['physical_memory'] = memory_status().ullTotalPhys
    result['virtual_memory'] = memory_status().ullTotalVirtual  # TODO its the value for the actual process
    result['local_drives'] = local_drives()
    result['logged_in_users'] = get_loggedinusers()
    result['last_logged_on_user'] = get_last_logged_on_user()
    result['boot_count'] = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters', 'BootId', 0)
    if uptime:
        result['last_bootup_time'] =  datetime.datetime.utcnow() - datetime.timedelta(seconds = uptime())

    # memory usage
    mem_info = psutil.Process().memory_info()
    result['wapt-memory-usage'] = {}
    for field in mem_info._fields:
        result['wapt-memory-usage'][field] = getattr(mem_info, field)

    return result


def fix_wmi():
    """reregister all the WMI related DLLs in the wbem folder
    """
    run('sc config winmgmt start= disabled')
    run('net stop winmgmt /y', accept_returncodes=[0, 2])
    for srv in glob.glob(makepath(system32(), 'wbem', '*.dll')):
        try:
            run(['regsvr32', '/s', srv])
        except CalledProcessErrorOutput as e:
            print('Register of DLL server %s failed. Code: %s' % (srv, e.returncode))

    run('wmiprvse /regserver')
    with disable_file_system_redirection():
        run('winmgmt /resyncperf')
    run('sc config winmgmt start= auto')
    run('net start winmgmt')
    for mof in find_all_files(makepath(system32(), 'wbem'), ['*.mof', '*.mfl']):
        try:
            run(['mofcomp', mof])
        except CalledProcessErrorOutput as e:
            print('mofcomp of %s failed. Code: %s' % (mof, e.returncode))

    try:
        with disable_file_system_redirection():
            run('winmgmt /verifyrepository')
        return True
    except CalledProcessErrorOutput as e:
        print('Verify wmi repository failed : %s' % (ensure_unicode(e)))
        return False


def get_file_properties(fname, ignore_warning=True):
    r"""Read all properties of the given file return them as a dictionary.

    Source: http://stackoverflow.com/questions/580924/python-windows-file-version-attribute

    Args:
        fname : path to Windows executable or DLL

    Returns:
        dict: properties of executable

    >>> xp = get_file_properties(r'c:\windows\explorer.exe')
    >>> 'FileVersion' in xp and 'FileDescription' in xp
    True
    """
    propNames = ('Comments', 'InternalName', 'ProductName',
                 'CompanyName', 'LegalCopyright', 'ProductVersion',
                 'FileDescription', 'LegalTrademarks', 'PrivateBuild',
                 'FileVersion', 'OriginalFilename', 'SpecialBuild')
    props = {}
    for propName in propNames:
        props[propName] = ''

    # \VarFileInfo\Translation returns list of available (language, codepage)
    # pairs that can be used to retreive string info. We are using only the first pair.
    try:
        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]
    except:
        lang, codepage = (None, None)
    # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
    # two are language/codepage pair returned from above

    if not (lang, codepage) == (None, None):
        for propName in propNames:
            try:
                strInfoPath = '\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
                # print str_info
                props[propName] = (win32api.GetFileVersionInfo(fname, strInfoPath) or '').strip()
            except Exception as e:
                if not ignore_warning:
                    logger.warning("%s" % ensure_unicode(e))
                    # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc

    try:
        fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
        props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo['FileVersionMS'] / 65536,
                                                fixedInfo['FileVersionMS'] % 65536, fixedInfo['FileVersionLS'] / 65536,
                                                fixedInfo['FileVersionLS'] % 65536)
    except Exception as e:
        if not ignore_warning:
            logger.warning("%s" % ensure_unicode(e))
            # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc

    if not props['ProductVersion']:
        try:
            fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
            props['ProductVersion'] = "%d.%d.%d.%d" % (fixedInfo['ProductVersionMS'] / 65536,
                                                       fixedInfo['ProductVersionMS'] % 65536, fixedInfo['ProductVersionLS'] / 65536,
                                                       fixedInfo['ProductVersionLS'] % 65536)
        except Exception as e:
            if not ignore_warning:
                logger.warning("%s" % ensure_unicode(e))
                # backslasfh as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc

    return props


def get_msi_properties(msi_filename,list_properties=["FileDescription","ProductCode","version","product","publisher","description","ProductVersion","UpgradeCode","Manufacturer","CompanyName","FileVersion","product","ProductName"]):
    r"""Return a dict of msi installer properties

    Source: http://stackoverflow.com/questions/3157955/get-msi-product-name-version-from-command-line

    Args:
        msi_filename (str): path to msi file

    Returns:
        dict: properties of msi. at least there seems to be keys like
             'Manufacturer','ProductCode','ProductName','ProductVersion'

    >>> zprop = get_msi_properties(r'C:\tranquilit\wapt\tests\7z920.msi')
    >>> 'ProductVersion' in zprop and 'ProductCode' in zprop and 'ProductName' in zprop
    True
    """
    lower_list_properties = [p.lower() for p in list_properties]
    db = msilib.OpenDatabase(msi_filename, msilib.MSIDBOPEN_READONLY)
    view = db.OpenView("SELECT * FROM Property")
    view.Execute(None)
    result = {}
    r = view.Fetch()
    while r:
        # https://bugs.python.org/issue11702
        if ensure_unicode(r.GetString(1)).lower() in lower_list_properties:
            try:
                result[ensure_unicode(r.GetString(1))] = ensure_unicode(r.GetString(2))
            except:
                logger.warning("get_msi_properties : error for string %s" % ensure_unicode(r.GetString(0)))
        try:
            r = view.Fetch()
        except:
            break
    return result

# local user / groups management (from winsys examples)


def create_user(user, password, full_name=None, comment=None):
    """Creates a local user

    """
    user_info = dict(
        name=user,
        password=password,
        priv=win32netcon.USER_PRIV_USER,
        home_dir=None,
        comment=comment,
        full_name=full_name,
        flags=win32netcon.UF_SCRIPT,
        script_path=None,
        password_expired=1
    )
    win32net.NetUserAdd(None, 1, user_info)


def create_group(group):
    """Creates a local group

    """
    group_info = dict(
        name=group
    )
    win32net.NetLocalGroupAdd(None, 0, group_info)


# from http://stackoverflow.com/questions/2017545/get-memory-usage-of-computer-in-windows-with-python
def memory_status():
    """Return system memory statistics

    """
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

        def __init__(self):
            # have to initialize this to the size of MEMORYSTATUSEX
            self.dwLength = ctypes.sizeof(self)
            super(MEMORYSTATUSEX, self).__init__()

    stat = MEMORYSTATUSEX()
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return stat
    else:
        raise Exception('Error in function GlobalMemoryStatusEx')


def register_uninstall(
    uninstallkey,
    uninstallstring=None,
    win64app=None,
    quiet_uninstall_string=None,
    install_location=None,
    display_name=None,
    display_version=None,
    publisher=None,
    icon=None,
    installed_size=None,
):
    r"""Register or update the uninstall entry in Windows registry,
    so that the application is displayed in Control Panel / Programs and features with correct informations

    Args:
        installed_size (int): in MB (default: converting bytes from control file to megabytes)

    .. versionchanged:: 2.3
        now detect automatically if the app is win64

    """
    if not uninstallkey:
        raise Exception("No uninstall key provided")

    if win64app is None:
        if len(installed_softwares(uninstallkey=uninstallkey)) > 1:
            raise Exception(
                "This application is installed with multiple architectures please uninstall the other version or precise if this application is a win64app application or not"
            )
        if len(installed_softwares(uninstallkey=uninstallkey)) == 1:
            win64app = installed_softwares(uninstallkey=uninstallkey)[0]["win64"]
        else:
            win64app = False

    if (win64app and iswin64()) or (not win64app and not iswin64()):
        root = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    elif iswin64() and not win64app:
        root = r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    else:
        raise Exception('Trying to install a Windows 64-bit application on a Windows that doesn\'t support Windows 64-bit applications')

    with reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, r'%s\%s' % (root, uninstallkey),
            sam=winreg.KEY_ALL_ACCESS, create_if_missing=True) as appkey:

        if uninstallstring:
            reg_setvalue(appkey, 'UninstallString', uninstallstring)
        if quiet_uninstall_string:
            reg_setvalue(appkey, 'QuietUninstallString', quiet_uninstall_string)
        if not reg_getvalue(appkey, "InstallDate"):
            reg_setvalue(appkey, "InstallDate", currentdate())
        if display_name:
            reg_setvalue(appkey, 'DisplayName', display_name)
        if display_version:
            reg_setvalue(appkey, 'DisplayVersion', display_version)
        if install_location:
            reg_setvalue(appkey, 'InstallLocation', install_location)
        if publisher:
            reg_setvalue(appkey, 'Publisher', publisher)
        if icon:
            reg_setvalue(appkey, 'DisplayIcon', icon)
        if installed_size:
            reg_setvalue(appkey, 'EstimatedSize', installed_size, type=winreg.REG_DWORD)


def register_windows_uninstall(package_entry, win64app=None):
    r""" Add a uninstall entry in Windows registry for custom installer (for example: portable installation)

    """
    register_uninstall(package_entry.name,
        'wapt-get remove %s' % package_entry.package,
        win64app=win64app,
        display_name=package_entry.name,
        display_version=package_entry.get_software_version(),
        publisher=package_entry.editor,
        installed_size=int(package_entry.installed_size)//10**3 if package_entry.installed_size else None,
    )


def unregister_uninstall(uninstallkey, win64app=None):
    r"""Removes the uninstallkey from the registry

    .. versionchanged:: 2.3
        now detect automatically if the app is win64
    .. versionchanged:: 2.5
        now includes empty_names

    """
    if not uninstallkey:
        raise Exception("No uninstall key provided")

    if win64app is None:
        if len(installed_softwares(uninstallkey=uninstallkey, ignore_empty_names=False)) > 1:
            raise Exception(
                "This application is installed with multiple architectures please uninstall the other version or precise if this application is a win64app application or not"
            )
        if len(installed_softwares(uninstallkey=uninstallkey, ignore_empty_names=False)) == 1:
            win64app = installed_softwares(uninstallkey=uninstallkey, ignore_empty_names=False)[0]["win64"]
        else:
            win64app = False

    if (win64app and iswin64()) or (not win64app and not iswin64()):
        root = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    elif iswin64() and not win64app:
        root = r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    else:
        raise Exception('Trying to install a Windows 64-bit application on a Windows that doesn\'t support Windows 64-bit applications')

    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, r'%s\%s' % (root, uninstallkey))
    except WindowsError as e:
        logger.warning('Unable to remove key %s, error : %s' % (ensure_unicode(root), ensure_unicode(e)))


def add_shutdown_script(cmd, parameters):
    """ Adds a local shutdown script as a local GPO

    Args:
        cmd (str): absolute path to exe or bat file (without parameters)
        parameters (str): parameters to append to command
    Returns:
        int: index of command into the list of shutdown scripts

    >>> index = add_shutdown_script(r'c:\wapt\wapt-get.exe','update')
    """
    gp_path = makepath(system32(), 'GroupPolicy')
    gptini_path = makepath(gp_path, 'gpt.ini')
    scriptsini_path = makepath(gp_path, 'Machine', 'Scripts', 'scripts.ini')
    update_gpt = False

    # manage GPT.INI file
    with disable_file_system_redirection():
        ensure_dir(scriptsini_path)
        gptini = RawConfigParser()
        # be sure to have section names case unsensitive
        gptini.data._sectionxform = _lower
        if os.path.isfile(gptini_path):
            gptini.readfp(codecs.open(gptini_path, mode='r', encoding='utf8'))
        if not gptini.has_section('General'):
            gptini.add_section('General')
        # set or extend extensionnames
        if not gptini.has_option('General', 'gPCMachineExtensionNames'):
            gptini.set('General', 'gPCMachineExtensionNames', '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
            update_gpt = True
        else:
            ext = gptini.get('General', 'gPCMachineExtensionNames').strip().replace('][', '],[').split(',')
            if not '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]' in ext:
                ext.append('[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]')
                update_gpt = True

            gptini.set('General', 'gPCMachineExtensionNames', ''.join(sorted(ext)))
        # increment version
        if gptini.has_option('General', 'Version'):
            version = gptini.getint('General', 'Version')
            user_version = version & 0xffff0000
            computer_version = version & 0x0000ffff
            computer_version += 1
            version = computer_version | user_version
        else:
            version = 1
        gptini.set('General', 'Version', version)

        # update shutdown/Scripts.ini
        scriptsini = RawConfigParser()
        if os.path.isfile(scriptsini_path):
            try:
                scriptsini.readfp(codecs.open(scriptsini_path, mode='r', encoding='utf16'))
            except UnicodeError:
                # bug http://roundup.tranquil.it/wapt/issue233
                scriptsini.readfp(codecs.open(scriptsini_path, mode='r', encoding='utf8'))
        if not scriptsini.has_section('Shutdown'):
            scriptsini.add_section('Shutdown')

        # check if cmd already exist in shutdown scripts
        cmd_index = -1
        param_index = -1
        script_index = None
        i = -1
        for (key, value) in scriptsini.items('Shutdown'):
            # keys are lowercase in iniparser !
            if key.endswith('cmdline'):
                i = int(key.split('cmdline')[0])
                if value.lower() == cmd.lower():
                    cmd_index = i
            if key.endswith('parameters'):
                i = int(key.split('parameters')[0])
                if value.lower() == parameters.lower():
                    param_index = i
            # cmd and params are matching... => script already exists
            if cmd_index >= 0 and param_index >= 0 and cmd_index == param_index:
                script_index = cmd_index
                break
        if script_index is None:
            update_gpt = True
            script_index = i+1
            scriptsini.set('Shutdown', '%iCmdLine' % (script_index,), cmd)
            scriptsini.set('Shutdown', '%iParameters' % (script_index,), parameters)
            if not os.path.isdir(os.path.dirname(scriptsini_path)):
                os.makedirs(os.path.dirname(scriptsini_path))
            if os.path.isfile(scriptsini_path):
                set_file_visible(scriptsini_path)
            try:
                with codecs.open(scriptsini_path, 'w', encoding='utf16') as f:
                    f.write(ini2winstr(scriptsini))
            finally:
                set_file_hidden(scriptsini_path)

        if update_gpt:
            if not os.path.isdir(os.path.dirname(gptini_path)):
                os.makedirs(os.path.dirname(gptini_path))
            with codecs.open(gptini_path, 'w', encoding='utf8') as f:
                f.write(ini2winstr(gptini))
            run('GPUPDATE /Target:Computer /Force /Wait:30')
            return script_index
        else:
            return None


def remove_shutdown_script(cmd, parameters):
    """ Removes a local shutdown GPO script

    >>> index = remove_shutdown_script(r'c:\wapt\wapt-get.exe','update')
    """
    gp_path = makepath(system32(), 'GroupPolicy')
    gptini_path = makepath(gp_path, 'gpt.ini')
    scriptsini_path = makepath(gp_path, 'Machine', 'Scripts', 'scripts.ini')

    # manage GPT.INI file
    with disable_file_system_redirection():
        ensure_dir(scriptsini_path)
        gptini = RawConfigParser()
        # be sure to have section names case unsensitive
        gptini.data._sectionxform = _lower

        if os.path.isfile(gptini_path):
            gptini.readfp(codecs.open(gptini_path, mode='r', encoding='utf8'))
        if not gptini.has_section('General'):
            gptini.add_section('General')

        # increment version
        if gptini.has_option('General', 'Version'):
            version = gptini.getint('General', 'Version')
            version += 1
        else:
            version = 1
        gptini.set('General', 'Version', version)

        # update shutdown/Scripts.ini
        scriptsini = RawConfigParser()
        if os.path.isfile(scriptsini_path):
            try:
                scriptsini.readfp(codecs.open(scriptsini_path, mode='r', encoding='utf16'))
            except UnicodeError:
                # bug http://roundup.tranquil.it/wapt/issue233
                scriptsini.readfp(codecs.open(scriptsini_path, mode='r', encoding='utf8'))
        if not scriptsini.has_section('Shutdown'):
            scriptsini.add_section('Shutdown')

        # check if cmd already exist in shutdown scripts
        last_cmd_index = -1
        last_param_index = -1
        script_index = None

        scripts = []
        for (key, value) in scriptsini.items('Shutdown'):
            # keys are lowercase in iniparser !
            if key.endswith('cmdline'):
                last_cmd_index = int(key.split('cmdline')[0])
                last_cmd = value
            if key.endswith('parameters'):
                last_param_index = int(key.split('parameters')[0])
                last_param = value
            if last_cmd_index >= 0 and last_param_index >= 0 and last_cmd_index == last_param_index:
                if last_cmd.lower() == cmd.lower() and last_param.lower() == parameters.lower():
                    script_index = last_cmd_index
                else:
                    scripts.append((last_cmd, last_param))

        if script_index is not None:
            # reorder remaining scripts
            scriptsini.remove_section('Shutdown')
            scriptsini.add_section('Shutdown')
            i = 0
            for (c, p) in scripts:
                scriptsini.set('Shutdown', '%iCmdLine' % (i,), c)
                scriptsini.set('Shutdown', '%iParameters' % (i,), p)
                i += 1

            if not os.path.isdir(os.path.dirname(scriptsini_path)):
                os.makedirs(os.path.dirname(scriptsini_path))
            if os.path.isfile(scriptsini_path):
                set_file_visible(scriptsini_path)
            try:
                with codecs.open(scriptsini_path, 'w', encoding='utf16') as f:
                    f.write(ini2winstr(scriptsini))
            finally:
                set_file_hidden(scriptsini_path)

            if not os.path.isdir(os.path.dirname(gptini_path)):
                os.makedirs(os.path.dirname(gptini_path))
            with codecs.open(gptini_path, 'w', encoding='utf8') as f:
                f.write(ini2winstr(gptini))
            run('GPUPDATE /Target:Computer /Force /Wait:30')
            return script_index
        else:
            return None


def shutdown_scripts_ui_visible(state=True):
    """Enable or disable the GUI for windows shutdown scripts

    >>> shutdown_scripts_ui_visible(None)
    >>> shutdown_scripts_ui_visible(False)
    >>> shutdown_scripts_ui_visible(True)
    """
    with reg_openkey_noredir(HKEY_LOCAL_MACHINE,
                             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', sam=KEY_ALL_ACCESS) as key:
        if state is None:
            try:
                winreg.DeleteValue(key, 'HideShutdownScripts')
            except WindowsError as e:
                if not e.errno in (259, 2):
                    raise
        elif state:
            reg_setvalue(key, 'HideShutdownScripts', 0, REG_DWORD)
        elif not state:
            reg_setvalue(key, 'HideShutdownScripts', 1, REG_DWORD)


def uninstall_cmd(guid):
    r"""return the (quiet) command stored in registry to uninstall a software given its registry key

    >>> old_softs = installed_softwares('notepad++')
    >>> for soft in old_softs:
    ...     print uninstall_cmd(soft['key'])
    [u'C:\\Program Files (x86)\\Notepad++\\uninstall.exe', '/S']
    """
    def get_fromkey(uninstall, noredir=True):
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE, "%s\\%s" % (uninstall, guid), noredir=noredir) as key:
            try:
                cmd = winreg.QueryValueEx(key, 'QuietUninstallString')[0]
                # fix silent arg for innosetup
                if 'unins000' in cmd.lower():
                    cmd = cmd.replace(' /SILENT', ' /VERYSILENT')
                return cmd
            except WindowsError:
                try:
                    cmd = winreg.QueryValueEx(key, 'UninstallString')[0]
                    if 'msiexec' in cmd.lower():
                        cmd = cmd.replace('/I', '/X').replace('/i', '/X')
                        args = shlex.split(cmd, posix=False)
                        if not '/q' in cmd.lower():
                            args.append('/q')
                        if not '/norestart' in cmd.lower():
                            args.append('/norestart')

                    else:
                        # separer commande et parametres pour eventuellement
                        cmd_arg = re.match(r'([^/]*?)\s+([/-].*)', cmd)
                        if cmd_arg:
                            (prog, arg) = cmd_arg.groups()
                            args = [prog]
                            args.extend(shlex.split(arg, posix=False))
                        # mozilla et autre
                        # si pas de "" et des espaces et pas d'option, alors encadrer avec des quotes
                        elif not(' -' in cmd or ' /' in cmd) and ' ' in cmd:
                            args = [cmd]
                        else:
                            # split on parameters
                            args = shlex.split(cmd, posix=False)

                        # remove double quotes if any
                        if args[0].startswith('"') and args[0].endswith('"') and (not "/" in cmd or not "--" in cmd):
                            args[0] = args[0][1:-1]

                        if ('spuninst' in cmd.lower()):
                            if not ' /quiet' in cmd.lower():
                                args.append('/quiet')
                        elif ('uninst' in cmd.lower() or 'helper.exe' in cmd.lower()):
                            if not ' /s' in cmd.lower():
                                args.append('/S')
                        elif ('unins000' in cmd.lower()):
                            if not ' /verysilent' in cmd.lower():
                                args.append('/verysilent')
                    return args
                except WindowsError:
                    is_msi = winreg.QueryValueEx(key, 'WindowsInstaller')[0]
                    if is_msi == 1:
                        return 'msiexec /quiet /norestart /X %s' % guid
                    else:
                        raise

    try:
        return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    except:
        if platform.machine() == 'AMD64':
            return get_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", noredir=False)
        else:
            raise


def uninstall_key_exists(uninstallkey, keywords=None, name=None):
    """Check if the uninstallkey is present in win32 / win64 registry"""
    if not uninstallkey:
        if installed_softwares(keywords=keywords, name=name):
            return True
        else:
            return False

    try:
        # use exception side effect to check if exists.
        with reg_openkey_noredir(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s" % uninstallkey):
            pass
        return True
    except:
        pass

    if platform.machine() == 'AMD64':
        try:
            # use exception side effect to check if exists.
            with reg_openkey_noredir(HKEY_LOCAL_MACHINE, "Software\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s" % uninstallkey, noredir=False):
                pass
            return True
        except:
            pass
    return False

def installed_softwares(keywords=None, uninstallkey=None, name=None, ignore_empty_names=True):
    """Return list of installed software from registry (both 32bit and 64bit)

    Args:
        keywords (str or list): string to lookup in key, display_name or publisher fields
        uninstallkey : filter on a specific uninstall key instead of fuzzy search

    .. versionchanged:: 1.3.11
        name (str regexp) : filter on a regular expression on software name

    Returns:
        list of dicts: [{'key', 'name', 'version', 'install_date', 'install_location'
                     'uninstall_string', 'publisher','system_component'}]

    >>> softs = installed_softwares('libre office')
    >>> if softs:
    ...     for soft in softs:
    ...         print uninstall_cmd(soft['key'])
    ???
    """

    name_re = re.compile(name) if name is not None else None

    def check_words(target, words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result

    def list_fromkey(uninstall, noredir=True):
        result = []
        with reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, uninstall, noredir=noredir) as key:
            if isinstance(keywords, str):
                mykeywords = keywords.lower().split()
            elif isinstance(keywords, bytes):
                mykeywords = str(keywords).lower().split()
            elif keywords is not None:
                mykeywords = [ensure_unicode(k).lower() for k in keywords]
            else:
                mykeywords = None

            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(key, i)
                    appkey = reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, "%s\\%s" % (uninstall, subkey), noredir=noredir)
                    display_name = reg_getvalue(appkey, 'DisplayName', '')
                    display_version = reg_getvalue(appkey, 'DisplayVersion', '')
                    try:
                        date = str(reg_getvalue(appkey, 'InstallDate', '')).replace('\x00', '')
                        try:
                            install_date = datetime.datetime.strptime(date, '%Y%m%d').strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            try:
                                install_date = datetime.datetime.strptime(date, '%d/%m/%Y').strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                install_date = date
                    except:
                        date = reg_getvalue(appkey, 'InstallDate', '')
                    install_location = reg_getvalue(appkey, 'InstallLocation', '')
                    uninstallstring = reg_getvalue(appkey, 'UninstallString', '')
                    publisher = reg_getvalue(appkey, 'Publisher', '')
                    if reg_getvalue(appkey, 'ParentKeyName', '') == 'OperatingSystem' or reg_getvalue(appkey, 'SystemComponent', 0) == 1:
                        system_component = 1
                    else:
                        system_component = 0
                    if  (not ignore_empty_names or display_name != '') and (
                            (uninstallkey is None or (subkey == uninstallkey)) and
                            (mykeywords is None or check_words(subkey+' '+display_name+' '+publisher, mykeywords)) and
                            (name_re is None or name_re.match(display_name))):
                        result.append({'key': subkey,
                                       'name': display_name.replace('\x00', ''),
                                       'version': ("%s" % display_version).replace('\x00', ''),
                                       'install_date': ("%s" % install_date),
                                       'install_location': install_location.replace('\x00', ''),
                                       'uninstall_string': uninstallstring.strip('\x00'),
                                       'publisher': publisher.replace('\x00', ''),
                                       'system_component': system_component,
                                       'win64': iswin64() and noredir})
                    i += 1
                except WindowsError as e:
                    # WindowsError: [Errno 259] No more data is available
                    if e.winerror == 259:
                        break
                    else:
                        raise
        return result
    result = list_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    if iswin64():
        result.extend(list_fromkey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", noredir=False))
    return result


def install_location(uninstallkey):
    """Return the install location of the software given its uninstall key
    or None if not found

    >>> install_location('winscp3_is1')
    u'C:\\Program Files\\WinSCP\\'
    """
    for soft in installed_softwares(uninstallkey=uninstallkey):
        return soft.get('install_location', None)
    return None


def get_computer_domain():
    """Get computer AD domain
    """
    try:
        # only works if connected ?
        info = win32security.DsGetDcName()
        return info.get('DomainName', None)
    except:
        return registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\Tcpip\Parameters', 'NV Domain')


def get_loggedinusers():
    """Return the list of logged in users on this host

    Returns:
        list: list of users logins

    >>> get_loggedinusers()
    [u'htouvet']
    """
    result = []
    try:
        import win32ts
        for session in win32ts.WTSEnumerateSessions():
            if session['State'] == win32ts.WTSActive:
                result.append(win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE, session['SessionId'], win32ts.WTSUserName))
        return result
    except:
        return [get_current_user()]


def registered_organization():
    return registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'RegisteredOrganization')


def _environ_params(dict_or_module={}):
    """set some environment params in the supplied module or dict"""
    if type(dict_or_module) is dict:
        params_dict = dict_or_module
    else:
        params_dict = {}

    params_dict['programfiles32'] = programfiles32()
    params_dict['programfiles64'] = programfiles64()
    params_dict['programfiles'] = programfiles()
    params_dict['domainname'] = get_domain_fromregistry()
    params_dict['computername'] = os.environ['COMPUTERNAME']
    params_dict['systemdrive'] = systemdrive()
    if type(dict_or_module) is types.ModuleType:
        for k, v in params_dict.items():
            setattr(dict_or_module, k, v)
    return params_dict


def registry_readstring(root, path, keyname, default=''):
    """Return a string from registry

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        the path can be either with backslash or slash

    >>> registry_readstring(HKEY_LOCAL_MACHINE,r'SYSTEM/CurrentControlSet/services/Tcpip/Parameters','Hostname').upper()
    u'HTLAPTOP'
    """
    path = path.replace('/', '\\')
    try:
        with reg_openkey_noredir(root, path) as key:
            return reg_getvalue(key, keyname, default)
    except:
        return default


def registry_set(root, path, keyname, value, type=None):
    """Set the value of a key in registry, taking in account value type
    The path can be either with backslash or slash

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : value (integer or string type) to put in keyname

    Returns:


    """
    path = path.replace('/', '\\')
    with reg_openkey_noredir(root, path, sam=KEY_WRITE, create_if_missing=True) as key:
        if not type:
            if isinstance(value, list):
                type = REG_MULTI_SZ
            elif isinstance(value, int):
                type = REG_DWORD
            elif isinstance(value, bytes):
                type = REG_BINARY
            else:
                type = REG_SZ
        return reg_setvalue(key, keyname, value, type=type)



def registry_setstring(root, path, keyname, value, type=winreg.REG_SZ):
    """Set the value of a string key in registry
    the path can be either with backslash or slash

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : None for value of key or str for a specific value like 'CommonFilesDir'
        value   : string to put in keyname
    """
    path = path.replace('/', '\\')
    with reg_openkey_noredir(root, path, sam=KEY_WRITE, create_if_missing=True) as key:
        return reg_setvalue(key, keyname, value, type=type)


def registry_delete(root, path, valuename):
    """Delete the valuename inside specified registry path

    The path can be either with backslash or slash

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        valuename : None for value of key or str for a specific value like 'CommonFilesDir'

    """
    result = False
    path = path.replace('/', '\\')
    try:
        with reg_openkey_noredir(root, path, sam=KEY_WRITE) as key:
            return winreg.DeleteValue(key, valuename)
    except WindowsError as e:
        logger.warning('registry_delete:%s' % ensure_unicode(e))
    return result


def registry_deletekey(root, path, keyname, force=False, recursive=False):
    r"""Delete the key under specified registry path and all its values.

    the path can be either with backslash or slash
    if the key has sub keys, the function fails.

    Args:
        root    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
        path    : string like "software\\microsoft\\windows\\currentversion"
                           or "software\\wow6432node\\microsoft\\windows\\currentversion"
        keyname : Name of key
        recursive: Whether the subkeys must be deleted recursively. If this is set to False and keyname has subkeys the function will fail.

    >>> from winsys import registry
    >>> py27 = registry.Registry(r'HKEY_LOCAL_MACHINE\Software\Python\PythonCore\2.7')
    >>> py27.copy(r'HKEY_LOCAL_MACHINE\Software\Python\PythonCore\test')
    >>> registry_deletekey(HKEY_LOCAL_MACHINE,'Software\\Python\\PythonCore','test')
    True
    """
    # revert to old 'non recursive' way as winsys doesn't handle.
    result = False
    path = path.replace('/', '\\')
    try:
        with reg_openkey_noredir(root, path, sam=KEY_WRITE) as parent_key:
            if not(isinstance(keyname, str)):
                keyname = str(keyname)
            if recursive:
                reg_delete_subkeys(root, path + '\\' + keyname)
            return winreg.DeleteKey(parent_key, keyname)
    except WindowsError as e:
        logger.warning('registry_deletekey:%s' % ensure_unicode(e))
    return result

    """
    def makeregpath(root,*path):
        hives = {
            HKEY_CLASSES_ROOT: u'HKEY_CLASSES_ROOT',
            HKEY_CURRENT_CONFIG: u'HKEY_CURRENT_CONFIG',
            HKEY_CURRENT_USER: u'HKEY_CURRENT_USER',
            HKEY_LOCAL_MACHINE: u'HKEY_LOCAL_MACHINE',
            HKEY_USERS: u'HKEY_USERS',
            }
        return makepath(hives[root],*path)

    result = False
    path = path.replace(u'/',u'\\')
    from winsys import registry,exc
    try:
        rootpath = makeregpath(root,path)
        if len(rootpath.split(u'\\')) <= 1 and not force:
            raise Exception(u'The registry path %s is too short...too dangerous to remove it'%rootpath)
        ## Issue here with KEY_WOW64_64KEY !
        registry.delete(rootpath,keyname)
        root = registry.Registry(rootpath,access = winreg.KEY_READ| winreg.KEY_WOW64_64KEY | winreg.KEY_WRITE)
        result = not keyname in [os.path.basename(k.as_string()) for k in root.keys()]
    except (WindowsError,exc.x_not_found) as e:
        logger.warning(u'registry_deletekey:%s' % repr(e))
    return result
    """


def get_computername():
    """Return host name (without domain part)"""
    global _fake_hostname
    global _computername
    global _computername_expire

    if _fake_hostname is not None:
        return _fake_hostname.split('.', 1)[0]
    if _computername is None or time.time() >= _computername_expire:
        _computername = socket.gethostname().lower()
        _computername_expire = time.time() + _dns_cache_ttl
    return _computername


def messagebox(title, msg, style=win32con.MB_ICONINFORMATION):
    r"""Open a message box to interact with the end user

    Args:
        title (str): Title of the message box
        msg (str): Text contained in the message box
        style (win32con): Format of the message box, usable values:
                    MB_OK
                    MB_OKCANCEL
                    MB_ABORTRETRYIGNORE
                    MB_YESNOCANCEL
                    MB_YESNO
                    MB_RETRYCANCEL

                    MB_ICONHAND
                    MB_ICONQUESTION
                    MB_ICONEXCLAMATION
                    MB_ICONASTERISK
                    MB_ICONWARNING = MB_ICONEXCLAMATION
                    MB_ICONERROR = MB_ICONHAND
                    MB_ICONSTOP = MB_ICONHAND
                    MB_ICONINFORMATION = MB_ICONASTERISK

                    MB_DEFBUTTON1
                    MB_DEFBUTTON2
                    MB_DEFBUTTON3
                    MB_DEFBUTTON4


    Returns:
        ID_OK = 0
        ID_CANCEL = 2
        ID_ABORT = 3
        ID_YES = 6
        ID_NO = 7

    """

    return win32api.MessageBox(0, ensure_unicode(msg), ensure_unicode(title), style)


def showmessage(msg):
    messagebox("Information", msg)


def register_ext(appname, fileext, shellopen, icon=None, otherverbs=[]):
    r"""Associates a file extension with an application, and command to open it

    Args:
        appname (str): descriptive name of the type of file / appication
        fileext (str): extension with dot prefix of


    >>> register_ext(
    ...     appname='WAPT.Package',
    ...     fileext='.wapt',
    ...     icon=r'c:\wapt\wapt.ico',
    ...     shellopen=r'"7zfm.exe" "%1"',otherverbs=[
    ...        ('install',r'"c:\wapt\wapt-get.exe" install "%1"'),
    ...        ('edit',r'"c:\wapt\wapt-get.exe" edit "%1"'),
    ...     ])
    >>>
    """
    def setvalue(key, path, value):
        with reg_openkey_noredir(key, path, sam=KEY_READ | KEY_WRITE, create_if_missing=True) as k:
            if value != None:
                reg_setvalue(k, '', value)
    filetype = appname+fileext
    setvalue(HKEY_CLASSES_ROOT, fileext, filetype)
    setvalue(HKEY_CLASSES_ROOT, filetype, appname + " file")
    if icon:
        setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "DefaultIcon"), icon)
    setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "shell"), '')
    setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "shell", "open"), '')
    setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "shell", "open", "command"), shellopen)
    if otherverbs:
        for (verb, cmd) in otherverbs:
            setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "shell", verb), '')
            setvalue(HKEY_CLASSES_ROOT, makepath(filetype, "shell", verb, "command"), cmd)


def get_computer_groups():
    """Try to finc the computer in the Active Directory
    and return the list of groups
    """
    groups = []
    active_directory._CACHE.clear()
    computer = active_directory.find_computer()
    if computer:
        computer_groups = computer.memberOf
        if computer_groups:
            if not isinstance(computer_groups, (tuple, list)):
                computer_groups = [computer_groups]
            for group in computer_groups:
                # extract first component of group's DN
                cn = group.split(',')[0].split('=')[1]
                groups.append(cn.lower())
    return groups


def create_shortcut(path, target='', arguments='', wDir='', icon=''):
    r"""Create a windows shortcut

    Args:
        path (str) : As what file should the shortcut be created?
        target (str): What command should the desktop use?
        arguments (str): What arguments should be supplied to the command?
        wdir (str) : working directory. What folder should the command start in?
        icon (str or list) : filename or (filename, index) (only for file sc)
                              What icon should be used for the shortcut

    Returns:
        None

    >>> create_shortcut(r'c:\\tmp\\test.lnk',target='c:\\wapt\\waptconsole.exe')
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == '.url':
        with open(path, 'w') as shortcut:
            shortcut.write('[InternetShortcut]\n')
            shortcut.write('URL=%s\n' % target)
            shortcut.write('IconFile="%s"\n' % icon)
            shortcut.write('IconIndex=0\n')
    else:
        winshell.CreateShortcut(path, target, arguments, wDir, (icon, 0), '')


def create_desktop_shortcut(label, target='', arguments='', wDir='', icon=''):
    r"""Create a desktop shortcut link for all users

    Args:
        label  (str): Name of the shorcut (.lnk extension is appended if not provided)
        target (str) : path to application
        arguments (str): argument to pass to application
        wDir (str): working directory
        icon (str): path to ico file

    Returns:
        str: Path to the shortcut

    >>> create_desktop_shortcut(r'WAPT Console Management',target=r'c:\wapt\waptconsole.exe')
    u'C:\\Users\\Public\\Desktop\\WAPT Console Management.lnk'
    >>> create_desktop_shortcut(r'WAPT local status',target='http://localhost:8088/')
    u'C:\\Users\\Public\\Desktop\\WAPT local status.url'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk', '.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc_path = os.path.join(desktop(1), label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path, target, arguments, wDir, icon)
    return sc_path


def create_user_desktop_shortcut(label, target='', arguments='', wDir='', icon=''):
    r"""Create a desktop shortcut link for current user

    Args:
        label  (str): Name of the shorcut (.lnk extension is appended if not provided)
        target (str) : path to application
        arguments (str): argument to pass to application
        wDir (str): working directory
        icon (str): path to ico file

    Returns:
        str: Path to the shortcut


    >>> create_user_desktop_shortcut(r'WAPT Console Management',target='c:\\wapt\\waptconsole.exe')
    u'C:\\Users\\htouvet\\Desktop\\WAPT Console Management.lnk'
    >>> create_user_desktop_shortcut(r'WAPT local status',target='http://localhost:8088/')
    u'C:\\Users\\htouvet\\Desktop\\WAPT local status.url'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk', '.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    sc_path = os.path.join(desktop(0), label)
    if os.path.isfile(sc_path):
        os.remove(sc_path)
    create_shortcut(sc_path, target, arguments, wDir, icon)
    return sc_path


def create_programs_menu_shortcut(label, target='', arguments='', wDir='', icon='', folder=None):
    r"""Create a program menu shortcut link for all users

    if label's extension is url, a http shortcut is created, else creates a file system shortcut.

    Args:
        label  : Name of the shorcut (.lnk extension is appended if not provided.)
        target : path to application
        arguments : argument to pass to application
        wDir : working directory
        icon : path to ico file
        folder (str) : folder of Programs Menu where to put the shortcut.

    Returns:
        str: Path to the shortcut

    >>> create_programs_menu_shortcut('Dev-TranquilIT', target='http://dev.tranquil.it')
    u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Dev-TranquilIT.url'
    >>> create_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe'))
    u'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Console WAPT.lnk'

    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk', '.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    if folder is None:
        sc = os.path.join(winshell.programs(1), label)
    else:
        sc = os.path.join(winshell.programs(1), folder, label)
    ensure_dir(sc)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc, target, arguments, wDir, icon)
    return sc


def create_user_programs_menu_shortcut(label, target='', arguments='', wDir='', icon='', folder=None):
    r"""Create a shortcut in the start menu of the current user

       If label extension is url, create a Http shortcut, else a file system shortcut.

    Args:
        label  : Name of the shorcut (.lnk or .url extension is appended if not provided.)
        target : path to application
        arguments : argument to pass to application
        wDir : working directory
        icon : path to ico file
        folder (str) : folder of User's Programs Menu where to put the shortcut.

    Returns:
        str: Path to the shortcut

    >>> create_user_programs_menu_shortcut('Doc-TranquilIT', target='https://doc.wapt.fr')
    u'C:\\Users\\htouvet\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Doc-TranquilIT.url'
    >>> create_user_programs_menu_shortcut('Console WAPT', target=makepath('c:/wapt','waptconsole.exe'))
    u'C:\\Users\\htouvet\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Console WAPT.lnk'
    """
    ext = os.path.splitext(label)[1].lower()
    if not ext in ('.lnk', '.url'):
        if target.startswith('http://') or target.startswith('https://'):
            label += '.url'
        else:
            label += '.lnk'
    if folder is None:
        sc = os.path.join(winshell.programs(0), label)
    else:
        sc = os.path.join(winshell.programs(0), folder, label)
    ensure_dir(sc)
    if os.path.isfile(sc):
        os.remove(sc)
    create_shortcut(sc, target, arguments, wDir, icon)
    return sc


def remove_programs_menu_folder(folder):
    """Remove a folder from the start menu of all users

    Args:
        folder(str): folder to remove
    """
    programs_menu_folder = makepath(winshell.programs(common=1), folder)
    if isdir(programs_menu_folder):
        remove_tree(programs_menu_folder)


def remove_programs_menu_shortcut(label, folder=None):
    """Remove a shortcut from the start menu of all users

    Args:
        label (str): label of shortcut without extension
        folder (str): subfolder of Programs menu where the shortcut resides.
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    if folder is None:
        remove_file(makepath(winshell.programs(common=1), label))
    else:
        remove_file(makepath(winshell.programs(common=1), folder, label))


def remove_user_programs_menu_shortcut(label, folder=None):
    """Remove a shortcut from the start menu of current user

    Args:
        label (str): label of shortcut without extension
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    if folder is None:
        remove_file(makepath(winshell.programs(common=0), label))
    else:
        remove_file(makepath(winshell.programs(common=0), folder, label))


def remove_user_programs_menu_folder(folder):
    """Remove a folder from the start menu of current user

    Args:
        folder(str): folder to remove
    """
    user_programs_menu_folder = makepath(winshell.programs(common=0), folder)
    if isdir(user_programs_menu_folder):
        remove_tree(user_programs_menu_folder)


def remove_desktop_shortcut(label):
    """Remove a shortcut from the desktop of all users

    Args:
        label (str): label of shortcut without extension
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(os.path.join(desktop(1), label))


def remove_user_desktop_shortcut(label):
    """Remove a shortcut from the desktop of current user

    Args:
        label (str): label of shortcut without extension
    """
    if not (label.endswith('.lnk') or label.endswith('.url')):
        label += '.lnk'
    remove_file(os.path.join(desktop(0), label))


def get_shortcut_properties(shortcut_filename):
    r"""Return a dict of shortcut properties

    Args:
        shortcut_filename (str): path to shortcut

    Returns:
        dict: properties of shortcut
             'description','hotkey','icon_location','lnk_filepath','show_cmd','show_cmd','show_states','working_directory'

    >>> lnk = get_shortcut_properties(shortcut_filename)
    >>> 'path' in lnk and 'description' in lnk
    True
    """
    result = {}
    frmlnk = winshell.Shortcut.from_lnk(shortcut_filename)
    result = {'arguments': frmlnk.arguments,
              'description': frmlnk.description,
              'hotkey': frmlnk.hotkey,
              'icon_location': frmlnk.icon_location,
              'lnk_filepath': frmlnk.lnk_filepath,
              'path': frmlnk.path,
              'show_cmd': frmlnk.show_cmd,
              'show_states': frmlnk.show_states,
              'working_directory': frmlnk.working_directory}
    return result



def win32com_ensure_dispatch_patch(prog_id):
    global win32com
    try:
        return win32com.client.gencache.EnsureDispatch(prog_id)
    except AttributeError:
        # Remove cache and try again.
        MODULE_LIST = [m.__name__ for m in sys.modules.values()]
        for module in MODULE_LIST:
            if re.match(r'win32com\.gen_py\..+', module):
                del sys.modules[module]
        shutil.rmtree(os.path.join(tempfile.gettempdir(), 'gen_py'))
        import win32com.client
        return win32com.client.gencache.EnsureDispatch(prog_id)


def get_version_from_binary(filename, property_name='ProductVersion'):
    r""" Get installer version from file informations, for now, only exe and msi files are compatibles

    Args:
        filename (str): path to the file
        property_name (str): selected property

    Returns:
        str: version number

     """
    if filename.endswith(".msi"):
        return get_msi_properties(filename).get(property_name, None)
    else:
        return get_file_properties(filename).get(property_name, None)


def getscreens():
    screens = []
    try:
        objWMI = GetObject(r'winmgmts:\\.\root\WMI').InstancesOf('WmiMonitorID')
        for monitor in objWMI:
            try:
                devPath = monitor.InstanceName.split('_')[0]
                regPath = 'SYSTEM\\CurrentControlSet\\Enum\\'+devPath+'\\Device Parameters'
                registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, regPath, 0, winreg.KEY_READ)
                edid, regtype = winreg.QueryValueEx(registry_key, "EDID")
                winreg.CloseKey(registry_key)
                if not edid: continue
                b64_edid = base64.b64encode(edid).decode('utf-8')
                #print ('DEBUG: EDID Version: '+str(edid[18])+'.'+str(edid[19]))
                #dtd = 54  # start byte of detailed timing desc.
                # upper nibble of byte x 2^8 combined with full byte
                #hres = ((edid[dtd+4] >> 4) << 8) | edid[dtd+2]
                #vres = ((edid[dtd+7] >> 4) << 8) | edid[dtd+5]
                edidp = pyedid.parse_edid(edid)
                manufacturer = edidp.manufacturer or "Unknown"
                resolution = "-"
                if(manufacturer == "Unknown"): manufacturer += " ("+str(edidp.manufacturer_id)+")"
                if(len(edidp.resolutions) > 0): resolution = str(edidp.resolutions[-1][0])+" x "+str(edidp.resolutions[-1][1])
                screens.append({
                    "b64_edid" : b64_edid,
                    "name": edidp.name,
                    "manufacturer": manufacturer,
                    "manufactured": str(edidp.year or "-"),
                    "resolution": resolution,
                    "size": str(edidp.width)+" x "+str(edidp.height),
                    "type": str(edidp.product_id or "-"),
                    "serialno": edidp.serial or "-",
                    "technology": str(edidp.type or "-")
                })
            except Exception:
                pass
    except Exception:
        pass
    return screens

def get_antivirus_info():
    list_av = []
    try:
        objWMI = GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiVirusProduct')


        for obj in objWMI:
            dict_av_info = {}
            if obj.displayName != None:
                dict_av_info['name'] = str(obj.displayName)
            else:
                dict_av_info['name'] = ""
            if obj.instanceGuid != None:
                dict_av_info["instanceGuid"] = str(obj.instanceGuid)
            if obj.pathToSignedProductExe != None:
                dict_av_info["pathToSignedProductExe"] = str(obj.pathToSignedProductExe)
            if obj.pathToSignedReportingExe != None:
                dict_av_info["pathToSignedReportingExe"] = str(obj.pathToSignedReportingExe)
            if obj.productState != None:
                dict_av_info["productState"] = str(obj.productState)
            if hasattr(obj,'timestamp') and obj.timestamp != None:
                dict_av_info["timestamp"] = str(obj.timestamp)


            if  "Windows Defender" in dict_av_info['name'] :

                objWMI = GetObject('winmgmts:\\\\.\\root\\microsoft\\windows\\defender').InstancesOf('MSFT_MpComputerStatus')

                for obj in objWMI:
                    dict_av_info["AMProductVersion"] = obj.AMProductVersion
                    dict_av_info["AntivirusEnabled"] = str(obj.AntivirusEnabled)
                    dict_av_info["AntivirusSignatureVersion"] = obj.AntivirusSignatureVersion
                    if not dict_av_info["AntivirusSignatureVersion"]:
                        dict_av_info["AntivirusSignatureVersion"] = registry_readstring(HKEY_LOCAL_MACHINE,"SOFTWARE/Microsoft/Windows Defender/Signature Updates","AVSignatureVersion")

            #TODO   https://github.com/fusioninventory/fusioninventory-agent/blob/df6e8e10e498ec4d7a8a883568a8474a329dbb16/lib/FusionInventory/Agent/Task/Inventory/Win32/AntiVirus.pm#L120

            if  "McAfee" in dict_av_info['name'] :
                pass

            if  "Kaspersky" in dict_av_info['name'] :
                pass

            if  "ESET" in dict_av_info['name'] :
                pass

            if  "McAfee" in dict_av_info['name'] :
                pass

            if  "Avira" in dict_av_info['name'] :
                pass

            if  "Security Essentials" in dict_av_info['name'] :
                pass

            if  "F-Secure" in dict_av_info['name'] :
                pass

            if  "Bitdefender" in dict_av_info['name'] :
                pass

            if  "Norton" in dict_av_info['name'] :
                pass

            list_av.append(dict_av_info)
    except:
        pass

    return list_av

def get_kb_dism_name():

    dict_dism_kb={}

    with disable_file_system_redirection():
        for f in glob.glob(r'C:\Windows\servicing\Packages\*.mum'):
            identifier = None
            dism_name = None
            tree =  ET.parse(f)
            root =  tree.getroot()
            for child in root:
                if child.tag == '{urn:schemas-microsoft-com:asm.v3}assemblyIdentity':
                    dism_name = child.attrib['name'] + '~' + child.attrib['publicKeyToken'] + "~" + child.attrib['processorArchitecture'] + '~~' + child.attrib['version']
                if child.tag == '{urn:schemas-microsoft-com:asm.v3}package':
                    identifier = child.attrib['identifier']

            if dism_name and identifier :
                dict_dism_kb[dism_name] = identifier

        dict_final_dism_kb = {}
        data = run('dism /Online /Get-Packages')
        for entry in data.splitlines():
            if entry.split(' : ',1)[-1] in dict_dism_kb:
                name_entry = entry.split(' : ',1)[-1]
                dict_final_dism_kb[dict_dism_kb[name_entry].lower()] = name_entry

    return dict_final_dism_kb


