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

import re
import wmi
import time
import ujson
import requests
import datetime
import os

from waptutils import run, logger, currentdatetime, Version
from setuphelpers import service_start, service_stop, service_installed, service_is_running, windows_version
from setuphelpers import registry_set, registry_readstring, reg_key_exists
from setuphelpers import HKEY_LOCAL_MACHINE, REG_DWORD, win32com_ensure_dispatch_patch, installed_windows_updates
import win32service
import win32con
from waptutils import get_disk_free_space # backward compatibility for fixwua packages

# parameter to cache kb to speedup process, cf. is_kb_installed()
_installed_update = None


class DisableWUAAgent(object):
    """Context object to disable wauserv and wsearch services to speed up upgrading process"""

    def __init__(self):
        self.old_au_options = None
        self.old_wsearch_start = None
        self.old_wsearch_running = None
        self.old_wuauserv_running = None

    def __enter__(self):
        self.old_au_options = registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', 0)
        self.old_wsearch_start = registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\WSearch', 'Start')
        self.old_wsearch_running = service_installed('wsearch') and service_is_running('wsearch') or None
        self.old_wuauserv_running = service_is_running('wuauserv')

        # disabling search indexer while upgrading for speeding up the process
        # note : on desactive windows search car il consomme beaucoup de cpu lors de l'install du service pack
        registry_set(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\WSearch', 'Start', 4)
        if self.old_wsearch_running:
            print('Stopping wsearch')
            run('net stop wsearch', accept_returncodes=[0, 2])

        # disable automatic update download
        print("disabling wuau automatic downloads")
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', 1)

        # stop wuauserv
        if self.old_wuauserv_running:
            print('Stopping wauserv')
            run('net stop wuauserv', accept_returncodes=[0, 2])

    def __exit__(self, type, value, tb):
        print("re-enabling wuauserv previous state")
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', self.old_au_options)
        if self.old_wuauserv_running:
            print('Starting wauserv')
            run('net start wuauserv', accept_returncodes=[0, 2])

        print("re-enabling wsearch previous state")
        registry_set(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\WSearch', 'Start', self.old_wsearch_start)
        if self.old_wsearch_running:
            print('Starting wsearch')
            run('net start wsearch', accept_returncodes=[0, 2])


class EWUAFixException(Exception):
    def __init__(self, *args):
        if isinstance(args[0], str):
            msg = '%s: %s' % (currentdatetime(), args[0])
        else:
            msg = args[0]
        Exception.__init__(self, msg, *args[1:])


class EWUABadSystem(EWUAFixException):
    pass


class EWUARebootNeeded(EWUAFixException):
    pass


class EWUAPendingWaptTasks(EWUAFixException):
    pass


def is_kb_installed(hotfixid, use_cache=True):
    global _installed_update
    if not use_cache:
        _installed_update = None
    if _installed_update is None:
        _installed_update = installed_windows_updates()
    if [kb for kb in _installed_update if kb['HotFixID'].upper() == hotfixid.upper()]:
        return True
    return False


def lower_priority_wuauserv():
    service_manager_handle = win32service.OpenSCManager(None,
                                                        None, win32con.GENERIC_READ)
    service_handler = win32service.OpenService(service_manager_handle,
                                               'wuauserv', win32service.SC_MANAGER_ALL_ACCESS)
    pid = win32service.QueryServiceStatusEx(service_handler)["ProcessId"]
    run('wmic process where handle=%s CALL setpriority "below normal"' % pid)


def ensure_wuauserv_in_own_svchost():
    """ Setup wuauserv (windows update agent process) in its own svchost
    process in order to isolate cpu and memory consumption
    """
    service_manager_handle = win32service.OpenSCManager(None,
                                                        None, win32con.GENERIC_READ)
    service_handler = win32service.OpenService(service_manager_handle,
                                               'wuauserv', win32service.SC_MANAGER_ALL_ACCESS)
    if win32service.QueryServiceConfig(service_handler)[0] == 16:
        return True

    print('Put wuauserv in its own svchost process to isolate cpu consumption')
    run("sc config wuauserv type= own")
    if service_is_running("wuauserv"):
        print("restarting Windows update service to take new configuration into account")
        service_stop("wuauserv")
        time.sleep(2)
        service_start("wuauserv")
    else:
        print('Service wuauserv was not running before reconfiguration, we do not restart it')


def waiting_for_reboot():
    """Return True if system is waiting for reboot to finish an install/update process
    """
    # Query WUAU from the registry
    if reg_key_exists(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") or \
            reg_key_exists(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") or \
            reg_key_exists(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Updates\UpdateExeVolatile'):
        return True
    return False


def get_service_pack_version():
    """Return service pack version of current system as int()

    Returns:
          0 : no service pack installed
          1 : sp1 installed
          2 : sp2 installed
    """
    return wmi.WMI().Win32_OperatingSystem()[0].ServicePackMajorVersion


def list_scheduled_tasks():
    """Return a list of current existing tasks in windows scheduler

    Example :
    >>> list_scheduled_tasks()
        [u'WAPT User Profile Cleanup', u'waptwua-install', u'waptwua-scan']
    """
    scheduler = win32com_ensure_dispatch_patch("Schedule.Service")
    scheduler.Connect()
    task_folder = scheduler.GetFolder("\\")
    tasks = task_folder.GetTasks(1)
    return [task.Name for task in tasks]


def wait_wapt_pending_tasks(wapt, timeout=30):
    """Query local waptservice and wait until there is no pending tasks in queue

    Args:
        wapt (Wapt): wapt client instance
        timeout (float): maximum delay in seconds to wait for pending tasks to terminate

    Returns:
        True if no pending tasks
        None if unable to check (no waptservice running ?)

    Raises:
        EWUAPendingWaptTasks if tiemout has exprired and there are still tasks in queue

    """
    if not wapt:
        return None
    try:
        start_time = time.time()
        while 1:
            waptservice_port = '8088'
            if wapt.config.has_option('global', 'waptservice_port'):
                waptservice_port = wapt.config.get('global', 'waptservice_port')
            tasks = ujson.loads(requests.get('http://127.0.0.1:%s/tasks.json' % (waptservice_port,), proxies={'http': None}, timeout=(5, 5)).content)
            running = tasks['running']
            pending = tasks['pending']
            wapt_running = running is not None or len(pending) > 0
            if not wapt_running:
                return True
            if time.time()-start_time > timeout:
                raise EWUAPendingWaptTasks('Running: %s, Pending: %s' % (running, pending))
            else:
                time.sleep(5)
    except Exception as e:
        logger.error('Waptservice pending tasks check failed : %s' % e)
        return None


def schtasks_remove(task_name):
    """ Remove a task from the windows task scheduler"""
    print('%s Final remove scheduled task %s' % (currentdatetime(), task_name))
    if task_name in list_scheduled_tasks():
        run('schtasks /delete /f /tn "%s"' % task_name)
        print('[OK] Task %s removed' % (task_name,))
    else:
        logger.error("could not find task %s " % task_name)


def authorized_url_wsus(test_url):
    test_url = test_url.split('://')[1].split('/')[0]
    list_authorize_url = [r'windowsupdate\.microsoft\.com', r'.*\.windowsupdate.microsoft.com', r'.*\.update\.microsoft\.com', r'.*\windowsupdate\.com', r'download\.windowsupdate\.com', r'download\.microsoft\.com', r'.*\download\.windowsupdate\.com', r'wustat\.windows\.com', r'ntservicepack\.microsoft\.com', r'go\.microsoft\.com', r'.*.mp\.microsoft\.com']
    for test in list_authorize_url:
        if re.match(test, test_url):
            return True
    return False

def get_sha1_from_filename(filename):
    try:
        sha1sum_parts = os.path.basename(filename).rsplit('.', 1)[0].rsplit('_', 1)
        if sha1sum_parts:
            sha1sum = sha1sum_parts[1]
            # looks like hex sha1
            if len(sha1sum) == 40:
                return sha1sum
        return None
    except:
        # be safe...
        return None


def disable_automatic_updates():
    """Set automatic update to not search, not download and not install
    automatically (may raise warning)

    """
    if registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions') == 1:
        logger.info("automatic download and install alredy disabled, skipping")
        return

    logger.info("auto update enabled, disabling")

    registry_set(HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
                 'AUOptions', 0x1, REG_DWORD)
    try:
        if service_is_running('wuauserv'):
            time.sleep(1)
            service_stop('wuauserv')
            time.sleep(3)
        service_start('wuauserv')
    except Exception as e:
        logger.error('Could not restart wuauserv: %s', str(e))
        raise e


def enable_automatic_updates():
    """
        set automatic updates to search, download and install (default value)
    """
    logger.info("auto update disabled, enabling")
    registry_set(HKEY_LOCAL_MACHINE,
                 r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
                 'AUOptions', 0x4, REG_DWORD)
    try:
        if service_is_running('wuauserv'):
            service_stop('wuauserv')
            time.sleep(2)
        service_start('wuauserv')
    except Exception as e:
        logger.error('Could not restart wuauserv: %s', str(e))
        raise e


def disable_gwx():
    """Disable automatic upgrade to win10 (GWX : get windows 10)
    """
    try:
        os_version = windows_version(2)
        if os_version < Version('6.1'):
            logger.info('OS version < 6.1/win7, no need to disable OS upgrades.')
            return
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'DisableOSUpgrade', 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Gwx', 'DisableGwx', 1, REG_DWORD)
    except Exception as e:
        logger.error('Problem while disableing automatic OS upgrade to win10. beware of GWX: %s', str(e))


def datetime_for_reg(adatetime=None):
    if adatetime is None:
        adatetime = datetime.datetime.now()
    return adatetime.strftime('%y-%m-%d %H:%M:%S')
