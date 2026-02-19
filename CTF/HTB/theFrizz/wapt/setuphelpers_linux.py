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
import os
import socket
import platform
import subprocess
import logging
import glob
import datetime
import re
import locale
import threading
import grp
import psutil

from setuphelpers_unix import host_info_common_unix,dmi_info_common_unix
from waptutils import isfile,fixed_columns_to_dicts,ensure_unicode,run
from contextlib import contextmanager

LOCALE_LOCK = threading.Lock()

@contextmanager
def setlocale(name):
    with LOCALE_LOCK:
        saved = locale.setlocale(locale.LC_ALL)
        try:
            yield locale.setlocale(locale.LC_ALL, name)
        finally:
            locale.setlocale(locale.LC_ALL, saved)

try:
    import distro
    linux_distribution = distro.linux_distribution(False)
except ImportError:
    linux_distribution = (None, None, None)

logger = logging.getLogger('waptcore')

def is_linux64():
    return platform.machine().endswith('64')

isLinux64 = is_linux64

def get_distrib_version():
    return linux_distribution[1]

def get_os_version():
    return get_distrib_version()

def get_distrib_linux():
    return linux_distribution[0]


def get_code_name_version():
    return linux_distribution[2]


def get_hostname():
    try:
        return socket.getfqdn().lower()
    except:
        return ""


def type_debian():
    return isfile('/etc/debian_version')

is_debian_based=type_debian

def is_debian():
    return linux_distribution is not None and linux_distribution[0].lower() == 'debian'

def get_debian_version():
    if isfile('/etc/debian_version'):
        with open('/etc/debian_version') as f:
            debian_version = f.read().strip()
        return debian_version

def type_redhat():
    return isfile('/etc/redhat-release')

def type_rhel():
    return linux_distribution is not None and linux_distribution[0].lower() in ('rhel', 'centos', 'oracle','almalinux','rocky')

is_rhel_based=type_rhel
is_redhat_based=type_redhat

def local_users():
    result = []
    with open('/etc/passwd') as f:
        for u in [entry.split(':',1) for entry in f.read().splitlines]:
            if not u[0]:
                continue
            result.append(u[0])
    return result

def host_info():
    info = host_info_common_unix()
    try:
        dmi = dmi_info()
        info['system_manufacturer'] = dmi['System_Information']['Manufacturer']
        info['system_productname'] = dmi['System_Information']['Product_Name']
    except:
        logger.warning('Error while running dmidecode, dmidecode needs root privileges')
        pass

    info['os_release_name'] = get_code_name_version().lower()
    if info['os_release_name'] == 'core':
        info['os_release_name'] = get_distrib_linux() + ' ' +  get_distrib_version()
    info['platform'] = platform.system()
    info['os_name'] = get_distrib_linux()
    info['os_version'] = get_distrib_version()

    if is_debian():
        info['debian_version'] = get_debian_version()

    if type_debian():

        info['reboot_needed'] = isfile('/var/run/reboot-required')

        info['reboot-required.pkgs'] = []
        if isfile('/var/run/reboot-required.pkgs'):
            with open('/var/run/reboot-required.pkgs','r') as f:
                info['reboot-required.pkgs'] = f.read().split('\n')

    info['linux64'] = isLinux64()

    with open('/etc/group') as f:
        info['local_groups'] = {group.split(':')[0]:[m for m in group.split(':')[3].split(',') if m != '' ] for group in f.read().split('\n') if group.split(':')[0] != ''}
    info['local_users'] = []
    with open('/etc/passwd') as f:
        for u in [entry.split(':') for entry in f.read().split('\n')]:
            if not u[0]:
                continue
            info['local_users'].append(u[0])
            gr_struct = grp.getgrgid(u[3])
            if gr_struct.gr_name in info['local_groups']:
                if u[0] not in info['local_groups'][gr_struct.gr_name]:
                    info['local_groups'][gr_struct.gr_name].append(u[0])

    return info


def dmi_info():
    return dmi_info_common_unix()


def listcontrol_to_dict(cmd=None, first_entry=None):
    if os.path.isfile(cmd):
        with open(cmd,'r') as f :
            list_package = '\n' + f.read()
    else:
        list_package = '\n' + run(cmd)
    list_control=[]
    for i in list_package.split(first_entry):
        if not i.strip('\n'):
            continue
        list_control.append(first_entry.replace('\n','') + i)

    list_package = []
    for pkg in list_control:
        entry = {}
        gpg = False
        for l in pkg.split('\n'):

            if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in l:
                gpg = True
                continue
            if '-----END PGP PUBLIC KEY BLOCK-----' in l:
                gpg = False
                continue
            if gpg :
                continue

            if not l:
                continue
            if (':' in l) and (not '::' in l) and (not l.startswith(' ')) :
                key = l.split(':',1)[0].strip().lower()
                value = l.split(':',1)[1].strip()
                entry[key] = value.strip('\n')
            else:
                entry[key] =  entry[key].strip('\n') + '\n' + l
        list_package.append(entry)
    return list_package


def installed_softwares(keywords=None, name=None, ignore_empty_names=True):
    """ Return list of installed software from apt or rpm

        Args:
            keywords (str or list): string to lookup in key, display_name or publisher fields

        Returns:
            list of dicts: [{'key', 'name', 'version', 'install_date', 'install_location'
                         'uninstall_string', 'publisher','system_component'}]
    """
    name_re = re.compile(name) if name is not None else None
    list_installed_softwares = []

    if isinstance(keywords, str):
        keywords = keywords.lower().split()
    elif isinstance(keywords, bytes):
        keywords = str(keywords).lower().split()
    elif keywords is not None:
        keywords = [ensure_unicode(k).lower() for k in keywords]
    else:
        keywords = None

    def check_words(target, words):
        mywords = target.lower()
        result = not words or mywords
        for w in words:
            result = result and w in mywords
        return result
    if type_debian():
        try:
            r = listcontrol_to_dict('dpkg-query -s','\nPackage: ')
        except:
            r = listcontrol_to_dict('/var/lib/dpkg/status','\nPackage: ')
        dict_info_test = {}
        for fileinfotest in glob.glob("/var/lib/dpkg/info/*.list"):
             dict_info_test[fileinfotest.rsplit(':',1)[0] + '.list'] = fileinfotest

        for pkg in r:
            path_dpkg_info = "/var/lib/dpkg/info/"
            if pkg['status'] == "install ok installed" and (not ignore_empty_names or pkg.get('package', '') != '') and (
                (name_re is None or name_re.match(pkg['package'])) and
                (keywords is None or check_words(' '.join([pkg['package'], pkg['version'] , pkg.get('homepage', '') ]), keywords))):

                path_dpkg_info_full = path_dpkg_info + pkg['package'] +'.list'
                if not os.path.isfile(path_dpkg_info_full):
                    if path_dpkg_info_full in dict_info_test:
                        path_dpkg_info_full = dict_info_test[path_dpkg_info_full]
                try:
                    install_date = os.path.getctime(path_dpkg_info_full)
                    install_date = datetime.datetime.fromtimestamp(install_date).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    install_date = ''
                list_installed_softwares.append({
                    'key': pkg['package'],
                    'name': pkg['package'],
                    'version': pkg['version'],
                    'install_date': install_date,
                    'install_location': '',
                    'uninstall_string': '',
                    'publisher': pkg.get('homepage',''),
                    'system_component': ''})

    elif type_redhat():
        for header in listcontrol_to_dict('LANG="en_US.UTF-8" rpm -qai','Name        : '):
            if (not ignore_empty_names or header.get('name', '') != '') and (
                (name_re is None or name_re.match(ensure_unicode(header['name']))) and
                (keywords is None or check_words(' '.join([ensure_unicode(header['name']), ensure_unicode(header.get('url', ''))]), keywords))):

                with setlocale('C'):
                    try:
                        dateformat = datetime.datetime.strptime(header['install date'],'%a %b %d %H:%M:%S %Y').strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        dateformat = datetime.datetime.strptime(header['install date'].rsplit(' ',1)[0],'%a %d %b %Y %H:%M:%S %p').strftime('%Y-%m-%d %H:%M:%S')

                list_installed_softwares.append({
                    'key': '%s_%s' % (ensure_unicode(header['name']),ensure_unicode(header['version'])),
                    'name': ensure_unicode(header['name']),
                    'version': ensure_unicode(header['version']),
                    'install_date': dateformat,
                    'install_location': '',
                    'uninstall_string': '',
                    'publisher': ensure_unicode(header.get('url','')),
                    'system_component': ''})
    else:
        list_installed_softwares.append({'key': 'Distribution not supported yet', 'name': 'Distribution not supported yet', 'version': 'Distribution not supported yet', 'install_date': 'Distribution not supported yet',
                                         'install_location': 'Distribution not supported yet', 'uninstall_string': 'Distribution not supported yet', 'publisher': 'Distribution not supported yet', 'system_component': 'Distribution not supported yet'})

    try:
        for snap in get_snap_softwares():
            if (not ignore_empty_names or snap['name'] != '') and (
                (name_re is None or name_re.match(snap['name'])) and
                (keywords is None or check_words(snap['name']), keywords)):
                list_installed_softwares.append(snap)
    except Exception as e:
        logger.warning('Error with snap list %s' % e)
        pass

    return list_installed_softwares

def get_snap_softwares():
          list_installed_softwares=[]
          cmd = "snap list --color=never --unicode=always"
          proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
stderr=subprocess.PIPE, shell=True, universal_newlines=True)
          stdout, stderr = proc.communicate()
          retcode = proc.returncode
          if retcode == 0:
             i=0
             for line in stdout.split("\n"):
                  # Skip header
                  if i==0:
                      i+=1
                      continue
                  else:
                      i+=1
                      package=line.split()
                      if package != []:
                          snap = {}
                          snap['name'] = package[0]
                          snap['version'] = package[1]
                          snap['revision'] = package[2]
                          snap['tracking'] = package[3]
                          snap['publisher'] = 'snap/' + package[4]
                          snap['notes'] = package[5]
                          if  os.path.isfile(os.path.join("/var/lib/snapd/snaps/", package[0] + "_" + package[2] + ".snap")):
                              snap['install_path'] = os.path.join("/var/lib/snapd/snaps/", package[0] + "_" + package[2] + ".snap")
                              snap['install_date'] = os.path.getctime(snap['install_path'])
                              snap['install_date'] = datetime.datetime.fromtimestamp(snap['install_date']).strftime('%Y-%m-%d %H:%M:%S')
                          else:
                              snap['install_path'] = ''
                              snap['install_date'] = ''
                          list_installed_softwares.append({
                              'key':'snap_' + snap['name'],
                              'name':snap['name'],
 'version':snap['version']+"-"+snap['revision'],
 'install_date':snap['install_date'],
 'install_location':snap['install_path'],
                              'uninstall_string':"snap",
                              'publisher':snap['publisher'],
                              'system_component':''})
          return list_installed_softwares


def uninstall_key_exists(uninstallkey):
    uninstallkey = uninstallkey.lower()
    for software in installed_softwares():
        if software['name'].lower()==uninstallkey:
            return True
    return False


def install_apt(package, allow_unauthenticated=False):
    """
    Install package from APT repositories

    """
    update_apt()
    if allow_unauthenticated:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated %s' % package)
    else:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get install -y %s' % package)


def uninstall_apt(package, autoremove=False):
    """
    Remove package with APT

    """
    if autoremove:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get remove --autoremove -y %s' % package)
    else:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get remove -y %s' % package)


def install_deb(path_to_deb):
    """
    Install .deb package from file
    """
    try:
        return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg -i %s' % path_to_deb)
    except:
        return install_required_dependencies_apt()

def install_package_if_needed(package_name):
    if not uninstall_key_exists(package_name):
        if type_debian():
            return install_apt(package_name)
        if type_redhat():
            return install_yum(package_name)
        else:
            raise Exception('not supported')

def purge_deb(deb_name):
    return run('LANG=C DEBIAN_FRONTEND=noninteractive dpkg --purge %s' % deb_name)


def install_required_dependencies_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -f -y install')


def autoremove_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y autoremove')


def install_yum(package):
    return run('LANG=C yum install -y %s' % (package))


def install_dnf(package):
    return install_yum(package)


def uninstall_yum(package):
    return run('LANG=C yum remove -y %s' % package)


def uninstall_dnf(package):
    return uninstall_yum(package)


def autoremove_yum():
    return run('LANG=C yum autoremove -y')


def autoremove_dnf():
    return autoremove_yum()


def update_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y update')


def upgrade_apt():
    return run('LANG=C DEBIAN_FRONTEND=noninteractive apt-get -y upgrade')


def update_yum():
    return run('LANG=C yum update -y')


def update_dnf():
    return update_yum()


def upgrade_yum():
    return run('LANG=C yum upgrade -y')


def upgrade_dnf():
    return upgrade_yum()


def install_rpm(package):
    return run('LANG=C yum localinstall -y %s' % (package))


def systemd_start_service(servicename):
    return run('LANG=C systemctl start %s' % (servicename))


def systemd_stop_service(servicename):
    return run('LANG=C systemctl stop %s' % (servicename))


def systemd_restart_service(servicename):
    return run('LANG=C systemctl restart %s' % (servicename))


def systemd_status_service(servicename):
    return run('LANG=C systemctl status %s' % (servicename))


def systemd_enable_start_service(servicename):
    return run('LANG=C systemctl enable --now %s' % (servicename))


def systemd_enable_service(servicename):
    return run('LANG=C systemctl enable %s' % (servicename))


def systemd_disable_service(servicename):
    return run('LANG=C systemctl disable %s' % (servicename))


def systemd_daemon_reload():
    return run('LANG=C systemctl daemon-reload')

def service_list():
    result = {}

    systemd_list =run('LANG=C systemctl systemctl list-units')
    units = fixed_columns_to_dicts(systemd_list)

    for unit in units:
        if unit['UNIT'].endswith('.service'):
            result[unit['UNIT']] = unit

    return result

def running_on_ac():
    t = psutil.sensors_battery()
    if not t:
        return True
    return t.power_plugged
