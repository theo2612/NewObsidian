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
import platform
import subprocess
import logging
import glob
import plistlib
import datetime
import re
import tempfile
import pathlib

import xml.etree.ElementTree as etree

from waptutils import isfile,isdir,copytree2,Version,run,error,makepath,ensure_unicode

from setuphelpers_unix import dmi_info_common_unix,host_info_common_unix,remove_tree,killalltasks,get_domain_from_socket,local_group_members
from setuphelpers_unix import *

logger = logging.getLogger('waptcore')

def local_users():
    return [u for u in run('dscl . list /Users').split('\n') if not u.startswith('_')]



_mac_ver = None

def mac_ver():
    """ platform.mac_ver() does not return the correct version of macOS, see
        https://stackoverflow.com/questions/65290242/pythons-platform-mac-ver-reports-incorrect-macos-version
    """
    global _mac_ver
    if _mac_ver is None:
        _mac_ver = platform.mac_ver()[0]
        if Version(_mac_ver) >= Version('10.16'):
            _mac_ver = run('sw_vers -productVersion').strip()
    return _mac_ver

def get_os_version():
    return mac_ver()


class MacOSVersions(object):
    """Helper class to get numbered macOS version from macOS name version

    Sources:
    https://en.wikipedia.org/wiki/MacOS_version_history

    ... versionadded:: 2.5

    """
    Sonoma          = Version("14.0", 2)
    Ventura         = Version("13.0", 2)
    Monterey        = Version("12.0", 2)
    BigSur          = Version("11.0", 2)
    Catalina        = Version("10.15", 2)
    Mojave          = Version("10.14", 2)
    HighSierra      = Version("10.13", 2)
    Sierra          = Version("10.12", 2)
    ElCapitan       = Version("10.11", 2)
    Yosemite        = Version("10.10", 2)
    Mavericks       = Version("10.9", 2)
    MountainLion    = Version("10.8", 2)
    Lion            = Version("10.7", 2)
    SnowLeopard     = Version("10.6", 2)
    Leopard         = Version("10.5", 2)
    Tiger           = Version("10.4", 2)
    Panther         = Version("10.3", 2)
    Jaguar          = Version("10.2", 2)
    Puma            = Version("10.1", 2)
    Cheetah         = Version("10.0", 2)


def get_release_name(lower=True):
    dict_version = {
        "14"    : "Sonoma",
        "13"    : "Ventura",
        "12"    : "Monterey",
        "11"    : "Big Sur",
        "10.15" : "Catalina",
        "10.14" : "Mojave",
        "10.13" : "High Sierra",
        "10.12" : "Sierra",
        "10.11" : "El Capitan",
        "10.10" : "Yosemite",
        "10.9"  : "Mavericks",
        "10.8"  : "Mountain Lion",
        "10.7"  : "Lion",
        "10.6"  : "Snow Leopard",
        "10.5"  : "Leopard",
        "10.4"  : "Tiger",
        "10.3"  : "Panther",
        "10.2"  : "Jaguar",
        "10.1"  : "Puma",
        "10.0"  : "Cheetah",
    }
    version_mac_number = mac_ver()
    for i in range(5,0,-1):
        if str(Version(version_mac_number,i)) in dict_version:
            if lower:
                return dict_version[str(Version(version_mac_number, i))].lower()
            else:
                return dict_version[str(Version(version_mac_number, i))]

    #guess name
    if not isfile('/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf'):
        return None
    with open('/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf','r') as f:
        data= f.read()
    if not "SOFTWARE LICENSE AGREEMENT FOR macOS " in data:
        return None
    if lower:
        return data.split("SOFTWARE LICENSE AGREEMENT FOR macOS ")[1].split("\\")[0].strip().lower()
    else:
        return data.split("SOFTWARE LICENSE AGREEMENT FOR macOS ")[1].split("\\")[0].strip()


def host_info():
    """ Read main workstation informations, returned as a dict """

    info = host_info_common_unix()
    try:
        dmi = dmi_info()
        info['system_manufacturer'] = dmi['Chassis_Information']['Manufacturer']
        info['system_productname'] = dmi['System_Information']['Product_Name']
    except Exception as e:
        print('Error while getting system_profiler_info: %s' % e)
        pass

    info['system_profiler'] = system_profiler_info()

    info['os_name'] = 'macOS %s ' % mac_ver()
    info['os_version'] = str(mac_ver())
    info['os_release_name'] = get_release_name()
    info['platform'] = 'macOS'

    info['computer_name'] = get_hostname()
    info['computer_fqdn'] = get_hostname()
    info['dnsdomain'] = get_domain_from_socket()


    info['local_groups'] = {g: local_group_members(g) for g in run('dscl . list /groups').splitlines() if g and not g.startswith('_')}
    info['local_users'] = [u for u in run('dscl . list /Users').splitlines() if u and not u.startswith('_')]

    return info

# TODO
def service_list():
    return None

def get_hostname():
    try:
        return subprocess.check_output('/bin/hostname',shell=True).lower().strip().decode('utf8')
    except:
        return ""


def system_profiler_info():
    """Returns data from the system_profiler command. Created because of an invalid UUID in dmidecode. """
    sphdt_string = run('system_profiler SPHardwareDataType -xml')
    sphdt_data = plistlib.loads(sphdt_string.encode('utf-8'))


    # minimal keys
    #'UUID', 'IdentifyingNumber', 'Name', 'Vendor'
    system_data = sphdt_data[0]['_items'][0]
    return system_data


def dmi_info():
    try:
        dmi = dmi_info_common_unix()
    except:
        dmi = {}
    spinfo = system_profiler_info()

    system_info = dict(
        UUID = spinfo['platform_UUID'],
        IdentifyingNumber = spinfo.get('serial_number',''),
        Product_Name = spinfo.get('machine_model',''),
        Vendor = spinfo.get('machine_name','')
    )

    BIOS = dict(
        BIOS_Revision=spinfo.get('os_loader_version',''),
        Version=spinfo.get('boot_rom_version','')
        )

    dmi['System_Information']=system_info
    dmi['BIOS']=BIOS
    return dmi


def get_info_plist_path(app_dir):
    """ Applications typically contain an Info.plist file that shows information
        about the app.
        It's typically located at {APPDIR}/Contents/Info.plist .
    """
    return app_dir + '/Contents/Info.plist'


def get_plist_obj(plist_file):
    """ Returns a plist obj when given the path to a plist file. """
    def get_file_type(file):
        file_output = run('file "%s"' % file)
        file_type = file_output.split(file)[1][2:-1]  # Removing ": " and "\n"
        return file_type

    file_type = get_file_type(plist_file)

    if file_type == 'Apple binary property list':
        tmp_plist = tempfile.mkstemp('.plist')[1]
        subprocess.check_call('plutil -convert xml1 \'' + plist_file + '\' -o ' + tmp_plist, shell=True)
        return plistlib.readPlist(tmp_plist)
    else:  # regular plist
        return plistlib.readPlist(plist_file)


def get_applications_info_files():
    """ Returns a list of the Info.plist files in the /Applications folder. """
    app_dirs = [file for file in glob.glob('/Applications/*.app')]
    plist_files = [get_info_plist_path(app_dir) for app_dir in app_dirs]
    return plist_files


def mount_dmg(dmg_path):
    """ Mounts a dmg file.

    Returns: The path to the mount point.
    """
    try:
        return run('hdiutil attach -nobrowse "%s"' % dmg_path).split('\t')[-1].rstrip()
    except subprocess.CalledProcessError as e:
        raise Exception('Error in mount_dmg : {0}'.format(e.output))


def unmount_dmg(dmg_mount_path):
    """ Unmounts a dmg file, given the path to the mount point.

    Returns the value of the 'hdiutil unmount' command ran.
    """
    try:
        return run('hdiutil detach "%s"' % dmg_mount_path)
    except subprocess.CalledProcessError as e:
        raise Exception('Error in unmount_dmg : {0}'.format(e.output))


def is_local_app_installed(appdir, check_version=True):
    """ Checks whether or not an application is already installed on the machine.
    Arguments:
        appdir          The path to the .app directory
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.
    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version.
    """
    def get_installed_apps_info():
        app_info_files = get_applications_info_files()
        for f in app_info_files:
            yield get_plist_obj(f)

    # TODO check version
    local_app_info = get_info_plist_path(appdir)
    local_app_info = get_plist_obj(local_app_info)
    for installed_info in get_installed_apps_info():
        if installed_info['CFBundleName'] == local_app_info['CFBundleName']:
            if check_version == False:
                return True
            else:
                return str(local_app_info['CFBundleShortVersionString']) == str(installed_info['CFBundleShortVersionString'])
    return False


def get_installed_pkgs():
    """ Returns the list of the IDs of the already installed packages. """
    return run('pkgutil --pkgs').rstrip().split('\n')


def get_pkg_info(pkg_id):
    """ Gets an installed pkg's info, given its ID.

    Returns: a dict made from data in plist format
    """
    pkginfo_str = run('pkgutil --pkg-info-plist {0}'.format(pkg_id))
    pkginfo = plistlib.readPlistFromBytes(pkginfo_str.encode('utf-8'))
    return dict(pkginfo)

def uninstall_key_exists(uninstallkey):
    if uninstallkey.startswith('pkgid:'):
        if uninstallkey[6:] in get_installed_pkgs():
            return True
    else:
        if isdir(uninstallkey):
            return True

    return False

def is_local_pkg_installed(pkg_path, check_version=False):
    """ Checks whether or not a package file is already installed on the machine.
    Arguments:
        pkg_path        The path to the .pkg file
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.
    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version.
    """
    tmp_dir = tempfile.mkdtemp()
    run('xar -xf "{0}" -C "{1}"'.format(pkg_path, tmp_dir))
    tree = etree.parse(tmp_dir + '/' + 'PackageInfo')
    root = tree.getroot()
    local_pkg_attrib = root.attrib
    remove_tree(tmp_dir)
    pkglist = get_installed_pkgs()
    if local_pkg_attrib['identifier'] in pkglist:
        if check_version == False:
            return True
        else:
            installed_pkg_info = get_pkg_info(local_pkg_attrib['identifier'])
            return str(installed_pkg_info['pkg-version']) == str(local_pkg_attrib['version'])
    return False

def is_dmg_installed(dmg_path, check_version=False):
    """ Checks whether or not a .dmg is already installed, given a path to it.
    Arguments:
        dmg_path        The path to the .dmg file
        check_version   If true, also checks if the local package's version is
                        equal or superior to its possibly already installed version.
    Returns:
        True if it's already installed, False if it isn't. If check_version
        is specified, will also return False if it is already installed AND
        its version is inferior to the local package's version."""
    result_map = []
    dmg_mount_path = mount_dmg(dmg_path)
    try:
        dmg_file_assoc = {'.pkg': is_local_pkg_installed, '.app': is_local_app_installed}
        files = [dmg_mount_path + '/' + fname for fname in os.listdir(dmg_mount_path)]
        for file in files:
            fname, fextension = os.path.splitext(file)
            if fextension in dmg_file_assoc:
                result_map.append(dmg_file_assoc[fextension](file, check_version))
    except Exception as e:
        logger.warning('Couldn\'t check contents of dmg file at {0}: {1}'.format(dmg_path, e))
        unmount_dmg(dmg_mount_path)
        raise
    unmount_dmg(dmg_mount_path)
    return any(result_map)


def install_pkg(pkg_path,key="",min_version="",get_version=None,killbefore=None,force=False,uninstallkeylist=None):
    """ Installs a pkg file, given its name or a path to it. """

    if key:
        if not need_install(key=key,min_version=min_version,get_version=get_version,force = force):
            print('The dmg file {0} is already installed on this machine.'.format(pkg_path))

            if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
                uninstallkeylist.append(key)

            return False

    pkg_name = os.path.basename(pkg_path)

    if killbefore:
        killalltasks(killbefore)
    run('sudo installer -package "{0}" -target /'.format(pkg_path))

    if key:
        if need_install(key=key):
            error('%s has been installed but the %s can not be found' % (pkg_path,key))
        if need_install(key=key,min_version=min_version,get_version=get_version):
            error('%s has been executed and %s has been found, but version does not match requirements of min_version=%s' % (pkg_path, key , min_version))

    # add the key to the caller uninstallkeylist
    if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
        uninstallkeylist.append(key)

    print('Package {0} has been installed.'.format(pkg_name))

def uninstall_pkg(pkg_name):
    """ Uninstalls a pkg by its name.

    DELETES EVERY FILE. Should not save the user's configuration.

    Returns: True if it succeeded, False otherwise.
    """
    pkg_list = get_installed_pkgs()

    if pkg_name not in pkg_list:
        print('Couldn\'t uninstall the package {0} : package not installed.'.format(pkg_name))
        return False

    print('Requiring root access to uninstall the package {0}:'.format(pkg_name))
    run('sudo -v')

    pkg_plist_info = get_pkg_info(pkg_name)
    # TODO check them before deleting them : moving them to a tmp location?
    pkg_file_list = run('pkgutil --only-files --files {0}'.format(pkg_name)).rstrip().split('\n')
    for f in pkg_file_list:
        f = os.path.join('/', pkg_plist_info['install-location'], f)
        if os.path.isfile(f):
            os.remove(f)
        else:
            print('Couldn\'t remove file {0} from pkg {1} : file does not exist'.format(f, pkg_name))

    run('sudo pkgutil --forget {0}'.format(pkg_name))

    pkg_list = get_installed_pkgs()
    if pkg_name in pkg_list:
        error("Uninstallation doesn't seem to work")

    print('Package {0} has been successfully uninstalled.'.format(pkg_name))
    return True


def install_app(app_dir,key="",min_version="",get_version=None,killbefore=None,force=False,uninstallkeylist=None):
    """ Installs an app given a path to it.
    Copies the app directory to /Applications.
    """

    if key:
        if not need_install(key=key,min_version=min_version,get_version=get_version,force = force):
            print('The {0} is already installed on this machine.'.format(app_dir))
            if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
                uninstallkeylist.append(key)
            return False

    app_name = os.path.basename(app_dir)
    applications_dir = '/Applications'

    print('Installing the contents of {0} in {1}...'.format(app_name, applications_dir))
    folder_app_dir = app_dir.split('/')[-1]

    if killbefore:
        killalltasks(killbefore)

    if isdir( makepath(applications_dir,folder_app_dir)):
        remove_tree(makepath(applications_dir,folder_app_dir))

    copytree2(app_dir,makepath(applications_dir,folder_app_dir))


    if key:
        if need_install(key=key):
            error('%s has been installed but the %s can not be found' % (app_dir,key))
        if need_install(key=key,min_version=min_version,get_version=get_version):
            error('%s has been executed and %s has been found, but version does not match requirements of min_version=%s' % (app_dir, key , min_version))

    # add the key to the caller uninstallkeylist
    if key and isinstance(uninstallkeylist, list) and not key in uninstallkeylist:
        uninstallkeylist.append(key)

    print('{0} succesfully installed in {1}'.format(app_name, applications_dir))


def uninstall_app(app_name):
    """ Uninstalls an app given its name.

    DELETES EVERY FILE. Should not save the user's configuration.
    """
    app_dir = '/Applications/'
    app_path = app_dir + app_name

    if app_path[-4:] != '.app':
        app_path += '.app'

    if not os.path.isdir(app_path):
        print("Application {0} not found in {1} : cannot uninstall".format(app_name, app_dir))
        return False

    remove_tree(app_path)

    if os.path.isdir(app_path):
        error("uninstallation doesn't seem to work")

    print("Application \"{0}\" deleted.".format(app_name))
    return True


def need_install(key="",min_version="",get_version=None,force=False,higher_version_warning=True):

    if force :
        return True

    if key :
        if uninstall_key_exists(key):
            if not min_version:
                return False
            if get_version:
                installed_version = get_version([p for p in installed_softwares() if p['key'] == key][0])
            else:
                if key.startswith('pkgid:'):
                    pkg = get_pkg_info(key[6:])
                    installed_version = pkg.get('pkg-version','')
                else:
                    plist_obj = get_plist_obj(get_info_plist_path(key))
                    installed_version = plist_obj.get('CFBundleShortVersionString','') if  plist_obj.get('CFBundleShortVersionString','') else plist_obj.get('CFBundleVersion','')
            if Version(installed_version) >= Version(min_version):
                if higher_version_warning:
                    if Version(min_version) < Version(installed_version):
                        print("WARNING the installed version (%s) is higher than the requested version (%s)" % (installed_version,min_version))
                return False
        else:
            return True

    return True


def install_dmg(dmg_path,key="",min_version="",get_version=None,force=False,killbefore=None,uninstallkeylist=None):
    """ Installs a .dmg if it isn't already installed on the system.

    Arguments:
        dmg_path : the path to the dmg file

    Returns:
        True if it succeeded, False otherwise
    """
    dmg_mount_path = mount_dmg(dmg_path)

    try:
        dmg_file_assoc = {'.pkg': install_pkg, '.mpkg': install_pkg ,'.app': install_app}
        files = [dmg_mount_path + '/' + fname for fname in os.listdir(dmg_mount_path)]
        nb_files_handled = 0
        for file in files:
            fname, fextension = os.path.splitext(file)
            if fextension in dmg_file_assoc:
                if not os.path.islink(file):
                    dmg_file_assoc[fextension](file,key=key,min_version=min_version,get_version=get_version,force=force,uninstallkeylist=uninstallkeylist,killbefore=killbefore)
                    nb_files_handled += 1

        if nb_files_handled == 0:
            error('Error : the dmg provided did not contain a package or an application, or none could be found.')

        unmount_dmg(dmg_mount_path)
    except Exception:
        unmount_dmg(dmg_mount_path)
        raise





def installed_softwares(keywords=None, name=None, ignore_empty_names=True):
    """ Return list of every application in the /Applications folder.

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

    app_dirs = [str(f.resolve()) for f in pathlib.Path('/Applications').rglob('*.app')]
    app_dirs2 = [str(f.resolve()) for f in pathlib.Path('/System/Applications').rglob('*.app')]
    app_dirs.extend(app_dirs2)

    already_ok = {}

    plist_files = sorted([get_info_plist_path(app_dir) for app_dir in app_dirs], key=len)


    list_pkg = get_installed_pkgs()
    for pkgentry in list_pkg:
        pkg = get_pkg_info(pkgentry)
        pkgentrytmp = {'key':'pkgid:%s' % pkg['pkgid'],
                                         "name":pkg['pkgid'],
                                         "install_location":pkg.get('volume',''),
                                         "install_date":str(datetime.datetime.fromtimestamp(int(pkg.get('install-time','')))).replace('T',' '),
                                         "version":pkg.get('pkg-version','')}

        if (not ignore_empty_names or pkgentrytmp['name'] != '') and (
                (name_re is None or name_re.match(pkgentrytmp['name'])) and
                (keywords is None or check_words(pkgentrytmp['name'], keywords))):

            list_installed_softwares.append(pkgentrytmp)


    for plist_file in plist_files:
        try:
            namerep = plist_file.split("/Applications/")[1].split('.app')[0]
            plist_obj = get_plist_obj(plist_file)

            if plist_file[:plist_file.index('.app') + 4] in already_ok:
                continue
            already_ok[plist_file[:plist_file.index('.app') + 4]]=None

            publisher = plist_obj.get('CFBundleIdentifier','').split('.')[1] if ('.' in plist_obj.get('CFBundleIdentifier','')) else plist_obj.get('CFBundleIdentifier','')
            version =  plist_obj.get('CFBundleShortVersionString','') if  plist_obj.get('CFBundleShortVersionString','') else plist_obj.get('CFBundleVersion','')
            if (not ignore_empty_names or plist_obj.get('CFBundleName',namerep) != '') and (
                (name_re is None or name_re.match(plist_obj.get('CFBundleName',''))) and
                (keywords is None or check_words(' '.join([plist_obj.get('CFBundleName',""), publisher ]), keywords))):
                list_installed_softwares.append({'key': plist_file[:plist_file.index('.app') + 4],
                                                 'name': plist_obj.get('CFBundleName',namerep),
                                                 'version': version,
                                                 'install_date': datetime.datetime.fromtimestamp(os.path.getmtime(plist_file)).strftime('%Y-%m-%d %H:%M:%S'),
                                                 'install_location': plist_file[:plist_file.index('.app') + 4],
                                                 'uninstall_string': '',
                                                 'publisher': publisher,  # "com.publisher.name" => "publisher"
                                                 'system_component': ''})

        except:
            pass
            #logger.warning("Application data acquisition failed for {} :".format(plist_file))

    return list_installed_softwares

def brew_install(pkg_name):
    """ Installs a brew package, given its name. """
    return subprocess.call('brew install ' + pkg_name, shell=True)


def brew_uninstall(pkg_name):
    """ Uninstalls a brew package, given its name. """
    return subprocess.call('brew uninstall ' + pkg_name, shell=True)

def running_on_ac():
    try:
        power_bat =  run('pmset -g batt')
        return 'AC Power' in power_bat
    except:
        return None
