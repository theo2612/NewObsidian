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
import struct
import getpass
import platform
import shutil
import configparser
import psutil
import netifaces
import cpuinfo
import subprocess
import logging
import grp
import pwd
import ipaddress
import dns.resolver
import datetime

try:
    import pyldap
except ImportError:
    from waptlicences import pyldap

try:
    from waptlicences import uptime
except ImportError:
    uptime = None


from waptutils import (ensure_unicode, makepath, error, get_main_ip, run, killtree, get_local_IPs, networking)


logger = logging.getLogger('waptcore')


def get_kernel_version():
    return os.uname()[2]


def get_computer_groups():
    """Try to find the computer in the Active Directory
    and return the list of groups
    """
    return get_groups(get_computername().split('.')[0] + '$')


def get_groups(user):
    gids = [g.gr_gid for g in grp.getgrall() if user.lower() in g.gr_mem]
    gid = pwd.getpwnam(user.lower()).pw_gid
    if not gid in gids:
        gids.append(grp.getgrgid(gid).gr_gid)
    return [grp.getgrgid(gid).gr_name.rsplit('\\')[-1].lower() for gid in gids]


def get_domain_info(force_tgt=True, hostname=None, domain=None):
    """Return dict ad_site , ou and groups"""

    if not pyldap:
        error('get_domain_info: pyldap module unavailable.')

    result = {}
    result['groups'] = []

    if platform.system() == 'Darwin':
        cmd = 'ktutil -k /etc/krb5.keytab list'
    else:
        cmd = 'klist -k'

    if (not hostname) or (not domain):
        splitlist = run(cmd).split('$@', 1)
        if not hostname:
            hostname = str(splitlist[0].rsplit(' ', 1)[-1] + '$').split('/')[-1]
        if not domain:
            domain = splitlist[1].split('\n')[0].strip()

    if force_tgt:
        try:
            subprocess.check_output(r'kinit -k %s\@%s' % (hostname, domain), shell=True, stderr=subprocess.STDOUT)
        except:
            pass

    result['site'] = pyldap.cldap_get_domain_info()['client_site']

    client = pyldap.PyLdapClient()
    r = client.bind_sasl_kerberos()

    if not r[0]:
        error('Failed connect to active directory')

    client.search(client.root_dn(), False, '(sAMAccountName=%s)' % hostname.lower(), ['distinguishedName','memberOf'])
    response = client.search_result()
    attrs = response[0].object_attributes
    attrs_result = { u.name : u.values for u in attrs}

    result['ou'] = attrs_result['distinguishedName'][0]

    if 'memberOf' in attrs_result:
        for u in attrs_result['memberOf']:
            result['groups'].append(u.split(',', 1)[0].split('=')[1].lower())

    return result



def get_default_gateways():
    if platform.system() == 'Linux':
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    elif platform.system() == 'Darwin':
        route_output = run('route -n get default').rstrip().split('\n')
        route_output = [line.strip() for line in route_output]
        route_dict = {}

        for line in route_output:
            split_l = line.split(':')
            try:
                route_dict[split_l[0]] = split_l[1].strip()
            except:
                pass
        gateway_ip = route_dict['gateway']
        gateway_hex = '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, gateway_ip.split('.')))
        return socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))


def user_local_appdata():
    r"""Return the local appdata profile of current user

    Returns:
        str: path like u'/home/user/.config/'
    """
    if 'HOME' in os.environ:
        return ensure_unicode(makepath(os.environ['HOME'], '.config/'))
    else:
        return ''

user_appdata=user_local_appdata

def remove_tree(*args, **kwargs):
    r"""Convenience function to delete a directory tree, with any error
    not ignored by default.  Pass ignore_errors=False to access possible
    errors.

    Args:
        path (str): path to directory to remove
        ignore_errors (boolean) : default to False. Set it to True to ignore exceptions on children deletion
        onerror (func) : hook called with (func, path, exc)
                         on each delete exception. Should raise if stop is required.
    """
    return shutil.rmtree(*args, **kwargs)


def local_drives():
    partitions = psutil.disk_partitions()
    result = {}
    for elem in partitions:
        result[elem.mountpoint] = dict(elem._asdict())
        result[elem.mountpoint] = result[elem.mountpoint].update(dict(psutil.disk_usage(elem.mountpoint)._asdict()))
    return result


def host_metrics():
    """Frequently updated host data
    """
    result = {}
    # volatile...
    result['physical_memory'] = psutil.virtual_memory().total
    result['virtual_memory'] = psutil.swap_memory().total
    result['local_drives'] = local_drives()
    result['logged_in_users'] = list(get_loggedinusers())
    result['last_logged_on_user'] = get_last_logged_on_user()

    # memory usage
    mem_info = psutil.Process().memory_info()
    result['wapt-memory-usage'] = {}
    for field in mem_info._fields:
        result['wapt-memory-usage'][field] = getattr(mem_info, field)

    if uptime:
        result['last_bootup_time'] =  datetime.datetime.utcnow() - datetime.timedelta(seconds = uptime())

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
    if default_gateway:
        return default_inet_gw[0]
    else:
        return None


def get_current_user():
    r"""Get the login name for the current user.
    >>> get_current_user()
    u'htouvet'
    """
    return ensure_unicode(getpass.getuser())


def application_data():
    return os.path.join(os.environ['HOME'], '.config')


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True


def get_dns_servers():
    dns_ips = []
    with open('/etc/resolv.conf') as fp:
        for cnt, line in enumerate(fp):
            columns = line.split()
            if len(columns) == 0:
                continue
            if columns[0] == 'nameserver':
                ip = columns[1:][0]
                if is_valid_ipv4_address(ip):
                    dns_ips.append(ip)
    return dns_ips


def get_loggedinusers():
    suser = psutil.users()
    result = {}
    for elem in suser:
        if not elem.name in result:
            result[elem.name] = None
    if platform.system() != 'Darwin':
        try:
            output = run('loginctl list-sessions')
            for line in output.split('\n'):
                if 'SESSION' in line:
                    continue
                if not line.startswith(' '):
                    continue
                col = []
                for c in line.split(' '):
                    if c == '':
                        continue
                    col.append(c)
                result[col[2]] = col[0]
        except:
            pass
    return result


def get_last_logged_on_user():
    suser = psutil.users()
    res = ''
    for elem in suser:
        if res == '':
            res = elem
        elif res.started < elem.started:
            res = elem
    return res


def get_domain_from_socket():
    """Return main DNS domain of the computer

    Returns:
        str: domain name

    >>> get_domain_from_socket()
    u'tranquilit.local'
    """

    try:
        return socket.getfqdn().split('.', 1)[1]
    except:
        return ""


def host_info_common_unix():
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

    info = {}
    info['computer_name'] = socket.gethostname().lower()
    info['computer_fqdn'] = socket.getfqdn().lower()

    try:
        if os.path.isfile('/etc/samba/smb.conf'):
            config = configparser.RawConfigParser(strict=False)
            config.read('/etc/samba/smb.conf')
            if config.has_option('global', 'workgroup'):
                info['workgroup_name'] = config.get('global', 'workgroup')
    except:
        info['workgroup_name'] = ''

    info['kernel_version'] = get_kernel_version()
    try:
        info['cpu_name'] = cpuinfo.get_cpu_info()['brand_raw']
    except:
        info['cpu_name'] = ""
    info['environ'] = {k: ensure_unicode(v) for k, v in os.environ.items()}

    return info

def host_info_networking():
    info = {}
    info['connected_ips'] = get_local_IPs()

    info['interfaces'] = networking()
    list_mac = {}
    for c in info['interfaces']:
        if 'mac' in c and 'addr' in c:
            for m in c['addr']:
                if m['addr'] in info['connected_ips']:
                    list_mac[c['mac']] = None

    info['gateways'] = [get_default_gateways()]
    info['dns_servers'] = get_dns_servers()
    info['mac'] = list(list_mac)
    info['main_ip'] = get_main_ip()
    info['dnsdomain'] = get_domain_from_socket()
    return info


def get_computername():
    """Return host name in lowercase (without domain part)"""
    return socket.gethostname().lower()

def dmi_info_common_unix():
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
    # dmidecode don't show errors
    if platform.system() == 'Darwin':
        dmiout = ensure_unicode(run('/opt/wapt/bin/dmidecode -q 2>/dev/null'))
    else:
        dmiout = ensure_unicode(run('dmidecode -q 2>/dev/null'))

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
            if l.startswith('\t'):
                logger.debug(l)
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
    return result


def get_file_properties(fname, ignore_warning=True):
    r"""Read all properties of the given file return them as a dictionary.

    Args:
        fname : path to Windows executable or DLL

    Returns:
        dict: properties of executable

    >>> xp = get_file_properties(r'c:\windows\explorer.exe')
    >>> 'FileVersion' in xp and 'FileDescription' in xp
    True
    """
    # TODO : POSIX version
    props = {}

    return props


def uac_enabled():
    return False


def killalltasks(process_names, include_children=True):
    """Kill the task by their process_names

    >>> killalltasks('firefox')
    """
    logger.debug('Kill tasks %s' % (process_names,))
    if not process_names:
        return []
    if not isinstance(process_names, list):
        process_names = [process_names]

    result = []
    process_names = [process.lower() for process in process_names]
    for p in psutil.process_iter():
        try:
            if p.name().lower() in process_names:
                logger.debug('Kill process %i' % (p.pid,))
                result.append((p.pid, p.name()))
                if include_children:
                    killtree(p.pid)
                else:
                    p.kill()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return result


def get_processes_with_name(name):
    """ Returns the processes which contain the given name """
    try:
        processes = []
        for proc in psutil.process_iter():
            if name.lower() in proc.name().lower():
                processes.append(proc)
            return [p.as_dict() for p in processes]
    except subprocess.CalledProcessError:
        return None


def local_groups():
    return [g.gr_name for g in grp.getgrall()]

def local_group_members(groupname):
    return grp.getgrnam(groupname).gr_mem

def local_group_memberships(username):
    """List the local groups a user is member Of"""
    return get_groups(username)