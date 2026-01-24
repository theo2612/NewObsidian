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

__version__ = "2.5.5"

import os
import sys
from typing import Dict, Optional, List, Any, Union, Callable
import re
import subprocess
import logging
import types
import datetime
import time
import json
import itertools
import random
import string
import email
import copy
import platform
import codecs
import glob
import requests
import locale
import textwrap
import zipfile
import tempfile
import fnmatch
import hashlib
import traceback
import imp
import shutil
import threading
import socket
import psutil
import urllib.parse
import netifaces
from configparser import RawConfigParser
from requests.adapters import HTTPAdapter
if sys.version_info > (3, 5, 0):
    from urllib3.util.ssl_ import create_urllib3_context
from urllib3.exceptions import InsecureRequestWarning
import io
from operator import attrgetter


if sys.platform == 'win32':
    import _winapi
    import win32process
    import win32net
    import win32netcon
    import winreg
    import pywintypes
    import win32security
elif sys.platform == 'linux':
    import pwd
    import grp

# some shortcuts
isfile = os.path.isfile
isdir = os.path.isdir

LOGLEVELS = ('debug', 'warning', 'info', 'error', 'critical')

class EWaptAuthException(Exception):
    pass

class CalledProcessErrorOutput(subprocess.CalledProcessError):
    """CalledProcessError with printed output"""

    def __str__(self):
        try:
            return "Command %s returned non-zero exit status %d.\nOutput:%s" % (repr(self.cmd), self.returncode, ensure_unicode(self.output))
        except UnicodeDecodeError:
            return "Command %s returned non-zero exit status %d.\nOutput:%s" % (repr(self.cmd), self.returncode, repr(self.output))


def setloglevel(logger: logging, loglevel: str):
    """set loglevel as string"""
    if loglevel and logger:
        if loglevel.lower() in LOGLEVELS:
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError('Invalid log level: {}'.format(loglevel))
            logger.setLevel(numeric_level)
        else:
            raise ValueError('Invalid log level: {}. Must be one of {}'.format(loglevel,LOGLEVELS))


logger = logging.getLogger('waptcore')
tasks_logger = logging.getLogger('wapttasks')

if platform.system() == 'Windows':
    try:
        import ctypes
        import win32api
        import pythoncom

        class _disable_file_system_redirection(object):
            r"""Context manager to disable temporarily the wow3264 file redirector

            >>> with disable_file_system_redirection():
            ...     winshell.get_path(shellcon.CSIDL_PROGRAM_FILES)
            u'C:\\Program Files (x86)'
            """
            try:
                _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
                _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
            except:
                _disable = None
                _revert = None

            def __enter__(self):
                if self._disable:
                    self.old_value = ctypes.c_long()
                    self.success = self._disable(ctypes.byref(self.old_value))

            def __exit__(self, type, value, traceback):
                if self._revert and self.success:
                    self._revert(self.old_value)
    except Exception:
        class _disable_file_system_redirection(object):
            def __enter__(self):
                pass

            def __exit__(self, type, value, traceback):
                pass

    def _programfiles():
        """Return native program directory, ie C:\Program Files for both 64 and 32 bits"""
        if 'PROGRAMW6432' in os.environ:
            return os.environ['PROGRAMW6432']
        else:
            return os.environ['PROGRAMFILES']

    ExceptionRun = WindowsError
    def get_exception_run_arg(e:ExceptionRun, index:int) -> str:
        return e.args[index];

else:
    class _disable_file_system_redirection(object):
        def __enter__(self):
            pass

        def __exit__(self, type, value, traceback):
            pass

    ExceptionRun = RuntimeError
    def get_exception_run_arg(e:ExceptionRun, index:int) -> str:
        return e[index];


def int2uhex(aint):
    """Convert a signed integer to a unsigned hex representation
    Useful for com error

    """
    return '%#4x' % (aint & 0xffffffff)


#####################################
# http://code.activestate.com/recipes/498181-add-thousands-separator-commas-to-formatted-number/
# Code from Michael Robellard's comment made 28 Feb 2010
# Modified for leading +, -, space on 1 Mar 2010 by Glenn Linderman
#
# Tail recursion removed and  leading garbage handled on March 12 2010, Alessandro Forghieri
def splitThousands(s: str, tSep: str = ',' , dSep: str = '.') -> str:
    '''Splits a general float on thousands. GIGO on general input'''
    if s == None:
        return 0
    if not isinstance(s, str):
        s = str(s)

    cnt = 0
    numChars = dSep+'0123456789'
    ls = len(s)
    while cnt < ls and s[cnt] not in numChars:
        cnt += 1

    lhs = s[0:cnt]
    s = s[cnt:]
    if dSep == '':
        cnt = -1
    else:
        cnt = s.rfind(dSep)
    if cnt > 0:
        rhs = dSep + s[cnt+1:]
        s = s[:cnt]
    else:
        rhs = ''

    splt = ''
    while s != '':
        splt = s[-3:] + tSep + splt
        s = s[:-3]

    return lhs + splt[:-1] + rhs


def format_bytes(bytes: int) -> str:
    if bytes is None:
        return None
    else:
        bytes = float(bytes)
        if bytes >= 1099511627776: # pow(1024, 4)
            terabytes = bytes / 1099511627776
            size = '%.2fT' % terabytes
        elif bytes >= 1073741824: # pow(1024, 3)
            gigabytes = bytes / 1073741824
            size = '%.2fG' % gigabytes
        elif bytes >= 1048576: # pow(1024, 2)
            megabytes = bytes / 1048576
            size = '%.2fM' % megabytes
        elif bytes >= 1024:
            kilobytes = bytes / 1024
            size = '%.2fK' % kilobytes
        else:
            size = '%.2fb' % bytes
        return size

# {{{ http://code.activestate.com/recipes/81189/ (r2)


def pptable(cursor, data=None, rowlens=0, callback=None):
    """
    pretty print a query result as a table
    callback is a function called for each field (fieldname,value) to format the output
    """
    def defaultcb(fieldname, value):
        return value

    if not callback:
        callback = defaultcb

    d = cursor.description
    if not d:
        return "#### NO RESULTS ###"
    names = []
    lengths = []
    rules = []
    if not data:
        data = cursor.fetchall()
    for dd in d:    # iterate over description
        l = dd[1]
        if not l:
            l = 12              # or default arg ...
        l = max(l, len(dd[0]))  # handle long names
        names.append(dd[0])
        lengths.append(l)
    for col in range(len(lengths)):
        if rowlens:
            rls = [len(row[col]) for row in data if row[col]]
        lengths[col] = max([lengths[col]]+rls)
        rules.append("-"*lengths[col])

    format = " ".join(["%%-%ss" % l for l in lengths])
    result = [format % tuple(names)]
    result.append(format % tuple(rules))
    for row in data:
        row_cb = []
        for col in range(len(d)):
            row_cb.append(callback(d[col][0], row[col]))
        result.append(format % tuple(row_cb))
    return "\n".join(result)
# end of http://code.activestate.com/recipes/81189/ }}}


def ppdicttable(alist, columns=[], callback=None):
    """
    pretty print a list of dict as a table
    columns is an ordered list of (fieldname,width)
    callback is a function called for each field (fieldname,value) to format the output
    """
    def defaultcb(fieldname, value, width):
        if value is None:
            return ''
        if width<10:
            placeholder=''
        else:
            placeholder='*'
        return textwrap.shorten('%s' % value,width,placeholder=placeholder)

    if not callback:
        callback = defaultcb

    if not alist:
        return "#### NO RESULTS ###"

    lengths = [c[1] for c in columns]
    names = [c[0] for c in columns]
    rules = []
    for col in range(len(lengths)):
        rules.append("-"*lengths[col])

    format = " ".join(["%%-%ss" % l for l in lengths])
    result = [format % tuple(names)]
    result.append(format % tuple(rules))
    for row in alist:
        row_cb = []
        for (name, width) in columns:
            if isinstance(name, (list, tuple)):
                name = name[0]
            if isinstance(row, dict):
                row_cb.append(callback(name, row.get(name, None),width))
            else:
                row_cb.append(callback(name, getattr(row, name, None),width))
        result.append(format % tuple(row_cb))
    return "\n".join(result)
# end of http://code.activestate.com/recipes/81189/ }}}


def html_table(cur, callback=None):
    """
        cur est un cursor issu d'une requete
        callback est une fonction qui prend (rowmap,fieldname,value)
        et renvoie une representation texte
    """
    def safe_unicode(iso):
        if iso is None:
            return None
        elif isinstance(iso, str):
            return iso.decode(locale.getpreferredencoding())
        else:
            return iso

    def itermap(cur):
        for row in cur:
            yield dict((cur.description[idx][0], value)
                       for idx, value in enumerate(row))

    head = "<tr>"+"".join(["<th>"+c[0]+"</th>" for c in cur.description])+"</tr>"
    lines = ""
    if callback:
        for r in itermap(cur):
            lines = lines+"<tr>"+"".join(["<td>"+str(callback(r, c[0], safe_unicode(r[c[0]])))+"</td>" for c in cur.description])+"</tr>"
    else:
        for r in cur:
            lines = lines+"<tr>"+"".join(["<td>"+safe_unicode(c)+"</td>" for c in r])+"</tr>"

    return "<table border=1  cellpadding=2 cellspacing=0>%s%s</table>" % (head, lines)


def merge_dict(d1: Dict, d2: Dict) -> Dict:
    """merge similar dict"""
    result = copy.deepcopy(d1)

    if d2:
        if not (isinstance(d1,(list,dict)) and isinstance(d2,(list,dict))):
            raise Exception('unsupported types: %s %s' % (type(d1),type(d2)))
        for k in d2:
            if k in result:
                if isinstance(result[k], list) and isinstance(d2[k],list):
                    for item in d2[k]:
                        if not item in result[k]:
                            result[k].append(item)
                elif isinstance(result[k], dict) and isinstance(d2[k],dict):
                    result[k] = merge_dict(result[k], d2[k])
                else:
                    result[k] = d2[k]
            else:
                result[k] = d2[k]
    return result


def generate_unique_string():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))


def default_json(o):
    """callback to extend handling of json.dumps"""
    if hasattr(o, 'as_dict'):
        return o.as_dict()
    if hasattr(o, '_asdict'):
        return o._asdict()
    elif hasattr(o, 'as_json'):
        return o.as_json()
    elif isinstance(o, datetime.datetime):
        return o.isoformat()
    else:
        return "%s" % (ensure_unicode(o),)


def jsondump(o, **kwargs):
    """Dump argument to json format, including datetime
    and customized classes with as_dict or as_json callables
    >>> class MyClass(object):
    ...    def as_dict(self):
    ...        return {'test':'a','adate2':datetime.date(2014,03,15)}
    >>> jsondump({'adate':datetime.date(2014,03,14),'an_object':MyClass()})
    '{"adate": "2014-03-14", "an_object": {"test": "a", "adate2": "2014-03-15"}}'
    """
    kwargs['separators'] = kwargs.get('separators',(',', ':'))
    return json.dumps(o, default=default_json,  **kwargs)


def jsondump_compact(o):
    return json.dumps(o, sort_keys=True, separators=(',', ':'))

# from opsi
def ensure_unicode(data):
    """Return a unicode string from data object
    It is sometimes difficult to know in advance what we will get from command line
    application output.

    This is to ensure we get a (not always accurate) representation of the data
    mainly for logging purpose.

    Args:
        data: either str or unicode or object having a __str__ or WindowsError or Exception

    Returns:
        unicode: unicode string representing the data

    >>> ensure_unicode(str('éé'))
    u'\xe9\xe9'
    >>> ensure_unicode(u'éé')
    u'\xe9\xe9'
    >>> ensure_unicode(Exception("test"))
    u'Exception: test'
    >>> ensure_unicode(Exception())
    u'Exception: '
    """
    try:
        if data is None:
            return None
        if isinstance(data, str):
            return data
        if isinstance(data, bytes):
            try:
                return data.decode('utf8')
            except UnicodeError:
                if platform.system() == 'Windows':
                    try:
                        # cmd output mostly cp850 in france ?
                        return data.decode('cp850')
                    except UnicodeError:
                        try:
                            return data.decode('utf16')
                        except UnicodeError:
                            try:
                                return data.decode(sys.getfilesystemencoding())
                            except UnicodeError:
                                return data.decode(sys.getdefaultencoding(), 'ignore')
                else:
                    return data.decode(sys.getfilesystemencoding(), 'replace')
        if platform.system() == 'Windows' and isinstance(data, pythoncom.com_error):  # pylint: disable=no-member
            try:
                try:
                    error_msg = ensure_unicode(win32api.FormatMessage(data.args[2][5]))
                except Exception:
                    error_msg = '(unable to get meaning for error code %s)' % int2uhex(data.args[2][5])
                return "%s (%s): %s (%s)" % (int2uhex(data.args[0]), data.args[1], int2uhex(data.args[2][5]), error_msg)
            except:
                try:
                    return "%s : %s" % (int2uhex(data.args[0]), data.args[1])
                except UnicodeError:
                    return "%s : %s" % (int2uhex(data.args[0]), data.args[1])

        if platform.system() == 'Windows' and isinstance(data, WindowsError):
            return "%s : %s" % (data.errno, data.strerror)
        if isinstance(data, UnicodeError):
            return "%s : faulty string is '%s'" % (data, repr(data.args[1]))
        if isinstance(data, Exception):
            try:
                return "%s: %s" % (data.__class__.__name__, data.__str__())
            except:
                return "%s" % (data.__class__.__name__)
        if hasattr(data, '__str__'):
            try:
                return data.__str__()
            except:
                pass
        return str(data)
    except UnicodeError:
        if logger.level != logging.DEBUG:
            return("Error in ensure_unicode / %s" % (repr(data)))
        else:
            raise


def ensure_list(csv_or_list, ignore_empty_args=True, allow_none=False):
    """if argument is not a list, return a list from a csv string

    Args:
        csv_or_list (list or str):
        ignore_empty_args (bool): if True, empty string found in csv are not appended to the list.
        allow_none (bool): if True, if csv_or_list is None, return None, else return empty list/

    Returns:
        list
    """
    if csv_or_list is None:
        if allow_none:
            return None
        else:
            return []

    if isinstance(csv_or_list, (tuple, list)):
        return list(csv_or_list)
    elif isinstance(csv_or_list, str):
        if ignore_empty_args:
            return [s.strip() for s in csv_or_list.split(',') if s.strip() != '']
        else:
            return [s.strip() for s in csv_or_list.split(',')]
    else:
        return [csv_or_list]


def datetime2isodate(adatetime : Optional[datetime.datetime]= None) -> str:
    """Return an iso8601 representation of the date/time
    If adatetime is None, return current datetime in UTC
    """
    if not adatetime:
        adatetime = datetime.datetime.utcnow()
    assert(isinstance(adatetime, datetime.datetime))
    return adatetime.isoformat()


def httpdatetime2datetime(httpdate: str ,localtime: bool = False) -> datetime.datetime:
    """convert a date string as returned in http headers or mail headers to datetime.datetime (UTC)

    Args:
        httpdate (str): form 'Thu, 23 Mar 2023 10:47:53 GMT'

    Returns:
        datetime.datetime

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    if httpdate:
        date_time_tz = email.utils.parsedate_to_datetime(httpdate)
        if localtime:
            return date_time_tz.astimezone()
        else:
            return date_time_tz
    else:
        return None

def httpdatetime2isodate(httpdate: str, localtime: bool = False) -> str:
    """Convert a date string as returned in http headers or mail headers to isodate (UTC)

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    if not httpdate:
        return None
    return datetime2isodate(httpdatetime2datetime(httpdate, localtime))


def httpdatetime2time(httpdate: str,localtime: bool = False) -> float:
    """convert a date string as returned in http headers or mail headers to isodate

    >>> import requests
    >>> last_modified = requests.head('http://wapt/wapt/Packages',headers={'cache-control':'no-cache','pragma':'no-cache'}).headers['last-modified']
    >>> len(httpdatetime2isodate(last_modified)) == 19
    True
    """
    if httpdate:
        if localtime:
            return httpdatetime2datetime(httpdate).timestamp()
        else:
            return time.mktime(httpdatetime2datetime(httpdate).timetuple())

    else:
        return None


def isodate2datetime(isodatestr: str) -> datetime.datetime:
    # we remove the microseconds part as it is not working for python2.5 strptime
    return datetime.datetime.strptime(isodatestr.split('.')[0], "%Y-%m-%dT%H:%M:%S")


def time2display(adatetime: datetime.datetime) -> str:
    return adatetime.strftime("%Y-%m-%d %H:%M")


def hours_minutes(hours: Optional[float]) -> Optional[str]:
    if hours is None:
        return None
    else:
        return "%02i:%02i" % (int(hours), int((hours - int(hours)) * 60.0))


def fileisodate(filename: str) -> str:
    """Returns last update date time from filename in local time"""
    return datetime.datetime.fromtimestamp(os.stat(filename).st_mtime).isoformat()


def fileutcdate(filename: str) -> datetime:
    """Returns last update date time from filename in UTC

    Returns:
        datetime
    """
    return datetime.datetime.utcfromtimestamp(os.stat(filename).st_mtime)


def fileutcmtime(filename: str) -> int:
    return fileutcdate(filename).timestamp()


def fileisoutcdate(filename: str) -> str:
    """Returns last update date time from filename in UTC"""
    return datetime2isodate(fileutcdate(filename))


def dateof(adatetime: datetime.datetime) -> datetime.datetime:
    return adatetime.replace(hour=0, minute=0, second=0, microsecond=0)


def force_utf8_no_bom(filename: str):
    """Check if the file is encoded in utf8 readable encoding without BOM
    rewrite the file in place if not compliant.
    """
    BOMLEN = len(codecs.BOM_UTF8)

    with open(filename, mode='rb') as f:
        content = f.read(BOMLEN)
    if content.startswith(codecs.BOM_UTF8):
        with open(filename, 'rb') as f:
            content = f.read()
        with open(filename, mode='wb') as f:
            f.write(content[BOMLEN:])
    else:
        try:
            with codecs.open(filename, encoding='utf8') as f:
                f.read()
        except:
            with codecs.open(filename, encoding='iso8859-15') as f:
                content = f.read()
            with codecs.open(filename, mode='wb', encoding='utf8') as f:
                f.write(content)


def sanitize_filename(filename: str) -> str:
    # old_forbidden = "@|():%/,\\[]<>*?;`\n"  # some characters were not mandatory to sanitize
    forbidden = '/:\\|<>"?*' + chr(127)
    return "".join([c for c in filename.replace("..", "_") if c not in forbidden and ord(c) >= 32]).strip().rstrip(".")

def is_unsafe_filename(filename: str) -> bool:
    if filename.startswith('\\\\') or filename.startswith('/'):
        return True
    if '\\..' in filename or '/..' in filename or '..\\' in filename or '../' in filename:
        return True
    if '$(' in filename:
        return True
    for c in filename:
        if ord(c) < ord(' '):
            return True
        if c in '|:<>*?;`\n':
            return True
    return False

def expand_args(args: List[str], expand_file_wildcards: bool = None) -> List[str]:
    """Return list of unicode file paths expanded from wildcard list args"""
    def from_system_encoding(t):
        if isinstance(t, str):
            return t
        else:
            try:
                return t.decode(sys.getfilesystemencoding())
            except:
                return ensure_unicode(t)

    all_args = []
    if expand_file_wildcards is None:
        expand_file_wildcards = True if [p for p in args if ('*' in p) or (':' in p) or (os.pathsep in p)] else False
    if expand_file_wildcards:
        for a in ensure_list(args):
            all_args.extend([os.path.abspath(p) for p in glob.glob(from_system_encoding(a))])
    else:
        all_args.extend([from_system_encoding(a) for a in args])

    return all_args


def default_http_headers() -> Dict:
    return {
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'user-agent': 'wapt/{}'.format(__version__),
    }


def http_resource_datetime(url, proxies=None, timeout=2, auth=None, verify_cert=False, cert=None):
    """Try to get header for the supplied URL, returns None if no answer within the specified timeout

    Args:
        url (str)      : URL to document
        proxies (dict) : proxies to use. eg {'http':'http://wpad:3128','https':'http://wpad:3128'}
        timeout (int)  : seconds to wait for answer before giving up
        auth (list)    : (user,password) to authenticate wirh basic auth
        verify_cert (bool or str) : either False, True (verify with embedded CA list), or path to a directory or PEM encoded CA bundle file
                                    to check https certificate signature against.
        cert (list)    : pair of (x509certfilename,pemkeyfilename) for authenticating the client

    Returns:
        datetime : last-modified date of document on server
    """
    try:
        headers = requests.head(url,
                                proxies=proxies, timeout=timeout,
                                auth=auth,
                                verify=verify_cert,
                                headers=default_http_headers(),
                                cert=cert,
                                allow_redirects=True)
        if headers.ok:
            return httpdatetime2datetime(headers.headers.get('last-modified', None))
        else:
            headers.raise_for_status()
    except Exception:
        return None


def http_resource_isodatetime(url, proxies=None, timeout=2, auth=None, verify_cert=False, cert=None):
    # try to get header for the supplied URL, returns None if no answer within the specified timeout or UTC iso datetime of resource from server
    try:
        headers = requests.head(url, proxies=proxies, timeout=timeout, auth=auth,
                                verify=verify_cert,
                                headers=default_http_headers(),
                                cert=cert,
                                allow_redirects=True)
        if headers.ok:
            return httpdatetime2isodate(headers.headers.get('last-modified', None))
        else:
            headers.raise_for_status()
    except Exception:
        return None


def get_disk_free_space(filepath: str) -> int:
    """
    Returns the number of free bytes on the drive that filepath is on
    """
    total, used, free = shutil.disk_usage(filepath)
    return free


def _hash_file(fname: str, block_size: int = 2**20, hash_func = hashlib.md5) -> str:
    if isinstance(fname, io.IOBase):
        buff_open = fname
    elif isinstance(fname, str):
        buff_open = open(fname, 'rb')
    else:
        raise Exception("Can't open %s not a buffer type or str" % fname)

    with buff_open as f:
        if isinstance(hash_func, str):
            hash_obj = hashlib.new(hash_func)
        else:
            hash_obj = hash_func()
        while True:
            data = f.read(block_size)
            if not data:
                break
            hash_obj.update(data)
    if isinstance(fname, str):
        buff_open.close()
    return hash_obj.hexdigest()


def sha1_for_file(fname: str, block_size: int = 2**20) -> str:
    return _hash_file(fname, block_size, hashlib.sha1)


def sha256_for_file(fname: str, block_size: int = 2**20) -> str:
    return _hash_file(fname, block_size, hashlib.sha256)


def hexdigest_for_data(data: str, md: str = 'sha256') -> str:
    if isinstance(data, str):
        data = data.encode('utf8')
    digest = hashlib.new(md)
    assert(isinstance(data, bytes))
    digest.update(data)
    return digest.hexdigest()


def sha1_for_data(data: str) -> str:
    return hexdigest_for_data(data, md='sha1')


def sha256_for_data(data: str) -> str:
    return hexdigest_for_data(data, md='sha256')


def _check_hash_for_file(fname: str, block_size: int = 2**20, md5: Optional[str] = None, sha1: Optional[str] = None, sha256: Optional[str] = None) -> bool:
    if not (sha1 or sha256 or md5):
        raise Exception('No hash to check file')
    hash_valid = True
    if sha256 is not None:
        hash_valid = hash_valid and _hash_file(fname, block_size, hashlib.sha256) == sha256.lower()
    if sha1 is not None:
        hash_valid = hash_valid and _hash_file(fname, block_size, hashlib.sha1) == sha1.lower()
    if md5 is not None:
        hash_valid = hash_valid and _hash_file(fname, block_size, hashlib.md5) == md5.lower()
    return hash_valid



def is_pem_key_encrypted(pem_filename: str) -> bool:
    if pem_filename and os.path.isfile(pem_filename):
        with open(pem_filename, 'r') as f:
            pem_content = f.read()
        return 'PRIVATE KEY' in pem_content and 'ENCRYPTED' in pem_content
    else:
        return False



def get_verify_cert(verify_cert_str: str, default=True):
    if verify_cert_str is None:
        return True
    elif verify_cert_str in (True,1,'1','True','true'):
        return True
    elif verify_cert_str in (False,0,'0','False','false',''):
        return False
    else:
        return str(verify_cert_str)

# from https://github.com/kennethreitz/requests/issues/1573
class SSLAdapter(HTTPAdapter):
    def __init__(self, certfile, keyfile, password=None, password_callback=None, *args, **kwargs):
        self._certfile = certfile
        self._keyfile = keyfile
        self._password_callback = password_callback
        self._password = password
        super(SSLAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        self._add_ssl_context(kwargs)
        return super(SSLAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        self._add_ssl_context(kwargs)
        return super(SSLAdapter, self).proxy_manager_for(*args, **kwargs)

    def _add_ssl_context(self, kwargs):
        if sys.version_info > (3, 5, 0):
            logger.debug('Loading ssl context with cert %s and key %s' % (self._certfile, self._keyfile,))
            context = create_urllib3_context()
            context.check_hostname = False

            if self._password is None and not self._password_callback is None:
                self._password = self._password_callback(self._keyfile)
            if not self._password and self._keyfile and is_pem_key_encrypted(self._keyfile):
                raise Exception('SSLAdapter: Private key is encrypted, but no password to decrypt it : %s' % self._keyfile)

            context.load_cert_chain(certfile=self._certfile,                        # pylint: disable=unexpected-keyword-arg
                                    keyfile=self._keyfile,
                                    password=self._password)
            # https://github.com/urllib3/urllib3/issues/1634
            if sys.version_info < (3, 7, 4) and sys.version_info >= (3, 6, 0):
                try:
                    context.post_handshake_auth=False
                except:
                    pass
            kwargs['ssl_context'] = context


def get_requests_client_cert_session(url=None, cert=None, verify=True, proxies={'http': None, 'https': None}, **kwargs) -> requests.Session:
    """Returns a requests Session which is aware of client cert auth with password protected key
    Disable use of environ.

    Args:
        url (str): base prefix url for which the session is created
        cert (tuple) : (certfilename,pem encoded key filename, key password)
        verify (bool or str) : verify server certificate. Id str, path to trusted CA bundle

    Returns:
        Session
    """
    result = requests.Session()
    # be sure to not use HTTP_PROXY or HTTPS_PROXY environ variable
    result.trust_env = False
    result.headers = default_http_headers()
    result.verify = get_verify_cert(verify)

    result.proxies = proxies
    if not result.verify:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # pylint: disable=no-member

    if url is not None and cert is not None:
        cert_path = cert[0]
        key_path = cert[1]
        if cert_path is not None and key_path is not None and os.path.isfile(cert_path) and os.path.isfile(key_path):
            # no client cert auth
            if len(cert) < 3:
                # append empty password
                cert = (cert[0], cert[1], None)
            adapter = SSLAdapter(cert[0], cert[1], cert[2], **kwargs)
            if result.verify:
                adapter.poolmanager.connection_pool_kw['ssl_context'].check_hostname = True

            result.mount(url, adapter)
    return result


def wget(url, target=None, printhook=None, proxies=None, connect_timeout=10, download_timeout=None, verify_cert=None, referer=None,
         user_agent=None, cert=None, resume=False, md5=None, sha1=None, sha256=None, cache_dir=None, requests_session=None, limit_bandwidth=None):
    r"""Copy the contents of a file from a given URL to a local file.

    Args:
        url (str): URL to document
        target (str) : full file path of downloaded file. If None, put in a temporary dir with supplied url filename (final part of url)
        proxies (dict) : proxies to use. eg {'http':'http://wpad:3128','https':'http://wpad:3128'}
        timeout (int)  : seconds to wait for answer before giving up
        auth (list)    : (user,password) to authenticate with basic auth
        verify_cert (bool or str) : either False, True (verify with embedded CA list), or path to a directory or PEM encoded CA bundle file
                                    to check https certificate signature against.
        cert (list) : tuple/list of (x509certfilename,pemkeyfilename,key password) for authenticating the client. If key is not encrypted, password must be None
        referer (str):
        user_agent:
        resume (bool):
        md5 (str) :
        sha1 (str) :
        sha256 (str) :
        cache_dir (str) : if file exists here, and md5 matches, copy from here instead of downloading. If not, put a copy of the file here after downloading.

        requests_session (request.Session) : predefined request session to use instead of building one from scratch from proxies, cert, verfify_cert

    Returns:
        str : path to downloaded file

    >>> respath = wget('http://wapt.tranquil.it/wapt/tis-firefox_28.0.0-1_all.wapt','c:\\tmp\\test.wapt',proxies={'http':'http://proxy:3128'})
    ???
    >>> os.stat(respath).st_size>10000
    True
    >>> respath = wget('http://localhost:8088/runstatus','c:\\tmp\\test.json')
    ???
    """
    start_time = time.time()
    last_time_display = 0.0
    last_downloaded = 0

    def reporthook(received, total):
        if total is not None:
            total = float(total)
        else:
            total = received
        if received > 1:
            # print only every 0.5 seconds or at end
            if (time.time()-last_time_display >= 0.5) or (received >= total):
                elapsed = time.time()-start_time
                if elapsed > 0.0:
                    speed = received / (1024.0 * elapsed)
                else:
                    speed = 0
                if printhook:
                    printhook(received, total, speed, url)
                elif sys.stdout is not None:
                    try:
                        if received == 0:
                            print("Downloading %s (%.1f MB)" % (url, int(total)/1024/1024))
                        elif received >= total:
                            print("  -> download finished (%.0f KB/s)" % (total / (1024.0*(time.time()+.001-start_time))))
                        else:
                            print('%i / %i (%.0f%%) (%.0f KB/s)\r' % (received, total, 100.0*received/total, speed))
                    except:
                        return False
                return True
            else:
                return False

    if target is None:
        target = tempfile.gettempdir()

    if os.path.isdir(target):
        target = os.path.join(target, '')

    (adir, filename) = os.path.split(target)
    if not filename:
        url_parts = urllib.parse.urlparse(url)
        filename = url_parts.path.split('/')[-1]
        if not filename:
            filename = next(tempfile._get_candidate_names())

    filename = sanitize_filename(filename)

    if not adir:
        adir = os.getcwd()

    if not os.path.isdir(adir):
        os.makedirs(adir)

    if requests_session is None:
        if verify_cert is None:
            verify_cert = True
        requests_session = get_requests_client_cert_session(url, cert=cert, verify=verify_cert, proxies=proxies)
    elif proxies is not None or verify_cert is not None or cert is not None:
        raise Exception('wget: requests_session and proxies,verify_cert,cert are mutually exclusive')

    with requests_session as session:
        target_fn = os.path.join(adir, filename)
        target_fn_temp = target_fn+'.part'

        # return cached file if md5 matches.
        if (md5 is not None or sha1 is not None or sha256 is not None):
            if cache_dir is None:
                cache_dir = adir
            if cache_dir is not None and os.path.isdir(cache_dir):
                cached_filename = os.path.join(cache_dir, filename)
                if os.path.isfile(cached_filename):
                    if _check_hash_for_file(cached_filename, md5=md5, sha1=sha1, sha256=sha256):
                        resume = False
                        if cached_filename != target_fn:
                            shutil.copy2(cached_filename, target_fn)
                        return target_fn
        else:
            cached_filename = None

        headers = copy.copy(session.headers)
        if referer != None:
            headers.update({'referer': '%s' % referer})
        if user_agent != None:
            headers.update({'user-agent': '%s' % user_agent})

        if os.path.isfile(target_fn_temp) and resume:
            try:
                actual_size = os.stat(target_fn_temp).st_size
                size_req = session.head(url,
                                        timeout=connect_timeout,
                                        headers=headers,
                                        allow_redirects=True)

                target_size = int(size_req.headers['content-length'])
                file_date = size_req.headers.get('last-modified', None)

                if target_size > actual_size:
                    headers.update({'Range': 'bytes=%s-' % (actual_size,)})
                    write_mode = 'ab'
                elif target_size < actual_size:
                    target_size = None
                    write_mode = 'wb'
            except Exception:
                target_size = None
                write_mode = 'wb'

        else:
            file_date = None
            actual_size = 0
            target_size = None
            write_mode = 'wb'

        # check hashes if size equal
        if resume and (md5 is not None or sha1 is not None or sha256 is not None) and target_size is not None and (target_size <= actual_size):
            if not _check_hash_for_file(target_fn_temp, md5=md5, sha1=sha1, sha256=sha256):
                # restart download...
                target_size = None
                write_mode = 'wb'

        if not resume or target_size is None or (target_size - actual_size) > 0:
            httpreq = session.get(url,
                                  stream=True,
                                  timeout=connect_timeout,
                                  headers=headers,
                                  allow_redirects=True)

            httpreq.raise_for_status()

            total_bytes = None
            if 'content-length' in httpreq.headers:
                total_bytes = int(httpreq.headers['content-length'])
                target_free_bytes = get_disk_free_space(os.path.dirname(os.path.abspath(target)))
                if total_bytes > target_free_bytes:
                    raise Exception('wget : not enough free space on target drive to get %s MB. Total size: %s MB. Free space: %s MB' % (url, total_bytes // (1024*1024), target_free_bytes // (1024*1024)))

                # 1Mb max, 1kb min
                chunk_size = min([1024*1024, max([total_bytes//100, 2048])])
            else:
                chunk_size = 1024*1024

            cnt = 0

            with open(target_fn_temp, write_mode) as output_file:
                last_time_display = time.time()
                last_downloaded = 0
                if httpreq.ok:
                    if limit_bandwidth:
                        sleep_time = chunk_size//(limit_bandwidth*1024*1024)
                    else:
                        sleep_time = 0
                    for chunk in httpreq.iter_content(chunk_size=chunk_size):
                        time.sleep(sleep_time)
                        output_file.write(chunk)
                        output_file.flush()
                        cnt += 1
                        if download_timeout is not None and (time.time()-start_time > download_timeout):
                            raise requests.Timeout(r'Download of %s takes more than the requested %ss' % (url, download_timeout))
                        if reporthook(cnt*len(chunk), total_bytes):
                            last_time_display = time.time()
                        last_downloaded += len(chunk)
                    if reporthook(last_downloaded, total_bytes or last_downloaded):
                        last_time_display = time.time()

            # check hashes
            if sha256 is not None:
                file_hash = _hash_file(target_fn_temp, hash_func=hashlib.sha256)
                if file_hash != sha256.lower():
                    raise Exception('Downloaded file %s sha256 %s does not match expected %s' % (url, file_hash, sha256))
            elif sha1 is not None:
                file_hash = _hash_file(target_fn_temp, hash_func=hashlib.sha1)
                if file_hash != sha1.lower():
                    raise Exception('Downloaded file %s sha1 %s does not match expected %s' % (url, file_hash, sha1))
            elif md5 is not None:
                file_hash = _hash_file(target_fn_temp, hash_func=hashlib.md5)
                if file_hash != md5.lower():
                    raise Exception('Downloaded file %s md5 %s does not match expected %s' % (url, file_hash, md5))

            file_date = httpreq.headers.get('last-modified', None)

        if file_date:
            file_datetime_local = httpdatetime2time(file_date,localtime=True)
            os.utime(target_fn_temp, (file_datetime_local, file_datetime_local))

        if os.path.isfile(target_fn):
            os.unlink(target_fn)
        shutil.move(target_fn_temp,target_fn)

        # cache result
        if cache_dir:
            if not os.path.isdir(cache_dir):
                os.makedirs(cache_dir)
            cached_filename = os.path.join(cache_dir, filename)
            if target_fn != cached_filename:
                shutil.copy2(target_fn, cached_filename)

    return target_fn


def wgets(url, proxies:dict=None, verify_cert=None, referer=None, user_agent=None, timeout=None, cert=None, requests_session=None, as_json = False)->str:
    """Return the content of a remote resource as a string / bytes or dict with a http get request.

    Raise an exception if remote data can't be retrieved.

    Args:
        url (str): http(s) url
        proxies (dict): proxy configuration as requests requires it {'http': url, 'https':url}
        verify_cert (bool or str) : verfiy server certificate, path to trusted CA bundle
        cert (tuple of 3 str) : (cert_path, key_path, key password) client side authentication.

        requests_session (request.Session) : predefined request session to use instead of building one from scratch

    Returns:
        str or bytes or dict : content of remote resource. str or bytes or json depending of the encoding and the Content-Type.

    >>> data = wgets('https://wapt/ping')
    >>> "msg" in data
    True
    """
    if requests_session is None:
        if verify_cert is None:
            verify_cert = True
        requests_session = get_requests_client_cert_session(url, cert=cert, verify=verify_cert, proxies=proxies)
    elif proxies is not None or verify_cert is not None or cert is not None:
        raise Exception('wgets: requests_session and proxies,verify_cert,cert are mutually exclusive')

    with requests_session as session:
        if referer != None:
            session.headers.update({'referer': '%s' % referer})
        if user_agent != None:
            session.headers.update({'user-agent': '%s' % user_agent})
        r = session.get(url, timeout=timeout, allow_redirects=True)
        if r.ok:
            if as_json and 'application/json' in r.headers.get('Content-Type'):
                return r.json()
            elif 'text/' in r.headers.get('Content-Type'):
                return r.text
            else:
                return r.content
        else:
            r.raise_for_status()


class FileChunks(object):
    def __init__(self, filename, chunk_size=2*1024*1024, progress_hook=None):
        self.chunk_size = chunk_size
        self.amount_seen = 0
        self.filename = filename
        self.file_obj = open(filename, 'rb')
        self.file_size = os.fstat(self.file_obj.fileno()).st_size
        self.progress_hook = progress_hook

    def get(self):
        try:
            data = self.file_obj.read(self.chunk_size)
            while len(data) > 0:
                self.amount_seen += len(data)
                if self.progress_hook:
                    cancel_request = self.progress_hook(self.filename, self.amount_seen, self.file_size)
                    if cancel_request:
                        raise Exception('Post canceled by user')
                else:
                    print('Uploading %s: %s / %s\r' % (self.filename, self.amount_seen, self.file_size))
                yield data
                data = self.file_obj.read(self.chunk_size)
        finally:
            if not self.progress_hook:
                print('Done Uploading %s' % (self.filename,))
            self.file_obj.close()

    def reopen(self):
        self.file_obj.close()
        self.file_obj = open(self.filename, 'rb')
        self.amount_seen = 0

    def close(self):
        if not self.file_obj.closed:
            self.file_obj.close()


class Version(object):
    """Version object of form 0.0.0
    can compare with respect to natural numbering and not alphabetical

    Args:
        version (str) : version string
        member_count (int) : number of version memebers to take in account.
                             If actual members in version is less, add missing memeber with 0 value
                             If actual members count is higher, removes last ones.

    >>> Version('0.10.2') > Version('0.2.5')
    True
    >>> Version('0.1.2') < Version('0.2.5')
    True
    >>> Version('0.1.2') == Version('0.1.2')
    True
    >>> Version('7') < Version('7.1')
    True

    .. versionchanged:: 1.6.2.5
        truncate version members list to members_count if provided.
    """

    def __init__(self, version, members_count: int = None):
        if version is None:
            version = ''
        assert isinstance(version, types.ModuleType) or isinstance(version, bytes) or isinstance(version, str) or isinstance(version, Version)
        if isinstance(version, types.ModuleType):
            self.versionstring = getattr(version, '__version__', None)
        elif isinstance(version, Version):
            self.versionstring = getattr(version, 'versionstring', None)
        else:
            self.versionstring = version
        self.members = [v.strip() for v in self.versionstring.split('.') if v]
        self.members_count = members_count
        if members_count is not None:
            if len(self.members) < members_count:
                self.members.extend(['0'] * (members_count-len(self.members)))
            else:
                self.members = self.members[0:members_count]

    def __cmp__(self, aversion) -> int:
        def nat_cmp(a, b):
            a = a or ''
            b = b or ''

            def convert(text):
                if text.isdigit():
                    return int(text)
                else:
                    return text.lower()

            def alphanum_key(key):
                return [convert(c) for c in re.split('([0-9]+)', key)]

            def cmp(a, b):
                return (a > b)-(a < b)

            return cmp(alphanum_key(a), alphanum_key(b))

        if not isinstance(aversion, Version):
            aversion = Version(aversion, self.members_count)
        for i in range(0, max([len(self.members), len(aversion.members)])):
            if i < len(self.members):
                i1 = self.members[i]
            else:
                i1 = '0'
            if i < len(aversion.members):
                i2 = aversion.members[i]
            else:
                i2 = '0'
            v = nat_cmp(i1, i2)
            if v:
                return v
        return 0

    def __lt__(self, aversion) -> bool:
        return self.__cmp__(aversion) < 0

    def __eq__(self, aversion) -> bool:
        return self.__cmp__(aversion) == 0

    def __le__(self, aversion) -> bool:
        return self.__cmp__(aversion) <= 0

    def __ne__(self, aversion) -> bool:
        return self.__cmp__(aversion) != 0

    def __gt__(self, aversion) -> bool:
        return self.__cmp__(aversion) > 0

    def __ge__(self, aversion) -> bool:
        return self.__cmp__(aversion) >= 0

    def __str__(self) -> str:
        return '.'.join(self.members)

    def __repr__(self) -> str:
        return "Version('{}')".format('.'.join(self.members))

    def sortable_str(self) -> str:
        """Output a str suitable for direct ordering
        members are converted to a chars hex padded with zero on the left.
        If member is not a digit, it is padded to a 8 chars string padded with spaces on the right.
        """
        return '.'.join('%08d' % m if isinstance(m,int) else '%08d' % int(m) if m.isdigit() else '%-8s' % m for m in self.members)

    def next_str(self) -> str:
        return '.'.join('%s' % m for m in self.members[0:-1] + [int(self.members[-1])+1,])

    def next(self) -> 'Version':
        return Version(self.next_str(),members_count=self.members_count)

def create_recursive_zip(zipfn: Union[str, zipfile.ZipFile], source_root: str, target_root: str = "",
    excludes: List[str] = ['.svn', '.git', '.gitignore', '*.pyc', '*.dbg','__pycache__'],
    excludes_full: List[str] = [os.path.join('WAPT', 'manifest.sha256')]):
    """Create a zip file with filename zipf from source_root directory with target_root as new root.
    Don't include file which match excludes file pattern

    Args;
        zipfn (unicode or ZipFile) : filename for zip file to create
        source_root (unicode) : root directory of filetree to zip
        target_root (unicode) ! root directory for all in zip file
        excludes (list)  : list of glob pattern of files to excludes
        excludes_full (list) : full "relative to source_root" filepath of files to exclude

    Returns:
        list : list of zipped filepath
    """
    result = []
    if not isinstance(source_root, str):
        source_root = str(source_root)
    if not isinstance(target_root, str):
        target_root = str(target_root)

    if isinstance(zipfn, str):
        if logger:
            logger.debug('Create zip file %s' % zipfn)
        zipf = CustomZipFile(zipfn, 'w', allowZip64=True, compression=zipfile.ZIP_DEFLATED)
    elif isinstance(zipfn, zipfile.ZipFile):
        zipf = zipfn
    else:
        raise Exception('zipfn must be either a filename (string) or an ZipFile')
    for item in os.listdir(source_root):
        excluded = False
        for x in excludes:
            excluded = fnmatch.fnmatch(item, x)
            if excluded:
                break
        if excluded:
            continue
        source_item_fn = os.path.join(source_root, item)
        if target_root:
            zip_item_fn = target_root + '/' + item
        else:
            zip_item_fn = item
        # exclude manifest and signature which are added afterward
        if zip_item_fn in excludes_full:
            continue
        if os.path.isfile(source_item_fn):
            #if logger: logger.debug(u' adding file %s' % source_item_fn)
            zipf.write(source_item_fn, zip_item_fn)
            result.append(zip_item_fn)
        # Defensive code, always True except for symlink pointing non existing file
        elif os.path.isdir(source_item_fn):
            #if logger: logger.debug(u'Add directory %s' % source_item_fn)
            # write directory entry even if empty
            zipf.write(source_item_fn, zip_item_fn)
            result.extend(create_recursive_zip(zipf, source_item_fn, zip_item_fn, excludes=excludes, excludes_full=excludes_full))
    if isinstance(zipfn, str) or isinstance(zipfn, str):
        zipf.close()
    return result


def find_all_files(rootdir: str,
    include_patterns: Optional[Union[str, List[str]]] = None,
    exclude_patterns: Optional[Union[str, List[str]]] = None,
    include_dirs: Optional[Union[str, List[str]]] = None,
    exclude_dirs: Optional[Union[str, List[str]]] = None,
    excludes_full: Optional[List[str]] = None):
    """Generator which recursively find all files from rootdir and sub directories
    matching the (dos style) patterns (example: *.exe)

    Args;
        rootdir (str): root dir where to start looking for files
        include_patterns (str or list) : list of glob pattern of files to return
        exclude_patterns (str or list) : list of glob pattern of files to exclude
                                         (if a file is both in include and exclude, it is excluded)

        include_dirs (str or list) : list of glob directory patterns to return
        exclude_dirs (str or list) : list of glob directory patterns to exclude
                                         (if a dir is both in include and exclude, it is excluded)
        excludes_full (list) : list of exact (relative to package root) filepathes to exclude from manifest.

    >>> for fn in find_all_files('c:\\tmp','*.txt'):
            print(fn)
    >>>
    """
    def match(fn, include_patterns, exclude_patterns):
        if include_patterns:
            result = False
            for pattern in include_patterns:
                if glob.fnmatch.fnmatch(fn, pattern):
                    result = True
                    break
        else:
            result = True

        if exclude_patterns:
            for pattern in exclude_patterns:
                if glob.fnmatch.fnmatch(fn, pattern):
                    result = False
                    break
        return result

    def do_find_all_files(rootdir):
        absolute_rootdir = os.path.abspath(rootdir)
        relative_rootdir = os.path.relpath(absolute_rootdir, top_rootdir)

        for fn in os.listdir(absolute_rootdir):
            if not excludes_full or not os.path.join(relative_rootdir, fn) in excludes_full:
                full_fn = os.path.join(absolute_rootdir, fn)
                if os.path.isdir(full_fn):
                    if match(fn, include_dirs, exclude_dirs):
                        for fn in do_find_all_files(full_fn):
                            yield fn
                else:
                    if match(fn, include_patterns, exclude_patterns):
                        yield full_fn

    top_rootdir = os.path.relpath(rootdir)
    if include_patterns and not isinstance(include_patterns, list):
        include_patterns = [include_patterns]

    if exclude_patterns and not isinstance(exclude_patterns, list):
        exclude_patterns = [exclude_patterns]

    if include_dirs and not isinstance(include_dirs, list):
        include_dirs = [include_dirs]

    if exclude_dirs and not isinstance(exclude_dirs, list):
        exclude_dirs = [exclude_dirs]

    return do_find_all_files(rootdir)


def all_files(rootdir: str, pattern: str = None) -> List[str]:
    """Recursively return all files from rootdir and sub directories
    matching the (dos style) pattern (example: *.exe)
    """
    rootdir = os.path.abspath(rootdir)
    result = []
    for fn in os.listdir(rootdir):
        full_fn = os.path.join(rootdir, fn)
        if os.path.isdir(full_fn):
            result.extend(all_files(full_fn, pattern))
        else:
            if not pattern or glob.fnmatch.fnmatch(fn, pattern):
                result.append(full_fn)
    return result

def all_dirs(rootdir: str, pattern: str = None) -> List[str]:
    """Recursively return all directories from rootdir and sub directories
    matching the (dos style) pattern (example: 'tag*')
    """
    rootdir = os.path.abspath(rootdir)
    result = []
    for fn in os.listdir(rootdir):
        full_fn = os.path.join(rootdir, fn)
        if os.path.isdir(full_fn):
            if not pattern or glob.fnmatch.fnmatch(fn, pattern):
                result.append(full_fn)
            result.extend(all_dirs(full_fn, pattern))
    return result


def all_empty_dirs(rootdir: str, pattern: str = None) -> List[str]:
    """Recursively return all empty directories from rootdir and sub directories
    matching the (dos style) pattern (example: 'tag*')
    """
    rootdir = os.path.abspath(rootdir)
    result = []
    is_empty = True
    for fn in os.listdir(rootdir):
        is_empty = False
        full_fn = os.path.join(rootdir, fn)
        if os.path.isdir(full_fn):
            result.extend(all_empty_dirs(full_fn,pattern))
    if is_empty and (not pattern or glob.fnmatch.fnmatch(os.path.basename(rootdir), pattern)):
        result.append(rootdir)
    return result


def touch(filename: str):
    if not os.path.isdir(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    if not os.path.isfile(filename):
        open(filename, 'w').close()
    else:
        os.utime(filename, None)


def import_code(code: str, name: str = '', add_to_sys_modules: bool = False):
    """\
    Import dynamically generated code as a module. code is the
    object containing the code (a string, a file handle or an
    actual compiled code object, same types as accepted by an
    exec statement). The name is the name to give to the module,
    and the final argument says wheter to add it to sys.modules
    or not. If it is added, a subsequent import statement using
    name will return this module. If it is not added to sys.modules
    import will try to load it in the normal fashion.

    import foo

    is equivalent to

    foofile = open("/path/to/foo.py")
    foo = import_code(foofile,"foo",1)

    Returns a newly generated module.
    From : http://code.activestate.com/recipes/82234-importing-a-dynamically-generated-module/

    Args:
        code (str): python code to load as a module
        name (str): import code as module name
        add_to_sys_modules (bool): True if module must be globally available as a sys module

    Returns:
        module: module object
    """
    import sys
    import imp

    if not name:
        name = '__waptsetup_%s__' % generate_unique_string()

    logger.debug('Import source code as %s' % (name))
    module = imp.new_module(name)

    exec(code, module.__dict__)
    if add_to_sys_modules:
        sys.modules[name] = module

    return module


def import_setup(setupfilename, modulename=''):
    """Import setupfilename as modulename, return the module object

    Args:
        setupfilename (str): path to module

    Returns:
        module: loaded module
    """
    try:
        if not modulename:
            modulename = '__waptsetup_%s__' % generate_unique_string()
        # can debug but keep module in memory
        logger.debug('Import source %s as %s' % (setupfilename, modulename))
        py_mod = imp.load_source(modulename, setupfilename)
        # can not debug but memory is not cumbered with setup.py modules
        #py_mod = import_code(codecs.open(setupfilename,'r').read(), modulename)
        return py_mod
    except Exception:
        logger.critical('Error importing %s :\n%s' % (setupfilename, ensure_unicode(traceback.format_exc())))
        raise


def remove_encoding_declaration(source):
    headers = source.split('\n', 3)
    result = []
    for h in headers[0:3]:
        result.append(h.replace('coding:', 'coding is').replace('coding=', 'coding is').replace('\ufeff', ''))
    result.extend(headers[3:])
    return "\n".join(result)


def list_intersection(list1: Optional[List[Any]], list2: Optional[List[Any]]) -> List[Any]:
    if list1 is None or list2 is None:
        return []
    return [item for item in list1 if item in list2]


def get_language() -> str:
    """Get the default locale like fr, en, pl etc..  etc

    >>> get_language()
    'fr'
    """
    return locale.getdefaultlocale()[0].split('_')[0]


class BaseObjectClass(object):
    def _pyobject(self):
        """Return pure python reference for calls in FreePascal"""
        return self


class LogOutput(BaseObjectClass):
    """File like contextual object to log print output to a db installstatus
    using update_status_hook

    output list gather all the stout / stderr output

    Args:
        console (fileout): print message here
        update_status_hook (func): hook to call when printing.
                                            Must accept "append_line" and "set_status" kwargs
                                            and will get context "**hook_args" at each call.

    Returns:
        stout file like object


    >>> def update_status(append_line,set_status=None,**kwargs):
            if set_status is not None:
                print('+ Status to: %s' % set_status)
            print(u'+out %s: %s' % (kwargs,append_line))
    >>> with LogInstallOutput(sys.stdout,update_status_hook=update_status,install_id=12,user='moi'):
            print('Install in progress')

    """

    def __init__(self, console=None, update_status_hook=None, running_status='RUNNING', exit_status='OK', error_status='ERROR', **hook_args):
        self.old_stdout = None
        self.old_stderr = None

        self.output = []
        self.console = console
        self.line = ''

        self.update_status_hook = update_status_hook
        self.hook_args = hook_args
        self.threadid = threading.current_thread()

        self.lock = threading.RLock()

        self.running_status = running_status
        self.error_status = error_status
        self.exit_status = exit_status

        # don't send output to update_hook too often
        self.update_buffer_time = 1.0
        self.last_update_time = 0
        self.last_update_idx = 0


    def _send_tail_to_updatehook(self):
        """send pending output to hook"""
        append_txt = '\n'.join(self.output[self.last_update_idx:])
        try:
            if append_txt:
                self.update_status_hook(append_line=append_txt, set_status=self.running_status, **self.hook_args)
            self.last_update_idx = len(self.output)
            self.last_update_time = time.time()
        except Exception as e:
            logger.info('Unable to update db status %s' % e)

    def write(self, txt):
        with self.lock:
            self.line = self.line + ensure_unicode(txt)
            if self.line.endswith('\n'):
                line = self.line.rstrip('\n')
                self.output.append(line)
                if self.update_status_hook and threading.current_thread() == self.threadid and (time.time()-self.last_update_time >= self.update_buffer_time):
                    # wait update_buffer_time before sending data to update_hook to avoid high frequency I/O
                    self._send_tail_to_updatehook()
                self.line = ''

            if self.console:
                try:
                    self.console.stream.write(txt)
                except Exception:
                    try:
                        self.console.write(txt)
                    except Exception:
                        self.console.write(repr(txt))

    def __enter__(self):
        self.old_stdout = sys.stdout
        self.old_stderr = sys.stderr
        sys.stderr = sys.stdout = self
        return self

    def __exit__(self, type, value, tb):
        try:
            if self.line:
                self.output.append(self.line)

            if self.update_status_hook and threading.current_thread() == self.threadid:
                self._send_tail_to_updatehook()

            if self.update_status_hook:
                if tb:
                    self.update_status_hook(set_status=self.error_status, append_line=traceback.format_exc(), **self.hook_args)
                else:
                    if self.exit_status is not None:
                        self.update_status_hook(set_status=self.exit_status, **self.hook_args)

        finally:
            self.update_status_hook = None
            self.console = None

            if self.old_stdout:
                sys.stdout = self.old_stdout
            if self.old_stderr:
                sys.stderr = self.old_stderr

    def __getattr__(self, name):
        return getattr(self.console, name)


def get_time_delta(schedule: str, default_unit: str = 'm') -> datetime.timedelta:
    """Convert a str time delta with unit to a datetime.timedelta

    Returns:
        datetime.timedelta
    """
    if schedule is not None:
        if schedule[-1] not in ('s', 'm', 'h', 'd', 'w'):
            schedule = schedule + default_unit
        if schedule.endswith('s'):
            timedelta = datetime.timedelta(seconds=float(schedule[:-1]))
        elif schedule.endswith('m'):
            timedelta = datetime.timedelta(minutes=float(schedule[:-1]))
        elif schedule.endswith('h'):
            timedelta = datetime.timedelta(hours=float(schedule[:-1]))
        elif schedule.endswith('d'):
            timedelta = datetime.timedelta(days=float(schedule[:-1]))
        elif schedule.endswith('w'):
            timedelta = datetime.timedelta(days=7*float(schedule[:-1]))
        else:
            timedelta = datetime.timedelta(minutes=float(schedule))
    else:
        timedelta = None
    return timedelta


def makepath(*p) -> str:
    r"""Create a path given the components passed, but with saner defaults than os.path.join - In particular, removes ending path separators (backslashes) from components. Path functions will be called automatically

    >>> makepath("c:", "Windows", "system32")
    'c:\\Windows\\system32'
    >>> makepath(system32())
    'C:\\WINDOWS\\system32'
    >>> system32()
    'C:\\WINDOWS\\system32'
    >>> system32
    <function system32 at 0x063EBE79>
    >>> makepath(system32)
    'C:\\WINDOWS\\system32'

    """
    parts = []
    if platform.system() == "Windows":
        for part in p:
            if hasattr(part, "__call__"):
                part = part()
            part = part.lstrip(os.path.sep)
            if part.endswith(":"):
                part += os.path.sep
            parts.append(part)
        return os.path.join(*parts)
    else:
        return os.path.join(*p)


def killtree(pid, including_parent=True):
    try:
        parent = psutil.Process(pid)
        if parent:
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except (psutil.AccessDenied, psutil.NoSuchProcess): # a chid process can't be killed if the child process have already received a kill signal from the parent
                    pass
            if including_parent:
                parent.kill()
    except psutil.NoSuchProcess:
        pass


def killalltasks(exenames, include_children=True):
    """Kill the task by their exename

    >>> killalltasks('firefox.exe')
    """
    logger.debug('Kill tasks %s' % (exenames,))
    if not exenames:
        return []
    if not isinstance(exenames, list):
        exenames = [exenames]

    exenames = [x.strip() for x in exenames]

    result = []
    exenames = [exe.lower() for exe in exenames]+[exe.lower()+'.exe' for exe in exenames if not exe.lower().endswith('.exe')]
    for p in psutil.process_iter():
        try:
            if p.name().lower() in exenames:
                logger.debug('Kill process %i' % (p.pid,))
                result.append((p.pid, p.name()))
                if include_children:
                    killtree(p.pid)
                else:
                    p.kill()
        except (psutil.NoSuchProcess,psutil.AccessDenied): #AccessDenied for WSL processes (they break psutil)
            pass

    return result
    """
    for c in exenames:
      run(u'taskkill /t /im "%s" /f' % c)
    """


def isrunning(processname):
    """Check if a process is running,

    >>> isrunning('explorer')
    True
    """
    processname = processname.lower()
    for p in psutil.process_iter():
        try:
            if p.name().lower() == processname or p.name().lower() == processname+'.exe':
                return True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return False


def remove_file(path: str):
    r"""Try to remove a single file or symlink
    log a warning msg if file doesn't exist
    log a critical msg if file can't be removed

    Args:
        path (str): path to file

    >>> remove_file(r'c:\tmp\fc.txt')

    """
    def remove_one_file(path: str):
        if os.path.isfile(path):
            try:
                os.remove(path)
            except Exception as e:
                logger.critical('Unable to remove file %s : error %s' % (path, e))
        # TODO: Verify this: if symlink points to a file, the first condition is true and the file is deleted instead of the symlink
        elif os.path.islink(path):
            try:
                os.unlink(path)
            except Exception as e:
                logger.critical('Unable to remove symlink %s : error %s' % (path, e))
        else:
            logger.info("File %s doesn't exist or is not a file, so not removed" % (path))

    if '*' in path:
        filelist = glob.glob(path)
        for filepath in filelist:
            remove_one_file(filepath)
    else:
        remove_one_file(path)


def mkdirs(path: str):
    """Create directory path if it doesn't exists yet
    Creates intermediate directories too.

    >>> mkdirs("C:\Program Files (x86)\wapt")
    u'C:\Program Files (x86)\wapt'
    """
    if not os.path.isdir(path):
        os.makedirs(path)


def ensure_dir(filename: str):
    """Be sure the directory of filename exists on disk. Create it if not

    The intermediate directories are created either.

    Args:
        filename (str): path to a future file for which to create directory.
    Returns:
        None

    """
    d = os.path.dirname(filename)
    if not os.path.isdir(d):
        os.makedirs(d)


def currentdate():
    """date as string YYYYMMDD

    >>> currentdate()
    '20161102'
    """
    return time.strftime('%Y%m%d')


def currentdatetime():
    """date/time as YYYYMMDD-hhmmss

    >>> currentdatetime()
    '20161102-193600'
    """
    return time.strftime('%Y%m%d-%H%M%S')


def _lower(s):
    return s.lower()


def ini2winstr(ini):
    """Returns a unicode string from an iniparse.RawConfigParser with windows crlf
    Utility function for local gpo
    """
    items = []
    for sub in [("%s" % l).strip() for l in ini.data._data.contents]:
        items.extend(sub.splitlines())
    return '\r\n'.join(items)


def error(reason: str):
    """Raise a WAPT fatal error"""
    raise EWaptSetupException('Fatal error : %s' % reason)


def get_sha256(afile: str = '', BLOCK_SIZE: int = 2**20) -> str:
    return _hash_file(afile, BLOCK_SIZE, hashlib.sha256)


def get_main_ip(host=None, hostv6=None):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't even have to be reachable
        s.connect(('10.0.0.0' if host is None else host, 1))
        IPV4 = s.getsockname()[0]
    except:
        IPV4 = '127.0.0.1'
    finally:
        if s:
            s.close()
    s = None
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        if hostv6 is None:
            hostv6 = host
        s.connect(('ff05::1' if hostv6 is None else hostv6, 1))
        IPV6 = s.getsockname()[0]
    except:
        IPV6 = '::1'
    finally:
        if s:
            s.close()
    return (IPV4, IPV6.split('%')[0])

def get_net_interfaces(up_only=True):
    return [i[0] for i in psutil.net_if_stats().items() if not up_only or i[1].isup]

def get_net_ips(up_only=True,families=[socket.AF_INET,socket.AF_INET6]):
    result = []
    if_addrs = psutil.net_if_addrs()
    for netif in get_net_interfaces(up_only=up_only):
        if netif in if_addrs:
            result.extend([a.address for a in if_addrs[netif] if a.family in families and a.address not in ('127.0.0.1','::1')])
    return result

def get_local_IPs():
    list_addressv4 = []
    list_addressv6 = []

    for interface in netifaces.interfaces():
        if_address = netifaces.ifaddresses(interface)
        if if_address.get(netifaces.AF_INET):
            list_addressv4.extend([addr['addr'] for addr in if_address[netifaces.AF_INET] if addr['addr'] != '127.0.0.1'])
        if if_address.get(netifaces.AF_INET6):
            list_addressv6.extend([addr['addr'].split('%')[0] for addr in if_address[netifaces.AF_INET6] if addr['addr'] != '::1'])
    return list_addressv4+list_addressv6


def is_between_two_times(time1: str, time2: str) -> bool:
    time_now = datetime.datetime.utcnow()
    time_nowHHMM = '%s:%s' % (str(time_now.hour) if time_now.hour > 9 else '0'+str(time_now.hour), str(time_now.minute) if time_now.minute > 9 else '0'+str(time_now.hour))
    if time2 < time1:
        return time_nowHHMM >= time1 or time_nowHHMM <= time2
    else:
        return time1 <= time_nowHHMM <= time2


class EWaptSetupException(Exception):
    pass


class RunReader(threading.Thread):
    # helper thread to read output of run command
    def __init__(self, callable, *args, **kwargs):
        super(RunReader, self).__init__()
        self.callable = callable
        self.args = args
        self.kwargs = kwargs
        self.setDaemon(True)

    def run(self):
        try:
            self.callable(*self.args, **self.kwargs)
        except Exception as e:
            print((ensure_unicode(e)))

def run_notfatal(*cmd, **args):
    """Runs the command and wait for it termination, returns output
    Ignore exit status code of command, return '' instead

    .. versionchanged:: 1.4.0
          output is now enforced to unicode
    """
    try:
        return run(*cmd, accept_returncodes=None, **args)
    except Exception as e:
        return ensure_unicode(e)

def run(cmd, shell=True, timeout=600, accept_returncodes=[0, 3010], on_write=None, pidlist=None, return_stderr=True, **kwargs):
    r"""Run the command cmd in a shell and return the output and error text as string

    Args:
        cmd : command and arguments, either as a string or as a list of arguments
        shell (boolean) : True is assumed
        timeout (int) : maximum time to wait for cmd completion is second (default = 600)
                        a TimeoutExpired exception is raised if tiemout is reached.
        on_write : callback when a new line is printed on stdout or stderr by the subprocess
                        func(unicode_line). arg is enforced to unicode
        accept_returncodes (list) : list of return code which are considered OK default = (0, 3010)
        pidlist (list): external list where to append the pid of the launched process.
        return_stderr (bool or list) : if True, the error lines are returned to caller in result.
                                       if a list is provided, the error lines are appended to this list

        all other parameters from the psutil.Popen constructor are accepted

    Returns:
        RunOutput : bytes like output of stdout and optionnaly stderr streams.
                    returncode attribute

    Raises:
        CalledProcessError: if return code of cmd is not in accept_returncodes list
        TimeoutExpired:  if process is running for more than timeout time.

    .. versionchanged:: 1.3.9
            return_stderr parameters to disable stderr or get it in a separate list
            return value has a returncode attribute to

    .. versionchanged:: 1.4.0
            output is not forced to unicode

    .. versionchanged:: 1.4.1
          error code 1603 is no longer accepted by default.

    .. versionchanged:: 1.5.1
          If cmd is unicode, encode it to default filesystem encoding before
            running it.

    >>> run(r'dir /B c:\windows\explorer.exe')
    'explorer.exe\r\n'

    >>> out = []
    >>> pids = []
    >>> def getlines(line):
    ...    out.append(line)
    >>> run(r'dir /B c:\windows\explorer.exe',pidlist=pids,on_write=getlines)
    u'explorer.exe\r\n'

    >>> print out
    ['explorer.exe\r\n']
    >>> try:
    ...     run(r'ping /t 127.0.0.1',timeout=3)
    ... except TimeoutExpired:
    ...     print('timeout')
    timeout
    """
    logger.info('Run "%s"' % (ensure_unicode(cmd),))
    output = []

    if return_stderr is None or return_stderr == False:
        return_stderr = []
    elif not isinstance(return_stderr, list):
        return_stderr = output

    if pidlist is None:
        pidlist = []

    # unicode cmd is not understood by shell system anyway...
    if not platform.system() == 'Windows' and isinstance(cmd, str):
        cmd = cmd.encode(sys.getfilesystemencoding())

    try:
        proc = psutil.Popen(cmd, shell=shell, bufsize=-1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    except ExceptionRun as e:
        # be sure to not trigger encoding errors.
        raise ExceptionRun(get_exception_run_arg(e, 0), repr(get_exception_run_arg(e, 1)));
    # keep track of launched pid if required by providing a pidlist argument to run
    if not proc.pid in pidlist:
        pidlist.append(proc.pid)

    def worker(pipe, on_write=None):
        while True:
            line = pipe.readline()
            if not line:
                break
            else:
                line = ensure_unicode(line) if platform.system() == 'Windows' else line.decode("utf-8")
                if on_write:
                    on_write(ensure_unicode(line))
                if pipe == proc.stderr:
                    return_stderr.append(line)
                else:
                    output.append(line)

    stdout_worker = RunReader(worker, proc.stdout, on_write)
    stderr_worker = RunReader(worker, proc.stderr, on_write)
    stdout_worker.start()
    stderr_worker.start()
    stdout_worker.join(timeout)
    if stdout_worker.is_alive():
        # kill the task and all subtasks
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd, ''.join(output), timeout)
    stderr_worker.join(timeout)
    if stderr_worker.is_alive():
        if proc.pid in pidlist:
            pidlist.remove(proc.pid)
            killtree(proc.pid)
        raise TimeoutExpired(cmd, ''.join(output), timeout)
    if platform.system() == 'Windows':
        proc.returncode = _winapi.GetExitCodeProcess(proc._handle)
    else:
        proc.returncode = proc.wait()
    if proc.pid in pidlist:
        pidlist.remove(proc.pid)
        killtree(proc.pid)
    if accept_returncodes is not None and not proc.returncode in accept_returncodes:
        if return_stderr != output:
            raise CalledProcessErrorOutput(proc.returncode, cmd, ''.join(output+return_stderr))
        else:
            raise CalledProcessErrorOutput(proc.returncode, cmd, ''.join(output))
    else:
        if proc.returncode == 0:
            logger.info('%s command returns code %s' % (ensure_unicode(cmd), proc.returncode))
        else:
            logger.warning('%s command returns code %s' % (ensure_unicode(cmd), proc.returncode))
    result = RunOutput(output)
    result.returncode = proc.returncode
    return result

CalledProcessError = subprocess.CalledProcessError

class TimeoutExpired(Exception):
    """This exception is raised when the timeout expires while waiting for a
    child process.

    >>> try:
    ...     run('ping -t 10.10.1.67',timeout=5)
    ... except TimeoutExpired as e:
    ...     print e.output
    ...     raise
    ...

    """

    def __init__(self, cmd, output=None, timeout=None):
        self.cmd = cmd
        self.output = output
        self.timeout = timeout

    def __str__(self):
        return "Command '%s' timed out after %s seconds with output '%s'" % (self.cmd, self.timeout, repr(self.output))


class RunOutput(str):
    """Subclass of str (bytes) to return returncode from runned command in addition to output

    >>> run(r'cmd /C dir c:\toto ',accept_returncodes=[0,1])
    No handlers could be found for logger "root"
    <RunOuput returncode :[0, 1]>
     Le volume dans le lecteur C n'a pas de nom.
     Le numéro de série du volume est 74EF-5918

    Fichier introuvable
     Répertoire de c:\

    .. versionchanged:: 1.4.0
          subclass str(bytes string) and not unicode
    """

    def __new__(cls, value):
        if isinstance(value, list):
            value = ''.join(value)
        self = super(RunOutput, cls).__new__(cls, value)
        self.returncode = None
        return self

    def __repr__(self):
        return "<RunOuput returncode :%s>\n%s" % (self.returncode, str.__repr__(self))

def networking():
    """return a list of (iface,mac,{addr,broadcast,netmask})
    """
    ifaces = netifaces.interfaces()
    local_ips = get_net_ips(up_only=True)
    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface': i, 'mac': params
                     [netifaces.AF_LINK][0]['addr'], 'addr': []}
            if netifaces.AF_INET in params:
                for a in params[netifaces.AF_INET]:
                    a['connected'] = 'addr' in a and a['addr'] in local_ips
                    iface['addr'].append(a)
            if netifaces.AF_INET6 in params:
                for a in params[netifaces.AF_INET6]:
                    if 'addr' in a:
                        a['addr'] = a['addr'].split('%')[0]
                    a['connected'] = 'addr' in a and a['addr'] in local_ips
                    iface['addr'].append(a)
            res.append(iface)
    return res

class Timeit:
    def __init__(self,title='',store=None):
        self.title = title
        self.store = store
    def __enter__(self):
        self.t1 = time.time()
    def __exit__(self,exc_type, exc_value, traceback):
        timing = time.time()-self.t1
        logger.debug('%s timing: %s s' % (self.title,timing))
        if self.store is not None:
            self.store[self.title] = timing

def safe_cmp(a,b):
    try:
        if a == b:
            return 0
        elif a is None and b is not None:
            return -1
        elif a is not None and b is None:
            return 1
        elif a < b:
            return -1
        else:
            return 1
    except:
        return 1

def safe_cmp_tuples(t1,t2):
    result = 0
    for a,b in itertools.zip_longest(t1,t2):
        result = safe_cmp(a,b)
        if result != 0:
            break
    return result

# from https://github.com/python/cpython/pull/19358
class CustomZipFile(zipfile.ZipFile):

    def __init__(self, file, mode="r", compression=zipfile.ZIP_STORED, allowZip64=True,
                 compresslevel=None, *, strict_timestamps=False): # set strict_timestamps to False
        zipfile.ZipFile.__init__(self, file=file, mode=mode, compression=compression, allowZip64=allowZip64, compresslevel=compresslevel, strict_timestamps=strict_timestamps)


    def remove(self, member):
        """Remove a file from the archive. The archive must be open with mode 'a'"""

        if self.mode != 'a':
            raise RuntimeError("remove() requires mode 'a'")
        if not self.fp:
            raise ValueError(
                "Attempt to write to ZIP archive that was already closed")
        if self._writing:
            raise ValueError(
                "Can't write to ZIP archive while an open writing handle exists."
            )

        # Make sure we have an info object
        if isinstance(member, zipfile.ZipInfo):
            # 'member' is already an info object
            zinfo = member
        else:
            # get the info object
            zinfo = self.getinfo(member)

        return self._remove_member(zinfo)

    def _remove_member(self, member):
        # get a sorted filelist by header offset, in case the dir order
        # doesn't match the actual entry order
        fp = self.fp
        entry_offset = 0
        filelist = sorted(self.filelist, key=attrgetter('header_offset'))
        for i in range(len(filelist)):
            info = filelist[i]
            # find the target member
            if info.header_offset < member.header_offset:
                continue

            # get the total size of the entry
            entry_size = None
            if i == len(filelist) - 1:
                entry_size = self.start_dir - info.header_offset
            else:
                entry_size = filelist[i + 1].header_offset - info.header_offset

            # found the member, set the entry offset
            if member == info:
                entry_offset = entry_size
                continue

            # Move entry
            # read the actual entry data
            fp.seek(info.header_offset)
            entry_data = fp.read(entry_size)

            # update the header
            info.header_offset -= entry_offset

            # write the entry to the new position
            fp.seek(info.header_offset)
            fp.write(entry_data)
            fp.flush()

        # update state
        self.start_dir -= entry_offset
        self.filelist.remove(member)
        del self.NameToInfo[member.filename]
        self._didModify = True

        # seek to the start of the central dir
        fp.seek(self.start_dir)

def load_json_config(directory):
    """ Load a wapt config as a dict from the config files found in the supplied directory """
    if not os.path.isdir(directory):
        raise Exception("{} is not a valid directory for wapt config files".format(directory))
    configs_list = []
    files = os.listdir(directory)
    for config_file in files:
        if not config_file.endswith(".json"):
            continue
        with open(os.path.join(directory, config_file), 'r') as f:
            logger.debug('%s Loading config from file %s' % (threading.get_ident(),os.path.join(directory, config_file)))
            try:
                configs_list.append(dict(json.load(f)))
            except:
                logger.warning('Invalid config json file %s' % (config_file))
    ## No config packages
    if not configs_list:
        return None
    result = {}
    ## Sort the configurations based on priority in descending order
    sorted_configs = sorted(configs_list, key=lambda item: item.get('priority',0), reverse=True)
    for config in sorted_configs:
        for section in config:
            if section in ['name','priority','filename','server_certificates','certificates']:
                continue
            if not isinstance(config[section],dict):
                continue
            if not section in result:
                result[section] = {}
            for key in config[section]:
                if not key in result[section]:
                    result[section][key] = config[section][key]
    return result

def save_default_ini_config(config, json_config):
    """ Make a copy of all sections prefixed by "default_" """
    for section in config.sections():
        saved_section = 'default_' + section
        ## Section Already saved, is a saved section or is not override by other config
        if config.has_section(saved_section) or (section.startswith('default_') and config.has_section(section[8:])) or not section in json_config:
            continue
        config.add_section(saved_section)
        for option in config.options(section):
            config.set(saved_section, option, config.get(section, option))
    return config

def add_default_config_sections(config, packages_config):
    for section in config.sections():
        ## If it is a saved section
        base_section = section[8:]
        if section.startswith('default_') and config.has_section(base_section):
            for option in config.options(section):
                ## If the option is already defined by a package (with higher priority)
                if base_section in packages_config and option in packages_config[base_section]:
                    continue
                if not base_section in packages_config:
                    packages_config[base_section] = {}
                packages_config[base_section][option] = config.get(section, option)

def clean_default_sections(config):
    for section in config.sections():
        saved_section = 'default_'+section
        if config.has_section(saved_section):
            for option in config.options(saved_section):
                config.set(section, option, config.get(saved_section, option))
            config.remove_section(saved_section)

def apply_json_config_to_ini_file(ini_filename, json_config, save_default_ini=True):
    if not os.path.isfile(ini_filename):
        raise Exception('{} is not a valid ini filename'.format(ini_filename))
    ## Load the current Config from wapt-get.ini
    changed_config = RawConfigParser()
    with open(ini_filename, 'r', encoding='utf8') as f:
        changed_config.readfp(f)

    if not json_config:
        ## There isn't any config packages, we clean the default sections lefts
        clean_default_sections(changed_config)
    else:
        ## We need to save the initial configuration
        add_default_config_sections(changed_config, json_config)
        if save_default_ini:
            save_default_ini_config(changed_config, json_config)
        ## Merge the wapt-get.ini with the config packages
        for section in json_config:
            if not changed_config.has_section(section):
                changed_config.add_section(section)
            for option in json_config[section]:
                changed_config.set(section, option, str(json_config[section][option]))

    ## If the config changed, we need to rewrite the wapt-get.ini
    default_config = RawConfigParser()
    with open(ini_filename, 'r', encoding='utf8') as f:
        default_config.readfp(f)
    if default_config != changed_config:
        tasks_logger.info("Configuration packages have been updated, rewriting wapt-get.ini")
        with open(ini_filename,'w',encoding='utf8') as inifile:
            changed_config.write(inifile, False)

def update_ini_from_json_config(ini_filename=None, json_config_dir=None):
    """ Update the config of a config file (wapt-get.ini) based on the config packages installed"""
    if not ini_filename:
        wapt_base_dir = os.path.abspath(os.path.dirname(__file__))
        ini_filename = os.path.join(wapt_base_dir, 'wapt-get.ini')
    if json_config_dir and os.path.isdir(json_config_dir):
        json_config = load_json_config(json_config_dir)
    else:
        json_config = None
    apply_json_config_to_ini_file(ini_filename, json_config)

def get_files_timestamp_sha256(files=[]):
    timestamps = {}
    for file in files:
        if not file:
            continue
        if os.path.isfile(file):
            timestamps[file] = str(os.stat(file).st_mtime)
        elif os.path.isdir(file):
            timestamps[file] = str(os.stat(file).st_mtime)
            for subfile in os.listdir(file):
                full_path = os.path.join(file, subfile)
                timestamps[full_path] = str(os.stat(full_path).st_mtime)
        else:
            raise Exception('{} is neither a file neither a directory'.format(file))
    #print('%s timestamps: %s' % (threading.get_ident(),timestamps))
    return hashlib.sha256(jsondump(timestamps).encode('utf8')).hexdigest()

def config_overview(wapt_base_dir,inifile):
    overview = {}
    configs = []
    priorities = {'wapt-get.ini':-1}
    conf_folder = os.path.join(wapt_base_dir, 'conf.d')

    for file in glob.glob(os.path.join(conf_folder, '*.json')):
        try:
            with open(file, 'r') as file_:
                conf = json.loads(file_.read())
                conf["filename"] = os.path.basename(file)
                configs.append(conf)
                priorities[conf["filename"]] = conf['priority']
        except:
            pass
    configs = sorted(configs, key=lambda item: item.get('priority',0), reverse=True)

    for conf in configs:
        for section in conf:
            if section in ['name','priority','filename','server_certificates','certificates']:
                continue
            if not overview.get(section, None):
                overview[section] = {}
                overview[section]["filename"] = []
            overview[section]["filename"].append(conf["filename"])

            for property in conf[section]:
                if not overview[section].get(property, None):
                    overview[section][property] = []
                overview[section][property].append({"value":conf[section][property], "filename":conf["filename"]})

    parser = RawConfigParser()
    with open(inifile, 'r', encoding='utf8') as f:
        parser.readfp(f)
    for section in parser.sections():
        if len(section) > 8:
            base_section_name = section[8:]
        ## Section is not a save
        if not (section.startswith('default_') and section[8:] in parser.sections()):
            ## There is a save of the section, we will only read the save
            if 'default_'+section in parser.sections():
                continue
            base_section_name = section

        if not overview.get(base_section_name, None):
            overview[base_section_name] = {}
            overview[base_section_name]["filename"] = []
        overview[base_section_name]["filename"].append('wapt-get.ini')

        for property in parser.options(section):
            if not overview[base_section_name].get(property, None):
                overview[base_section_name][property] = []
            overview[base_section_name][property].append({"value":parser.get(section, property), "filename":'wapt-get.ini'})
    return {'config':overview, 'priorities':priorities}

def harakiri(exitcode):
    #sys.stdout.flush()
    #sys.stderr.flush()
    if platform.system() == 'Windows':
        handle = win32api.OpenProcess(1, False, win32process.GetCurrentProcessId())
        win32process.TerminateProcess(handle, exitcode)
        win32api.CloseHandle(handle)
    else:
        current_process = psutil.Process()
        current_process.kill()

def get_pid_to_name(pid):
    try:
        return psutil.Process(pid).name()
    except Exception as e:
        return str(e)


def listening_sockets(low_ports=False,include_loc=True, kind='all'):
    return sorted([{'local_port':c.laddr.port, 'local_ip':c.laddr.ip, 'process': get_pid_to_name(c.pid), 'type': c.type.name,'family': c.family.name}  for c in psutil.net_connections(kind=kind) if
                c.family in (socket.AF_INET,socket.AF_INET6) and
                (include_loc or not c.laddr.ip in('127.0.0.1','::1')) and
                c.status=='LISTEN' and
                (not low_ports or c.laddr.port<1024)],key=lambda c: c.get('local_port'))


def is_local_user(username):
    if not username:
        return False
    username = username.lower()
    try:
        if os.name == 'nt':
            for u in win32net.NetUserEnum(None, 2)[0]:
                if u['name'].lower() == username:
                    return True
            return False
        elif sys.platform == "darwin":
            for u in run('dscl . list /Users').splitlines():
                if not u.startswith('_') and u.lower() == username:
                    return True
            return False
        else:
            with open('/etc/passwd') as f:
                for u in [entry.split(':',1) for entry in f.read().splitlines()]:
                    if not u[0]:
                        continue
                    if u[0].lower() == username:
                        return True
            return False
    except Exception as e:
        logger.critical('Error looking for local user %s: %s' % (username,e))
        return False

if sys.platform == 'linux':
    class LinuxImpersonate():
        def __init__(self, user, group = None):
            self.uid = pwd.getpwnam(user).pw_uid
            if not group:
                self.gid = pwd.getpwnam(user).pw_gid
            else:
                self.gid = grp.getgrnam(group).gr_gid

        def __enter__(self):
            self.original_uid = os.getuid()
            self.original_gid = os.getgid()
            os.setegid(self.uid)
            os.seteuid(self.gid)

        def __exit__(self, type, value, traceback):
            os.seteuid(self.original_uid)
            os.setegid(self.original_gid)

if sys.platform=='win32':

    def reg_openkey_noredir(rootkey, subkeypath, sam=winreg.KEY_READ, create_if_missing=False, noredir=True):
        """Open the registry key\subkey with access rights sam

        The Wow6432Node redirector is disabled. So one can access 32 and 64 part or the registry
        even if python is running in 32 bits mode.

        Args:
           rootkey    : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
           subkeypath : string like "software\\microsoft\\windows\\currentversion"
           sam        : a boolean combination of KEY_READ | KEY_WRITE
           create_if_missing : True to create the subkeypath if not exists, access rights will include KEY_WRITE
           noredir (boolean): True by default. disable the redirection to the 32 bits view of registry.

        Returns:
            keyhandle :   a key handle for reg_getvalue and reg_set_value

        >>>

        """
        # for backward compatibility. wapt is 32bits. If we try to access this vurtual node, reenable redirection
        if platform.machine() == 'AMD64' and '\\Wow6432Node\\' in subkeypath:
            subkeypath = subkeypath.replace('\\Wow6432Node\\', '\\')
            noredir = False

        if not(isinstance(subkeypath, str)):
            subkeypath = str(subkeypath)
        try:
            if platform.machine() == 'AMD64' and noredir:
                result = winreg.OpenKey(rootkey, subkeypath, 0, sam | winreg.KEY_WOW64_64KEY)
            else:
                result = winreg.OpenKey(rootkey, subkeypath, 0, sam)
            return result
        except WindowsError as e:
            if e.errno == 2:
                if create_if_missing:
                    if platform.machine() == 'AMD64' and noredir:
                        return winreg.CreateKeyEx(rootkey, subkeypath, 0, sam | winreg.KEY_READ | winreg.KEY_WOW64_64KEY | winreg.KEY_WRITE)
                    else:
                        return winreg.CreateKeyEx(rootkey, subkeypath, 0, sam | winreg.KEY_READ | winreg.KEY_WRITE)
                else:
                    raise WindowsError(e.errno, 'The key %s can not be opened' % subkeypath)

    def reg_enum_subkeys(rootkey):
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(rootkey, i)
                if subkey_name is not None:
                    yield subkey_name
                i += 1
            except WindowsError as e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    break
                else:
                    raise

    def reg_enum_values(rootkey):
        os_encoding = locale.getpreferredencoding()
        i = 0
        while True:
            try:
                (name, value, _type) = winreg.EnumValue(rootkey, i)
                try:
                    name = name.decode(os_encoding)
                except:
                    pass
                if name is not None:
                    if not(isinstance(value, str)):
                        value = str(value)
                    yield (name, value, _type)
                i += 1
            except WindowsError as e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    break
                else:
                    raise

    def reg_key_exists(rootkey, subkeypath):
        """Check if a key exists in registry

        The Wow6432Node redirector is disabled. So one can access 32 and 64 part or the registry
        even if python is running in 32 bits mode.

        Args:
           rootkey     : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
           subkeypath : string like "software\\microsoft\\windows\\currentversion"

        Returns:
            boolean

        >>> if reg_key_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','VideoLAN','VLC')):
        ...     print('VLC key exists')
        ???
        """
        try:
            with reg_openkey_noredir(rootkey, subkeypath):
                return True
        except WindowsError as e:
            if e.errno == 2:
                return False
            else:
                raise


    def reg_value_exists(rootkey, subkeypath, value_name):
        """Check if there is value named value_name in the subkeypath registry key of rootkey

        Args:
            rootkey (int): branch of registry HKEY_LOCAL_MACHINE,HKEY_USERS,HKEY_CURRENT_USER,HKEY_CURRENT_CONFIG
            subkeypath (str): path with back slashes like 'SOFTWARE\\VideoLAN\\VLC'
            value_name (str) : value key like "Version"

        Returns:
            boolean: True if there is a value called value_name in the subkeypath of rootkey

        >>> if reg_value_exists(HKEY_LOCAL_MACHINE,makepath('SOFTWARE','VideoLAN','VLC'),'Version'):
        ...     print('VLC seems to be installed')
        ???
        """
        try:
            with reg_openkey_noredir(rootkey, subkeypath) as key:
                if not(isinstance(value_name, str)):
                    value_name = str(value_name)
                # try getting the value. as a side effect, trigger an exception if not exists
                winreg.QueryValueEx(key, value_name)[0]
                return True

        except WindowsError as e:
            if e.errno in (259, 2):
                return False
            else:
                raise


    def reg_getvalue(key, name, default=None):
        r"""Return the value of specified name inside 'key' folder

        >>> with reg_openkey_noredir(HKEY_LOCAL_MACHINE,'SOFTWARE\\7-Zip') as zkey:
        ...     path = reg_getvalue(zkey,'Path')
        >>> print path
        c:\Program Files\7-Zip\

        Args:
             key  : handle of registry key as returned by reg_openkey_noredir()
             name : value name or None for key default value
             default : value returned if specified name doesn't exist
        Returns:
            int or str or list: depends on type of value named name.
        """
        try:
            if not(isinstance(name, str)):
                name = str(name)
            value = winreg.QueryValueEx(key, name)[0]
            if not(isinstance(value, str)):
                value = str(value)
            return value
        except WindowsError as e:
            if e.errno in (259, 2):
                # WindowsError: [Errno 259] No more data is available
                # WindowsError: [Error 2] Le fichier spécifié est introuvable
                return default
            else:
                raise


    def reg_setvalue(key, name, value, type=winreg.REG_SZ):
        """Set the value of specified name inside 'key' folder

             key  : handle of registry key as returned by reg_openkey_noredir()
             name : value name
             type : type of value (REG_SZ,REG_MULTI_SZ,REG_DWORD,REG_EXPAND_SZ)

        """
        if not(isinstance(name, str)):
            name = str(name)
        if isinstance(value, bytes):
            type=winreg.REG_BINARY
        return winreg.SetValueEx(key, name, 0, type, value)


    def reg_delvalue(key, name):
        """Remove the value of specified name inside 'key' folder
             key  : handle of registry key as returned by reg_openkey_noredir()
             name : value name
        """
        try:
            if not(isinstance(name, str)):
                name = str(name)
            winreg.DeleteValue(key, name)
            return True
        except WindowsError as e:
            # WindowsError: [Errno 2] : file does not exist
            if e.winerror == 2:
                return False
            else:
                raise

    def reg_delete_subkeys(rootkey, key_path):
        """Delete all subkeys of a key

             rootkey  : HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER ...
             key_path : string like "software\\microsoft\\windows\\currentversion"
        """
        with reg_openkey_noredir(rootkey, key_path, winreg.KEY_ALL_ACCESS) as key:
            infokey = winreg.QueryInfoKey(key)
            for _i in range(0, infokey[0]):
                # Since we are deleting subkeys we cannot iterate with reg_enum_subkeys because the count change during the iteration
                subkey_name = winreg.EnumKey(key, 0)
                reg_delete_subkeys(rootkey, key_path + '\\' + subkey_name)
                winreg.DeleteKey(key, subkey_name)

    def reg_closekey(hkey):
        """Close a registry key opened with reg_openkey_noredir

        """
        winreg.CloseKey(hkey)


    def get_user_from_sid(sid):
        """Returns user for the given sid
        sid is either a string or a PySID
        """
        if not sid:
            return None
        try:
            if isinstance(sid, pywintypes.SIDType):
                pysid = sid
            else:
                if not(isinstance(sid, str)):
                    sid = str(sid)
                pysid = win32security.ConvertStringSidToSid(sid)
            name, domain, type = win32security.LookupAccountSid(None, pysid)
            return name
        except Exception as e:
            logger.debug('Unable to get user from SID %s: %s' % (sid,e))
            return None

    def get_profile_path(sid):
        """Return the filesystem path to profile of user with SID sid"""
        prof_key = reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE,  r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\%s' % sid)
        (profile_image_path,atype) = winreg.QueryValueEx(prof_key,'ProfileImagePath')
        return os.path.expandvars(profile_image_path)


    def replace_at_next_reboot(tmp_filename, target_filename):
        r"""Schedule a file rename at next reboot using standard Windows PendingFileRenameOperations
        Creates a key in HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager with content :
                PendingFileRenameOperations
                    Data type : REG_MULTI_SZ Value
                    data: \??\c:\temp\win32k.sys !\??\c:\winnt\system32\win32k.s

        Args:
            tmp_filename (str):  Temporary path to file to rename (defaults to <target_filename>.pending)
            target_filename (str): Final target filename
        """
        if not tmp_filename:
            tmp_filename = target_filename+'.pending'

        with reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager', sam=winreg.KEY_WRITE | winreg.KEY_READ) as key:
            pending = reg_getvalue(key, 'PendingFileRenameOperations', default=[])
            tmp = '\??\{}'.format(tmp_filename)
            target = '!\??\{}'.format(target_filename)
            if not tmp in pending:
                pending.extend([tmp, target])
                reg_setvalue(key, 'PendingFileRenameOperations', pending, type=winreg.REG_MULTI_SZ)


    def delete_at_next_reboot(target_filename):
        r"""delete at next reboot using standard Windows PendingFileRenameOperations
        Creates a key in HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager with content :
                PendingFileRenameOperations
                    Data type : REG_MULTI_SZ Value
                    data: [\??\path,\0]

        Args:
            target_filename (str): File to delete
        """
        with reg_openkey_noredir(winreg.HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager', sam=winreg.KEY_WRITE | winreg.KEY_READ) as key:
            pending = reg_getvalue(key, 'PendingFileRenameOperations', default=[])
            target = '\??\{}'.format(target_filename)
            if not target in pending:
                pending.extend([target, '\0'])
                reg_setvalue(key, 'PendingFileRenameOperations', pending, type=winreg.REG_MULTI_SZ)


def user_config_directory(username):
    if not username:
        return ''
    result = ''
    if is_unsafe_filename(username):
        raise Exception('unsafe username %s' % username)
    if os.path.sep in username:
        raise Exception('unsafe username %s' % username)

    if sys.platform == 'win32':
        profiles_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        for profsid in reg_enum_subkeys(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profiles_path)):
            if profsid.startswith('S-'):
                if username.startswith('S-') and profsid == username:
                    result = get_profile_path(profsid)
                    if result:
                        break

                user = get_user_from_sid(profsid)
                if user and user.lower() == username.lower():
                    result = get_profile_path(profsid)
                    if result:
                        break
        if os.path.isdir(result):
            return result
        else:
            # fallback for old windows
            return os.path.join(os.path.expanduser("~%s" % username),'.config')
    elif sys.platform == "darwin":
        return os.path.expanduser("~%s/Library/Application Support" % username)
    elif sys.platform == 'linux':
        home = pwd.getpwnam(username).pw_dir
        if home and os.path.isdir(home):
            return os.path.join(home,'.config')

    return result

def user_is_local_admin(username):
    username = username.lower()
    try:
        if sys.platform == 'win32':
            for g in win32net.NetUserEnum(None, 2)[0]:
                if g['name'].lower() == username and g['priv'] == win32netcon.USER_PRIV_ADMIN:
                    return True
            return False
        else: # TODO linux and darwin with sudo
            if username == 'root':
                return True
            for group in ['root','sudo','wheel']:
                if user_is_member_of(username,group):
                    return True
        return False
    except:
        return False

def user_is_member_of(username,groupname):
    if not username or not groupname:
        return False
    username = username.lower()
    if sys.platform == 'win32':
        try:
            for item in win32net.NetLocalGroupGetMembers(None, groupname, 3)[0]:
                if '\\' in item['domainandname']:
                    domain,user = item['domainandname'].split('\\')
                else:
                    user = item['domainandname']
                if user.lower() == username:
                    return True
        except:
            pass
        return False
    elif sys.platform == 'linux':
        try:
            return username in grp.getgrnam(groupname).gr_mem
        except:
            return False
    else: # TODO darwin ?
        return False

def default_skip(src, dst):
    return False

def default_overwrite(src, dst):
    return True


def default_oncopy(msg, src, dst):
    logger.debug('%s : "%s" to "%s"' % (ensure_unicode(msg), ensure_unicode(src), ensure_unicode(dst)))
    return True



def default_overwrite_older(src, dst):
    if os.stat(src, follow_symlinks=False).st_mtime <= os.stat(dst, follow_symlinks=False).st_mtime:
        logger.debug('Skipping, file on target is newer than source: "%s"' % (dst,))
        return False
    else:
        logger.debug('Overwriting file on target is older than source: "%s"' % (dst,))
        return True


def copytree2(src: str, dst: str,
              ignore: Callable[[str, str], List[str]] = None,
              onreplace: Callable[[str, str], bool] = default_skip,
              oncopy: Callable[[str, str, str], bool] = default_oncopy,
              enable_replace_at_reboot: bool = True,
              follow_symlinks: bool = False):
    r"""Copy src directory to dst directory. dst is created if it doesn't exists
    src can be relative to installation temporary dir

    oncopy is called for each file copy. if False is returned, copy is skipped
    onreplace is called when a file will be overwritten.

    Args:
        src (str): path to source directory (absolute path or relative to package extraction tempdir)
        dst (str): path to target directory (created if not present)
        ignore (func) : callback func(root_dir,filenames) which returns names to ignore
        onreplace (func) : callback func(src,dst):boolean called when a file will be replaced to decide what to do.
                        default is to not replace if target exists. can be default_overwrite or default_overwrite_older or
                        custom function.
        oncopy (func) : callback func(msg,src,dst) called when a file is copied.
                        default is to log in debug level the operation
        enable_replace_at_reboot (boolean): if True, files which are locked will be scheduled for replace at next reboot

    Returns:

    Raises:

    >>> copytree2(r'c:\tranquilit\wapt\tests',r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    True
    >>> remove_tree(r'c:\tranquilit\wapt\tests2')
    >>> isdir(r'c:\tranquilit\wapt\tests2')
    False
    """
    logger.debug('Copy tree from "%s" to "%s"' % (ensure_unicode(src), ensure_unicode(dst)))

    if not src or not os.path.isdir(src):
        raise Exception("Invalid source directory for copytree2")

    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    if not os.path.isdir(dst):
        if oncopy('create directory', src, dst):
            os.makedirs(dst)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if os.path.islink(srcname) and not follow_symlinks:
                need_overwrite = os.path.islink(dstname)
                if (not need_overwrite or onreplace(srcname, dstname)) and oncopy('link', srcname, dstname):
                    if need_overwrite:
                        os.unlink(dstname)
                    shutil.copy2(srcname, dstname, follow_symlinks=False)
            elif os.path.isdir(srcname):
                if oncopy('directory', srcname, dstname):
                    copytree2(srcname, dstname, ignore=ignore, onreplace=onreplace, oncopy=oncopy, enable_replace_at_reboot=enable_replace_at_reboot, follow_symlinks=follow_symlinks)
            else:
                try:
                    need_overwrite = os.path.isfile(dstname)
                    if (not need_overwrite or onreplace(srcname, dstname)) and oncopy('overwrites', srcname, dstname):
                        if need_overwrite:
                            os.unlink(dstname)
                        shutil.copy2(srcname, dstname, follow_symlinks=follow_symlinks)
                except (IOError, os.error) as e:
                    # file is locked...
                    if enable_replace_at_reboot and e.errno in (5, 13):
                        shutil.copy2(srcname, dstname+'.pending',follow_symlinks=follow_symlinks)
                        replace_at_next_reboot(tmp_filename=dstname+'.pending', target_filename=dstname)
                    else:
                        raise

        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except shutil.Error as err:
            # errors.extend(err.args[0])
            errors.append(err)
        except (IOError, os.error) as why:
            logger.critical('Error copying from "%s" to "%s" : %s' % (ensure_unicode(src), ensure_unicode(dst), ensure_unicode(why)))
            errors.append((srcname, dstname, str(why)))

    try:
        if os.path.isdir(dst):
            shutil.copystat(src, dst)
    except WindowsError:
        # can't copy file access times on Windows
        pass
    except OSError as why:
        errors.extend((src, dst, str(why)))
    if errors:
        raise shutil.Error(errors)

def fixed_columns_to_dicts(txt: str, stop_when_empty_row: bool = True):
    """Decode fixed width text table with header into a list of dict
    The first line is the header and defines the key, start and width of each column

    Args:
        txt (str): multiline text

    Returns:
        list of dicts
    """
    lines = txt.splitlines()
    header = lines[0]
    fields = [] # key,start,end)
    current_key=''
    start_pos=None
    i = 0

    # decode header
    while i <len(header):
        while i <len(header) and header[i] in (' ','\n','\t'):
            i += 1
        start_pos=i
        while i <len(header) and not header[i] in (' ','\n','\t'):
            current_key += header[i]
            i += 1
        while i <len(header) and header[i] in (' ','\n','\t'):
            i += 1
        if current_key:
            if i>=len(header):
                fields.append((current_key,start_pos,None)) # end of line
            else:
                fields.append((current_key,start_pos,i-1)) # 1 space between columns
        current_key=''

    # read records
    result = []
    for line in lines[1:]:
        # stop at first emty line, to skip trailers data
        if not line.strip():
            if stop_when_empty_row:
                break
            else:
                continue
        rec = {}
        for k,start,end in fields:
            rec[k] = line[start:end].strip()
        result.append(rec)
    return result


if __name__ == '__main__':
    sys.exit(0)
