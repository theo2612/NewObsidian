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
from waptutils import import_setup, format_bytes, wget, wgets, merge_dict, remove_encoding_declaration
from waptutils import httpdatetime2isodate, datetime2isodate, CustomZipFile, FileChunks, jsondump, LogOutput, isodate2datetime
from waptpackage import REGEX_PACKAGE_CONDITION, WaptLocalRepo, WaptRemoteRepo, PackageEntry, PackageRequest, HostCapabilities, PackageKey, PackageVersion
from waptcrypto import SSLCABundle, SSLCertificate, SSLPrivateKey, SSLCRL, SSLVerifyException, SSLPKCS12
from waptutils import BaseObjectClass, ensure_list, ensure_unicode, default_http_headers, get_time_delta
from waptpackage import EWaptException, EWaptMissingLocalWaptFile, EWaptNotAPackage, EWaptNotSigned, EWaptBadPackageAttribute,EWaptBadSetup
from waptcrypto import get_peer_cert_chain_from_server, get_cert_chain_as_pem
from waptpackage import EWaptNeedsNewerAgent, EWaptDiskSpace
from waptcrypto import EWaptMissingPrivateKey, EWaptMissingCertificate, get_cert_chain_from_pem
from waptutils import isrunning, killalltasks, killtree, run
from waptutils import get_requests_client_cert_session, get_main_ip, update_ini_from_json_config, get_files_timestamp_sha256, hexdigest_for_data, sha256_for_data
from waptpackage import EWaptDownloadError, EWaptMissingPackageHook
from waptpackage import EWaptUnavailablePackage, EWaptConflictingPackage
import netifaces
import setuphelpers
from itsdangerous import URLSafeTimedSerializer
from waptpackage import make_valid_package_name,DEFAULT_EXCLUDED_PATHS_FOR_BUILD
from waptutils import is_pem_key_encrypted
from waptutils import _disable_file_system_redirection
from waptutils import Timeit, config_overview
from waptutils import get_verify_cert
from waptutils import __version__
from waptutils import __file__ as waptutils__file__
import os
import re
import logging
import datetime
import time
import sys
import tempfile
import hashlib
import glob
import codecs
import base64
import zlib
import sqlite3
import json
import ujson
import io
import requests
import pickle

try:
    # pylint: disable=no-member
    # no error
    import requests.packages.urllib3
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

import fnmatch
import ipaddress
import subprocess
import platform
import socket
import getpass
import psutil
import threading
import traceback
import uuid
import gc
import random
import string
from iniparse import RawConfigParser
from optparse import OptionParser

from operator import itemgetter
from collections import OrderedDict
from collections import defaultdict

import shutil
import urllib.parse
import zipfile
import ldap3

import arpy
import rpmfile
import tarfile

import imp

logger = logging.getLogger('waptcore')
tasks_logger = logging.getLogger('wapttasks')

bad_uuid= ['90218F6F-8B87-8442-8AAD-4A676F39B1F3','FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF','00000000-0000-0000-0000-000000000000','Not Settable','03000200-0400-0500-0006-000700080009']

# conditionnal imports for windows or linux
if sys.platform == 'win32':
    import win32api
    import win32security
    import win32net
    import pywintypes
    import pythoncom
    from ntsecuritycon import DOMAIN_GROUP_RID_ADMINS
    import winreg
    from winreg import HKEY_LOCAL_MACHINE, EnumKey

old_argv = sys.argv
try:
    import waptlicences
    logger.debug('waptlicences module location: %s' % waptlicences.__file__)
except Exception as e:
    logger.debug('Unable to load waptlicences module: %s' % e)
    waptlicences = None
assert sys.argv == old_argv

if sys.platform == 'win32':
    from waptwua.client import WaptWUA

try:
    import requests_kerberos
    has_kerberos = True
except:
    has_kerberos = False

if not sys.platform == 'win32':
    import kerberos
else:
    import winkerberos as kerberos


class EWaptBadServerAuthentication(EWaptException):
    pass


def is_system_user():
    return setuphelpers.get_current_user().lower() == 'system'


def host_ipv4():
    """return a list of (iface,mac,{addr,broadcast,netmask})"""
    ifaces = netifaces.interfaces()
    res = []
    for i in ifaces:
        params = netifaces.ifaddresses(i)
        if netifaces.AF_LINK in params and params[netifaces.AF_LINK][0]['addr'] and not params[netifaces.AF_LINK][0]['addr'].startswith('00:00:00'):
            iface = {'iface': i, 'mac': params[netifaces.AF_LINK][0]['addr']}
            if netifaces.AF_INET in params:
                iface.update(params[netifaces.AF_INET][0])
            res.append(iface)
    return res


def tryurl(url, proxies=None, timeout=5.0, auth=None, verify_cert=False, cert=None):
    # try to get header for the supplied URL, returns None if no answer within the specified timeout
    # else return time to get he answer.
    with get_requests_client_cert_session(url=url, cert=cert, verify=verify_cert, proxies=proxies) as session:
        try:
            logger.debug('  trying %s' % url)
            starttime = time.time()
            headers = session.head(url=url,
                                   timeout=timeout,
                                   auth=auth,
                                   allow_redirects=True)
            if headers.ok:
                logger.debug('  OK')
                return time.time() - starttime
            else:
                headers.raise_for_status()
        except Exception as e:
            logger.debug('  Not available : %s' % e)
            return None


class EWaptCancelled(Exception):
    pass


class WaptBaseDB(BaseObjectClass):
    curr_db_version = None

    def __init__(self, dbpath):
        self._dbpath = ''
        self._db= None
        self.transaction_depth = 0
        self._db_version = None
        self.dbpath = dbpath
        self.threadid = None

    @property
    def dbpath(self):
        return self._dbpath

    @dbpath.setter
    def dbpath(self, value):
        if not self._dbpath or (self._dbpath and self._dbpath != value):
            self._dbpath = value
            self._db= None

    def begin(self):
        # recreate a connection if not in same thread (reuse of object...)
        if self.transaction_depth == 0:
            logger.debug('DB Start transaction')
            self.execute('begin')
        self.transaction_depth += 1

    def commit(self):
        if self.transaction_depth > 0:
            self.transaction_depth -= 1
        else:
            msg = 'Unexpected commit of an already committed transaction...'
            logger.critical(msg)
            if logger.level == logging.DEBUG:
                raise Exception(msg)
        if self.transaction_depth == 0:
            logger.debug('DB commit')
            try:
                self.execute('commit')
            except:
                self.execute('rollback')
                raise

    def rollback(self):
        if self.transaction_depth > 0:
            self.transaction_depth -= 1
        if self.transaction_depth == 0:
            logger.debug('DB rollback')
            self.execute('rollback')

    @property
    def db(self):
        if self.threadid and self.threadid != threading.current_thread().ident and self._db:
            self._db = None
        if self._db is None:
            if not self.dbpath:
                raise EWaptException('dbpath not set. Unable to access core waptdb.sqlite database.')
            logger.debug('Thread %s is connecting to wapt db' % threading.current_thread().ident)
            self.threadid = threading.current_thread().ident
            if not self.dbpath == ':memory:' and not os.path.isfile(self.dbpath):
                dirname = os.path.dirname(self.dbpath)
                if os.path.isdir(dirname) == False:
                    os.makedirs(dirname)
                os.path.dirname(self.dbpath)
                self._db = sqlite3.connect(self.dbpath, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
                self._db.isolation_level = None
                self.transaction_depth = 0
                self.create_db_structure()
                self.init_db_data()
            elif self.dbpath == ':memory:':
                self._db = sqlite3.connect(self.dbpath, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
                self._db.isolation_level = None
                self.transaction_depth = 0
                self.create_db_structure()
                self.init_db_data()
            else:
                self._db = sqlite3.connect(self.dbpath, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
                self._db.isolation_level = None
                self.transaction_depth = 0
                if self.curr_db_version != self.db_version:
                    self.upgradedb()
                    self.init_db_data()
        return self._db

    def __enter__(self):
        self.start_timestamp = time.time()
        self.begin()
        #logger.debug(u'DB enter %i' % self.transaction_depth)
        return self

    def __exit__(self, type, value, tb):
        if time.time()-self.start_timestamp > 1.0:
            logger.debug('Transaction took too much time : %s' % (time.time()-self.start_timestamp,))
        if not value:
            #logger.debug(u'DB exit %i' % self.transaction_depth)
            self.commit()
        else:
            self.rollback()
            logger.debug('Error at DB exit %s, rollbacking\n%s' % (value, ensure_unicode(traceback.format_tb(tb))))

    @property
    def db_version(self):
        if not self._db_version:
            val = self.execute('select value from wapt_params where name="db_version"').fetchone()
            if val:
                self._db_version = val[0]
            else:
                raise Exception('Unknown DB Version')
        return self._db_version

    @db_version.setter
    def db_version(self, value):
        with self:
            self.execute('insert or replace into wapt_params(name,value,create_date) values (?,?,?)', ('db_version', value, datetime2isodate()))
            self._db_version = value

    @db_version.deleter
    def db_version(self):
        with self:
            self.execute("delete from wapt_params where name = 'db_version'")
            self._db_version = None

    def create_db_structure(self):
        return self._db_version

    def set_package_attribute(self, install_id, key, value):
        """Store permanently a (key/value) pair in database for a given package, replace existing one"""
        with self:
            self.execute('insert or replace into wapt_package_attributes(install_id,key,value,create_date) values (?,?,?,?)', (install_id, key, value, datetime2isodate()))

    def set_param(self, name, value, ptype=None):
        """Store permanently a (name/value) pair in database, replace existing one"""
        with self:
            if not value is None:
                if ptype is None:
                    if isinstance(value, str):
                        ptype = 'str'
                    if isinstance(value, bytes):
                        ptype = 'bytes'
                    # bool before int !
                    elif isinstance(value, bool):
                        ptype = 'bool'
                    elif isinstance(value, int):
                        ptype = 'int'
                    elif isinstance(value, float):
                        ptype = 'float'
                    elif isinstance(value, datetime.datetime):
                        ptype = 'datetime'
                    else:
                        ptype = 'json'

                if ptype in ('int', 'float'):
                    value = str(value)
                elif ptype in ('json', 'bool'):
                    value = jsondump(value)
                elif ptype == 'datetime':
                    value = datetime2isodate(value)
                elif ptype == 'bytes':
                    value = sqlite3.Binary(value)
            self.execute('insert or replace into wapt_params(name,value,create_date,ptype) values (?,?,?,?)', (name, value, datetime2isodate(), ptype))

    def get_param(self, name, default=None, ptype=None):
        """Retrieve the value associated with name from database"""
        q = self.execute('select value,ptype from wapt_params where name=? order by create_date desc limit 1', (name,)).fetchone()
        if q:
            (value, sptype) = q
            if ptype is None:
                ptype = sptype
            if not value is None:
                if ptype == 'int':
                    value = int(value)
                elif ptype == 'float':
                    value = float(value)
                elif ptype in ('json', 'bool'):
                    value = ujson.loads(value)
                elif ptype == 'datetime':
                    value = isodate2datetime(value)
            return value
        else:
            return default

    def delete_param(self, name):
        with self:
            row = self.execute('select value from wapt_params where name=? limit 1', (name,)).fetchone()
            if row:
                self.execute('delete from wapt_params where name=?', (name,))

    def query(self, query, args=(), one=False, as_dict=True):
        """
        execute la requete query sur la db et renvoie un tableau de dictionnaires
        """
        cur = self.execute(query, args)
        if as_dict:
            rv = [dict((cur.description[idx][0], value)
                       for idx, value in enumerate(row)) for row in cur.fetchall()]
        else:
            rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv

    def execute(self, query, args=()):
        """
        Wrapper around sqlite.execute.
        """
        nb_tries = 0
        nb_max_tries = 3
        seconds_before_retry = 2

        while nb_tries < nb_max_tries:
            try:
                return self.db.execute(query, args)
            except sqlite3.OperationalError as e:
                if 'database is locked' in repr(e):
                    nb_tries += 1
                    if nb_tries >= nb_max_tries:
                        raise Exception("The database is locked. There is probably another WAPT process currently running (WaptAgent, WaptSelfService, wapt-get, waptpython.exe). Please check running processes. Error: %s" % (repr(e),))
                    else:
                        time.sleep(seconds_before_retry)
                else:
                    raise

    def init_db_data(self):
        pass

    def upgradedb(self, force=False):
        """Update local database structure to current version if rules are described in db_upgrades

        Args:
            force (bool): force upgrade even if structure version is greater than requested.

        Returns:
            tuple: (old_structure_version,new_structure_version)

        """
        with self:
            try:
                backupfn = ''
                # use cached value to avoid infinite loop
                old_structure_version = self._db_version
                if old_structure_version >= self.curr_db_version and not force:
                    logger.warning('upgrade db aborted : current structure version %s is newer or equal to requested structure version %s' % (old_structure_version, self.curr_db_version))
                    return (old_structure_version, old_structure_version)

                logger.info('Upgrade database schema')
                if self.dbpath != ':memory:':
                    # we will backup old data in a file so that we can rollback
                    backupfn = tempfile.mktemp('.sqlite')
                    logger.debug(' copy old data to %s' % backupfn)
                    shutil.copy(self.dbpath, backupfn)
                else:
                    backupfn = None

                # we will backup old data in dictionaries to convert them to new structure
                logger.debug(' backup data in memory')
                old_datas = {}
                tables = [c[0] for c in self.execute('SELECT name FROM sqlite_master WHERE type = "table" and name like "wapt_%"').fetchall()]
                for tablename in tables:
                    old_datas[tablename] = self.query('select * from %s' % tablename)
                    logger.debug(' %s table : %i records' % (tablename, len(old_datas[tablename])))

                logger.debug(' drop tables')
                for tablename in tables:
                    self.execute('drop table if exists %s' % tablename)

                # create new empty structure
                logger.debug(' recreates new tables ')
                new_structure_version = self.create_db_structure()
                del(self.db_version)
                # append old data in new tables
                logger.debug(' fill with old data')
                for tablename in tables:
                    if old_datas[tablename]:
                        logger.debug(' process table %s' % tablename)
                        allnewcolumns = [c[0] for c in self.execute('select * from %s limit 0' % tablename).description]
                        # take only old columns which match a new column in new structure
                        oldcolumns = [k for k in old_datas[tablename][0] if k in allnewcolumns]

                        insquery = "insert into %s (%s) values (%s)" % (tablename, ",".join(oldcolumns), ",".join("?" * len(oldcolumns)))
                        for rec in old_datas[tablename]:
                            logger.debug(' %s' % [rec[oldcolumns[i]] for i in range(0, len(oldcolumns))])
                            self.execute(insquery, [rec[oldcolumns[i]] for i in range(0, len(oldcolumns))])

                # be sure to put back new version in table as db upgrade has put the old value in table
                self.db_version = new_structure_version
                return (old_structure_version, new_structure_version)
            except Exception as e:
                if backupfn:
                    logger.critical("UpgradeDB ERROR : %s, copy back backup database %s" % (e, backupfn))
                    shutil.copy(backupfn, self.dbpath)
                raise


class WaptSessionDB(WaptBaseDB):
    curr_db_version = '20201217'

    def __init__(self, username=''):
        super(WaptSessionDB, self).__init__(None)
        if not username:
            username = setuphelpers.get_current_user()
        self.username = username
        self.dbpath = os.path.join(setuphelpers.application_data(), 'wapt', 'waptsession.sqlite')

    def create_db_structure(self):
        """Initialize current sqlite db with empty table and return structure version"""
        assert(isinstance(self.db, sqlite3.Connection))
        logger.debug('Initialize Wapt session database')

        self.execute("""
        create table if not exists wapt_sessionsetup (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username varchar,
          package_uuid varchar,
          package varchar,
          version varchar,
          architecture varchar,
          install_date varchar,
          install_status varchar,
          install_output TEXT,
          process_id integer
          )"""
                        )
        self.execute("""
            create index if not exists idx_sessionsetup_username on wapt_sessionsetup(username,package);""")

        self.execute("""
            create index if not exists idx_sessionsetup_package on wapt_sessionsetup(package);""")

        self.execute("""
            create index if not exists idx_sessionsetup_package_uuid on wapt_sessionsetup(package_uuid);""")

        self.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar,
          value text,
          ptype varchar,
          create_date varchar
          ) """)

        self.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)

        self.db_version = self.curr_db_version
        return self.curr_db_version

    def add_start_install(self, package_entry):
        """Register the start of installation in local db

        Returns:
            int : rowid of the inserted record
        """
        with self:
            cur = self.execute("""delete from wapt_sessionsetup where package=?""", (package_entry.package,))
            cur = self.execute("""\
                  insert into wapt_sessionsetup (
                    username,
                    package_uuid,
                    package,
                    version,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    process_id
                    ) values (?,?,?,?,?,?,?,?,?)
                """, (
                self.username,
                package_entry.package_uuid,
                package_entry.package,
                package_entry.version,
                package_entry.architecture,
                datetime2isodate(),
                'INIT',
                '',
                os.getpid()
            ))
            return cur.lastrowid

    def update_install_status(self, rowid, set_status=None, append_line=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK', 'WARNING', 'ERROR'):
                pid = None
            else:
                pid = os.getpid()
            cur = self.execute("""\
                  update wapt_sessionsetup
                    set install_status=coalesce(?,install_status),install_output = coalesce(install_output,'') || ?,process_id=?
                    where rowid = ?
                """, (
                set_status,
                ensure_unicode(append_line)+'\n' if append_line is not None else '',
                pid,
                rowid,
            )
            )
            return cur.lastrowid

    def update_install_status_pid(self, pid, set_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.execute("""\
                  update wapt_sessionsetup
                    set install_status=coalesce(?,install_status) where process_id = ?
                """, (
                set_status,
                pid,
            )
            )
            return cur.lastrowid

    def remove_install_status(self, package):
        """Remove status of package installation from localdb

        >>> wapt = Wapt()
        >>> wapt.forget_packages('tis-7zip')
        ???
        """
        with self:
            cur = self.execute("""delete from wapt_sessionsetup where package=?""", (package,))
            return cur.rowcount

    def remove_obsolete_install_status(self, installed_packages):
        """Remove local user status of packages no more installed"""
        with self:
            cur = self.execute("""delete from wapt_sessionsetup where package not in (%s)""" %
                                  ','.join('?' for i in installed_packages), installed_packages)
            return cur.rowcount

    def is_installed(self, package, version):
        p = self.query('select * from  wapt_sessionsetup where package=? and version=? and install_status="OK"', (package, version))
        if p:
            return p[0]
        else:
            return None


class WaptDB(WaptBaseDB):
    """Class to manage SQLite database with local installation status"""

    curr_db_version = '20230601'
    wapt_package_columns = OrderedDict({
                    'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
                    'package_uuid': 'varchar',
                    'package': 'varchar',
                    'categories': 'varchar',
                    'version' : 'varchar',
                    'architecture': 'varchar',
                    'section': 'varchar',
                    'priority': 'varchar',
                    'maintainer': 'varchar',
                    'description': 'varchar',
                    'filename': 'varchar',
                    'size': 'integer',
                    'md5sum': 'varchar',
                    'depends': 'varchar',
                    'conflicts': 'varchar',
                    'sources': 'varchar',
                    'repo_url': 'varchar',
                    'repo': 'varchar',
                    'signer': 'varchar',
                    'signer_fingerprint': 'varchar',
                    'signature': 'varchar',
                    'signature_date': 'varchar',
                    'signed_attributes': 'varchar',
                    'min_wapt_version': 'varchar',
                    'maturity': 'varchar',
                    'locale': 'varchar',
                    'installed_size': 'integer',
                    'target_os': 'varchar',
                    'max_os_version': 'varchar',
                    'min_os_version': 'varchar',
                    'impacted_process': 'varchar',
                    'audit_schedule': 'varchar',
                    'name': 'varchar',
                    'editor': 'varchar',
                    'keywords': 'varchar',
                    'licence': 'varchar',
                    'homepage': 'varchar',
                    'changelog': 'varchar',
                    'valid_from': 'varchar',
                    'valid_until': 'varchar',
                    'forced_install_on': 'varchar',
                    'icon_sha256sum': 'varchar',
                    })

    def create_db_structure(self):
        """Initialize current sqlite db with empty table and return structure version"""
        assert(isinstance(self.db, sqlite3.Connection))
        logger.debug('Initialize Wapt database')

        query_cols = [col_name + ' ' + col_type for col_name, col_type in self.wapt_package_columns.items()]
        query_cols = ','.join(query_cols)
        init_wapt_package_table_query = 'create table if not exists wapt_package ({})'.format(query_cols)

        self.execute(init_wapt_package_table_query)

        self.execute("""
        create index if not exists idx_package_name on wapt_package(package);""")
        self.execute("""
        create index if not exists idx_package_uuid on wapt_package(package_uuid);""")

        self.execute("""
        create table if not exists wapt_localstatus (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          package_uuid varchar,
          package varchar,
          version varchar,
          version_pinning varchar,
          explicit_by varchar,
          architecture varchar,
          section varchar,
          priority varchar,
          maturity varchar,
          locale varchar,
          install_date varchar,
          install_status varchar,
          install_output TEXT,
          install_params VARCHAR,
          uninstall_key varchar,
          setuppy TEXT,
          process_id integer,
          depends varchar,
          conflicts varchar,
          last_audit_on varchar,
          last_audit_status varchar,
          last_audit_output TEXT,
          next_audit_on varchar,
          impacted_process varchar,
          audit_schedule varchar,
          persistent_dir varchar,
          status_revision integer
          )
          """)

        # in a separate table :
        # upgrade_action -> 'INSTALL, UPGRADE, REMOVE'
        # related_package_uuid  -> package which will replace
        # upgrade_planned_on
        # upgrade_deadline
        # upgrade_allowed_schedules
        # retry_count
        # max_retry_count

        self.execute("""
        create index if not exists idx_localstatus_name on wapt_localstatus(package);
        """)
        self.execute("""
        create index if not exists idx_localstatus_status on wapt_localstatus(install_status);
        """)
        self.execute("""
        create index if not exists idx_localstatus_next_audit_on on wapt_localstatus(next_audit_on);
        """)
        self.execute("""
        create index if not exists idx_localstatus_package_uuid on wapt_localstatus(package_uuid);
        """)

        self.execute("""
        create table if not exists wapt_params (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name  varchar,
          value text,
          ptype varchar,
          create_date varchar
          ) """)

        self.execute("""
          create unique index if not exists idx_params_name on wapt_params(name);
          """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_ins_status
            AFTER INSERT ON wapt_params
            WHEN NEW.name not in ('status_revision','last_update_server_hashes')
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_upd_status
            AFTER UPDATE ON wapt_params
            WHEN NEW.name <> 'status_revision'
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS inc_rev_del_status
            AFTER DELETE ON wapt_params
            WHEN OLD.name <> 'status_revision'
            BEGIN
                update wapt_params set value=cast(value as integer)+1
                where name='status_revision';
            END
            """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS wapt_localstatus_ai
            AFTER INSERT ON wapt_localstatus
            BEGIN
                update wapt_localstatus set status_revision=(select cast(value as integer) from wapt_params where name='status_revision') WHERE id = NEW.id;
            END
            """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS wapt_localstatus_au
            AFTER UPDATE ON wapt_localstatus
            BEGIN
                update wapt_localstatus set status_revision=(select cast(value as integer) from wapt_params where name='status_revision') WHERE id = NEW.id;
            END
            """)

        self.execute("""CREATE TRIGGER IF NOT EXISTS wapt_localstatus_au
            AFTER DELETE ON wapt_localstatus
            BEGIN
                update wapt_localstatus set status_revision=(select cast(value as integer) from wapt_params where name='status_revision') WHERE id = NEW.id;
            END
            """)


        # action : install, remove, check, session_setup, update, upgrade
        # state : draft, planned, postponed, running, done, error, canceled
        self.execute("""
            CREATE TABLE if not exists wapt_task (
                id integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                action varchar,
                state varchar,
                current_step varchar,
                process_id integer,
                start_date varchar,
                finish_date varchar,
                package_name varchar,
                username varchar,
                package_version_min varchar,
                package_version_max varchar,
                rundate_min varchar,
                rundate_max varchar,
                rundate_nexttry varchar,
                runduration_max integer,
                created_date varchar,
                run_params VARCHAR,
                run_output TEXT
            );
                """)

        self.execute("""
          create index if not exists idx_task_state on wapt_task(state);
          """)

        self.execute("""
          create index if not exists idx_task_package_name on wapt_task(package_name);
          """)

        self.execute("""
        create table if not exists wapt_sessionsetup (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username varchar,
          package varchar,
          version varchar,
          architecture varchar,
          maturity varchar,
          locale varchar,
          install_date varchar,
          install_status varchar,
          install_output TEXT
          )"""
                        )
        self.execute("""
        create index idx_sessionsetup_username on wapt_sessionsetup(username,package);""")

        # store metrics
        # they are uploaded to server
        self.execute("""
        create table if not exists wapt_audit_data (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          value_date varchar,
          value_section varchar,
          value_key varchar,
          value_type varchar,
          value text,
          expiration_date varchar
          ) """)

        self.execute("""
        create unique index idx_wapt_audit_data_key on wapt_audit_data(value_section,value_key,value_date);
        """)
        self.execute("""
        create index idx_wapt_audit_data_date on wapt_audit_data(value_date);
        """)
        self.execute("""
        create index idx_wapt_audit_data_exp on wapt_audit_data(expiration_date);
        """)

        self.db_version = self.curr_db_version
        return self.curr_db_version

    def init_db_data(self):
        if self.get_param('status_revision') is None:
            self.set_param('status_revision',0)

    def _get_insert_package_query(self):
        if not hasattr(self,'_insert_package_query'):
            pkg_col_names = [col_name for col_name in self.wapt_package_columns]
            pkg_col_names.remove('id')
            pkg_col_names_str = ','.join(pkg_col_names)
            self._insert_package_query = 'insert into wapt_package ({})'.format(pkg_col_names_str)
            fields_nbr = len(pkg_col_names)
            self._insert_package_query += ' values ({})'.format(','.join(['?'] * fields_nbr))

        return self._insert_package_query


    def add_package_entry(self, package_entry, locale_code=None):
        """Add a package into the database
        """
        with self:
            # for backward compatibility with packages signed without package_uuid attribute
            if not package_entry.package_uuid:
                package_entry.package_uuid = package_entry.make_fallback_uuid()
            #cur = self.execute("""delete from wapt_package where package=? and version=? and target_os=? and architecture=? and maturity=? and locale=?""",
            #                      (package_entry.package, package_entry.version, package_entry.target_os,package_entry.architecture, package_entry.maturity, package_entry.locale))

            cur = self.execute("""delete from wapt_package where package_uuid=?""",(package_entry.package_uuid, ))
            cur = self.execute(self._get_insert_package_query(), package_entry.get_values_for_db(locale_code))
            return cur.lastrowid

    def add_start_install(self, package_entry, params_dict={}, explicit_by=None):
        """Register the start of installation in local db

        Args:
            params_dict (dict) : dictionary of parameters provided on command line with --param or by the server
            explicit_by (str) : username of initiator of the install.
                          if not None, install is not a dependencie but an explicit manual install
            setuppy (str) : python source code used for install, uninstall or session_setup
                            code used for uninstall or session_setup must use only wapt self library as
                            package content is no longer available at this step.

        Returns:
            int : rowid of the inserted install status row
        """
        with self:
            if package_entry.package_uuid:
                # keep old entry for reference until install is completed.
                cur = self.execute("""update wapt_localstatus set install_status='UPGRADING' where package=? and package_uuid <> ?""", (package_entry.package, package_entry.package_uuid))
                cur = self.execute("""delete from wapt_localstatus where package_uuid=?""", (package_entry.package_uuid,))
            else:
                cur = self.execute("""delete from wapt_localstatus where package_uuid=?""", (package_entry.package,))

            cur = self.execute("""\
                  insert into wapt_localstatus (
                    package_uuid,
                    package,
                    version,
                    section,
                    priority,
                    architecture,
                    install_date,
                    install_status,
                    install_output,
                    install_params,
                    explicit_by,
                    process_id,
                    maturity,
                    locale,
                    depends,
                    conflicts,
                    impacted_process,
                    audit_schedule
                    ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                package_entry.package_uuid,
                package_entry.package,
                package_entry.version,
                package_entry.section,
                package_entry.priority,
                package_entry.architecture,
                datetime2isodate(),
                'INIT',
                '',
                jsondump(params_dict),
                explicit_by,
                os.getpid(),
                package_entry.maturity,
                package_entry.locale,
                package_entry.depends,
                package_entry.conflicts,
                package_entry.impacted_process,
                package_entry.audit_schedule,
            ))
            return cur.lastrowid

    def update_install_status(self, rowid, set_status=None, append_line=None, uninstall_key=None, persistent_dir=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK', 'WARNING', 'ERROR'):
                pid = None
            else:
                pid = os.getpid()

            cur = self.execute("""\
                  update wapt_localstatus
                    set install_status=coalesce(?,install_status),
                        install_output = coalesce(install_output,'') || ?,
                        uninstall_key=coalesce(?,uninstall_key),
                        process_id=?,
                        persistent_dir = coalesce(?,persistent_dir)
                    where rowid = ?
                """, (
                set_status,
                ensure_unicode(append_line)+'\n' if append_line is not None else '',
                uninstall_key,
                pid,
                persistent_dir,
                rowid,
            )
            )

            # removed previously installed package entry
            install_rec = self.query('select package_uuid,package from wapt_localstatus where rowid = ?', (rowid,), one=True)
            if install_rec and set_status in ('OK', 'WARNING'):
                cur = self.execute("""delete from wapt_localstatus where package=? and rowid <> ?""", (install_rec['package'], rowid))
            return cur.lastrowid

    def update_audit_status(self, rowid, set_status=None, set_output=None, append_line=None, set_last_audit_on=None, set_next_audit_on=None):
        """Update status of package installation on localdb"""
        with self:
            if set_status in ('OK', 'WARNING', 'ERROR'):
                pid = None
            else:
                pid = os.getpid()

            # retrieve last status
            #cur = self.execute("""select last_audit_status,last_audit_on,next_audit_on from wapt_localstatus where rowid = ?""",(rowid,))
            #(last_audit_status,last_audit_on,next_audit_on) = cur.fetchone()
            # if last_audit_on is None:
            #    last_audit_on = datetime2isodate()
            #
            # if set_status is None:
            #    set_status = last_audit_status

            # if set_status is None:
            #    set_status = 'RUNNING'

            cur = self.execute("""\
                  update wapt_localstatus set
                    last_audit_status=coalesce(?,last_audit_status,'RUNNING'),
                    last_audit_on=coalesce(?,last_audit_on),
                    last_audit_output = coalesce(?,last_audit_output,'') || ?,
                    process_id=?,next_audit_on=coalesce(?,next_audit_on)
                    where rowid = ?
                """, (
                set_status,
                set_last_audit_on,
                set_output,
                append_line+'\n' if append_line is not None else '',
                pid,
                set_next_audit_on,
                rowid
            )
            )
            return cur.lastrowid

    def update_install_status_pid(self, pid, set_status='ERROR'):
        """Update status of package installation on localdb"""
        with self:
            cur = self.execute("""\
                  update wapt_localstatus
                    set install_status=coalesce(?,install_status) where process_id = ?
                """, (
                set_status,
                pid,
            )
            )
            return cur.lastrowid

    def switch_to_explicit_mode(self, package, user_id):
        """Set package install mode to manual
        so that package is not removed
        when meta packages don't require it anymore
        """
        with self:
            cur = self.execute("""\
                  update wapt_localstatus
                    set explicit_by=? where package = ?
                """, (
                user_id,
                package,
            )
            )
            return cur.lastrowid

    def store_setuppy(self, rowid, setuppy=None, install_params={}):
        """Update status of package installation on localdb"""
        with self:
            cur = self.execute("""\
                  update wapt_localstatus
                    set setuppy=?,install_params=? where rowid = ?
                """, (
                remove_encoding_declaration(setuppy),
                jsondump(install_params),
                rowid,
            )
            )
            return cur.lastrowid

    def remove_install_status(self, package=None, package_uuid=None):
        """Remove status of package installation from localdb"""
        with self:
            if package_uuid is not None:
                cur = self.execute("""delete from wapt_localstatus where package_uuid=?""", (package_uuid,))
            else:
                cur = self.execute("""delete from wapt_localstatus where package=?""", (package,))
            return cur.rowcount

    def known_packages(self):
        """Return a dict of all known packages PackageKey(s) indexed by package_uuid

        Returns:
            dict  {'package_uuid':PackageKey(package)}
        """
        q = self.execute("""\
              select distinct wapt_package.package_uuid,wapt_package.package,wapt_package.version,architecture,locale,maturity from wapt_package
           """)
        return {e[0]: PackageKey(e[0], e[1], Version(e[2]), *e[3:]) for e in q.fetchall()}

    def packages_matching(self, package_cond):
        """Return an ordered list of available packages entries which match
        the condition "packagename[([=<>]version)]?"
        version ascending

        Args:
            package_cond (PackageRequest or str): filter packages and determine the ordering

        Returns:
            list of PakcageEntry

        """
        if isinstance(package_cond, str):
            package_cond = PackageRequest(request=package_cond)

        if package_cond.package_uuid is not None:
            q = self.query_package_entry("""\
                  select * from wapt_package where package_uuid = ?
               """, (package_cond.package_uuid,))
        elif package_cond.package is not None:
            q = self.query_package_entry("""\
                  select * from wapt_package where package = ?
               """, (package_cond.package,))
        else:
            q = self.query_package_entry("""\
                  select * from wapt_package
               """)
        result = [p for p in q if package_cond.is_matched_by(p)]
        result.sort(key=package_cond.get_package_compare_key)
        return result

    def packages_search(self, searchwords=[], exclude_host_repo=True, section_filter=None, packages_filter=None):
        """Return a list of package entries matching the search words

        Args:
            searchwords (list): list of words which must be in package name or description
            exclude_host (bool): don't take in account packages comming from a repo named 'wapt-host"
            section_filter (list): list of packages sections to take in account
            packages_filter (PackageRequest): additional filters (arch, locale, maturities etc...)
                                              to take in account for filter and sort

        Returns:
            list of PackageEntry

        """
        if not isinstance(searchwords, list) and not isinstance(searchwords, tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = ["%"+w.lower()+"%" for w in searchwords]
            search = ["lower(description || package) like ?"] * len(words)
        if exclude_host_repo:
            search.append('repo <> "wapt-host"')
        if section_filter:
            section_filter = ensure_list(section_filter)
            search.append('section in ( %s )' % ",".join(['"%s"' % x for x in section_filter]))

        if isinstance(packages_filter, str):
            packages_filter = PackageRequest(request=packages_filter)

        result = self.query_package_entry("select * from wapt_package where %s" % " and ".join(search), words)
        if packages_filter is not None:
            result = [p for p in result if packages_filter.is_matched_by(packages_filter)]
            result.sort(key=packages_filter.get_package_compare_key)
        else:
            result.sort()
        return result

    def installed_package_names(self, include_errors=False):
        """
        """
        sql = ["select l.package from wapt_localstatus l"]
        if not include_errors:
            sql.append('where l.install_status in ("OK","UNKNOWN")')
        return [p['package'] for p in self.query('\n'.join(sql))]

    def installed(self, include_errors=False, include_setup=True):
        """Return a list of installed packages on this host (status 'OK' or 'UNKNWON')

        Args:
            include_errors (bool) : if False, only packages with status 'OK' and 'UNKNOWN' are returned
                                    if True, all packages are installed.
            include_setup (bool) : if True, setup.py files content is in the result rows

        Returns:
            list: of installed PackageEntry
        """
        sql = ["""\
              select l.id,l.package,l.version,l.architecture,r.description,r.name,l.install_date,l.install_status,l.install_output,l.install_params,%s
                l.uninstall_key,l.explicit_by,
                coalesce(l.depends,r.depends) as depends,coalesce(l.conflicts,r.conflicts) as conflicts,coalesce(l.section,r.section) as section,
                coalesce(l.priority,r.priority) as priority,
                r.maintainer,r.name,r.description,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo,r.signer,r.signature_date,r.signer_fingerprint,
                l.maturity,l.locale,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.package_uuid,
                l.persistent_dir
                from wapt_localstatus l
                left join wapt_package r on r.package_uuid=l.package_uuid
            """ % (('l.setuppy,' if include_setup else ''),)]
        if not include_errors:
            sql.append('where l.install_status in ("OK","UNKNOWN")')

        q = self.query_package_entry('\n'.join(sql))
        result = []
        for p in q:
            result.append(p)
        return result

    def installed_packages_inventory(self,since_status_revision=None):
        """Return a list of installed packages status suitable for inventory

        List of list.
        First line is the header (fields names)

        Returns:
            list (of list): of installed packages
        """
        query = """\
              select l.id,l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,
                l.uninstall_key,l.explicit_by,
                coalesce(l.depends,r.depends) as depends,
                coalesce(l.conflicts,r.conflicts) as conflicts,
                coalesce(l.section,r.section) as section,
                coalesce(l.priority,r.priority) as priority,
                r.maintainer,r.name,r.description,r.sources,r.filename,r.size,
                r.repo_url,r.md5sum,r.repo,r.signer,r.signature_date,r.signer_fingerprint,
                l.maturity,l.locale,
                l.package_uuid,
                l.persistent_dir
                from wapt_localstatus l
                left join wapt_package r on r.package_uuid=l.package_uuid
            """
        if since_status_revision is None:
            cur = self.execute(query)
        else:
            cur = self.execute(query+' where l.status_revision>?',[since_status_revision])

        result = []
        # first line is columns headers
        result.append([c[0] for c in cur.description])
        for row in cur.fetchall():
            result.append(row)
        return result

    def installed_packages_ids(self):
        """Return list of id of package install status

        """
        cur = self.execute('select id from wapt_localstatus')
        return [c[0] for c in cur.fetchall()]

    def packages_audit_inventory(self,after_date=None):
        """Return a list of packages audit status suitable for inventory

        List of list.
        First line is the header (fields names)

        Returns:
            list (of list): of installed packages
        """
        query = """\
              select l.id,l.package_uuid,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on
                from wapt_localstatus l
            """
        if after_date is None:
            cur = self.execute(query)
        else:
            cur = self.execute(query+' where l.last_audit_on > ?',(after_date,))
        result = []
        result.append([c[0] for c in cur.description])
        for row in cur.fetchall():
            result.append(list(row))
        return result


    def install_status(self, id):
        """Return the local install status for id

        Args:
            id: sql rowid

        Returns:
            dict : merge of package local install, audit and package attributes.

        """
        sql = ["""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,l.explicit_by,
                    l.depends,l.conflicts,l.uninstall_key,
                    l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.audit_schedule,l.package_uuid,
                    r.section,r.priority,r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                    r.repo_url,r.md5sum,r.repo,l.maturity,l.locale,l.persistent_dir
                from wapt_localstatus l
                left join wapt_package r on
                    r.package_uuid=l.package_uuid
                where l.id = ?
           """]

        q = self.query_package_entry('\n'.join(sql), args=[id])
        if q:
            return q[0]
        else:
            return None

    def installed_search(self, searchwords=[], include_errors=False):
        """Return a list of installed package entries based on search keywords


        Returns:
            list of PackageEntry merge with localstatus attributes without setuppy

        """
        if not isinstance(searchwords, list) and not isinstance(searchwords, tuple):
            searchwords = [searchwords]
        if not searchwords:
            words = []
            search = ['1=1']
        else:
            words = ["%"+w.lower()+"%" for w in searchwords]
            search = ["lower(l.package || (case when r.description is NULL then '' else r.description end) ) like ?"] * len(words)
        if not include_errors:
            search.append('l.install_status in ("OK","UNKNOWN")')
        q = self.query_package_entry("""\
              select l.package,l.version,l.architecture,l.install_date,l.install_status,l.install_output,l.install_params,
                l.uninstall_key,l.explicit_by,
                coalesce(l.depends,r.depends) as depends,coalesce(l.conflicts,r.conflicts) as conflicts,coalesce(l.section,r.section) as section,coalesce(l.priority,r.priority) as priority,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,l.audit_schedule,l.package_uuid,
                r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                r.repo_url,r.md5sum,r.repo,l.persistent_dir
              from wapt_localstatus l
                left join wapt_package r on r.package_uuid=l.package_uuid
              where %s
           """ % " and ".join(search), words)
        return q

    def installed_matching(self, package_cond, include_errors=False, include_setup=True):
        """Return a list of PackageEntry
        if one properly installed (if include_errors=False) package match the package condition 'tis-package (>=version)'

        Args:
            package_cond (str): package requirement to lookup
            include_errors

        Returns:
            list of PackageEntry merge with localstatus attributes WITH setuppy

        """
        if isinstance(package_cond, str):
            requ = package_cond
            package_cond = PackageRequest(request=requ)
        elif not isinstance(package_cond, PackageRequest):
            raise Exception('installed_matching: package_cond must be either str ot PackageRequest')

        if include_errors:
            status = '"OK","UNKNOWN","ERROR"'
        else:
            status = '"OK","UNKNOWN"'

        q = self.query_package_entry("""\
              select l.rowid,l.package_uuid,
                l.package,l.version,l.architecture,
                coalesce(l.locale,r.locale) as locale,
                coalesce(l.maturity,r.maturity) as maturity,
                l.install_date,l.install_status,l.install_output,l.install_params,%s
                l.persistent_dir,
                l.uninstall_key,l.explicit_by,
                l.last_audit_status,l.last_audit_on,l.last_audit_output,l.next_audit_on,
                coalesce(l.depends,r.depends) as depends,
                coalesce(l.conflicts,r.conflicts) as conflicts,
                coalesce(l.section,r.section) as section,
                coalesce(l.priority,r.priority) as priority,
                r.maintainer,r.description,r.sources,r.filename,r.size,r.signer,r.signature_date,r.signer_fingerprint,
                r.repo_url,r.md5sum,r.repo
                from wapt_localstatus l
                left join wapt_package r on r.package_uuid=l.package_uuid
              where (l.package=? or l.package_uuid=?) and l.install_status in (%s)
           """ % (('l.setuppy,' if include_setup else ''), status), (package_cond.package,package_cond.package_uuid))
        return q[0] if q and package_cond.is_matched_by(q[0]) else None

    def upgradeable(self, include_errors=True, check_version_only=True,include_setup=False):
        """Return a dictionary of upgradable Package entries

        Returns:
            dict 'package': [candidates] order by  mot adequate to more generic and

        """
        result = {}
        allinstalled = self.installed(include_errors=True,include_setup=include_setup)
        for p in allinstalled:
            available = self.query_package_entry("""select * from wapt_package where package=?""", (p.package,))
            available.sort()
            available.reverse()
            if (available and (
                ((check_version_only and PackageVersion(available[0]['version']) > PackageVersion(p['version'])) or (not check_version_only and available[0] > p)) or  # check version only or full attributes
                (include_errors and p.install_status == 'ERROR'))
                ):  # if current package is in error status, and we have a candidate, add it
                    result[p.package] = available
        return result

    def upgradeable_status(self):
        """Return a list of upgradable Package entries. (faster than upgradeable() )

        Returns:
            list of (installed PackageEntry, candidate PackageEntry)
        """
        result = []
        allinstalled = self.query("""select install_status,package_uuid,package,version,section,priority,maturity,locale from wapt_localstatus""")
        for p in allinstalled:
            availables = self.query("""select package_uuid,package,version,section,priority,maturity,locale,target_os from wapt_package where (? in ('RETRY','ERROR') or package_uuid<>?) and package=?""", (p['install_status'],p['package_uuid'],p['package'],))
            upgr = None
            for available in availables:
                if available and (p['install_status'] in ('ERROR','RETRY') or PackageVersion(available['version']) > PackageVersion(p['version'])):
                    if upgr is None or PackageVersion(available['version']) > PackageVersion(upgr['version']):
                        upgr = available
            if upgr:
                result.append((PackageEntry(**p),PackageEntry(**upgr)))

        return result

    def audit_status(self):
        """Return WORST audit status among properly installed packages"""
        errors = self.query("""select count(*) from wapt_localstatus where install_status="OK" and last_audit_status="ERROR"  """, one=True, as_dict=False)[0]
        if errors > 0:
            return 'ERROR'
        warnings = self.query("""select count(*) from wapt_localstatus where install_status="OK" and (last_audit_status is NULL or last_audit_status in ("WARNING","UNKNOWN")) """, one=True, as_dict=False)[0]
        if warnings and warnings > 0:
            return 'WARNING'
        return 'OK'

    def build_depends(self, packages, packages_filter=None):
        """Given a list of packages conditions (packagename (optionalcondition))
        return a list of dependencies (packages conditions) to install


        Args:
            packages (list of str): list of packages requirements ( package_name(=version) )

        Returns:
            (list depends,list conflicts,list missing) : tuple of (all_depends,missing_depends)

        TODO : choose available dependencies in order to reduce the number of new packages to install

        >>> waptdb = WaptDB(':memory:')
        >>> office = PackageEntry('office','0')
        >>> firefox22 = PackageEntry('firefox','22')
        >>> firefox22.depends = 'mymissing,flash'
        >>> firefox24 = PackageEntry('firefox','24')
        >>> thunderbird = PackageEntry('thunderbird','23')
        >>> flash10 = PackageEntry('flash','10')
        >>> flash12 = PackageEntry('flash','12')
        >>> office.depends='firefox(<24),thunderbird,mymissing'
        >>> firefox22.depends='flash(>=10)'
        >>> firefox24.depends='flash(>=12)'
        >>> waptdb.add_package_entry(office)
        >>> waptdb.add_package_entry(firefox22)
        >>> waptdb.add_package_entry(firefox24)
        >>> waptdb.add_package_entry(flash10)
        >>> waptdb.add_package_entry(flash12)
        >>> waptdb.add_package_entry(thunderbird)
        >>> waptdb.build_depends('office')
        ([u'flash(>=10)', u'firefox(<24)', u'thunderbird'], [u'mymissing'])
        """
        if not isinstance(packages, list) and not isinstance(packages, tuple):
            packages = [packages]

        MAXDEPTH = 30
        # roots : list of initial packages to avoid infinite loops

        alldepends = []
        allconflicts = []
        missing = []
        explored = []

        def dodepends(packages, depth):
            if depth > MAXDEPTH:
                raise Exception('Max depth in build dependencies reached, aborting')
            package_request = PackageRequest(request=None, copy_from=packages_filter)
            # loop over all package names
            for package in packages:
                if not package in explored:
                    if isinstance(package, str):
                        package_request.request = package
                        entries = self.packages_matching(package_request)
                    else:
                        entries = self.packages_matching(package)

                    if not entries and package not in missing:
                        missing.append(package)
                    else:
                        # get depends of the most recent matching entry
                        # TODO : use another older if this can limit the number of packages to install !
                        depends = ensure_list(entries[-1].depends)
                        available_depends = []
                        for d in depends:
                            package_request.request = d
                            if self.packages_matching(package_request):
                                available_depends.append(d)
                            elif d not in missing:
                                missing.append(d)

                        newdepends = dodepends(available_depends, depth+1)
                        for d in newdepends:
                            if not d in alldepends:
                                alldepends.append(d)

                        for d in available_depends:
                            if not d in alldepends:
                                alldepends.append(d)

                        conflicts = ensure_list(entries[-1].conflicts)
                        for d in conflicts:
                            if not d in allconflicts:
                                allconflicts.append(d)

                    explored.append(package)
            return alldepends

        depth = 0
        alldepends = dodepends(packages, depth)
        return (alldepends, allconflicts, missing)

    def query_package_entry(self, query, args=(), one=False, package_request=None):
        """Execute the query on the db try to map result on PackageEntry attributes
        Fields which don't match attributes are added as attributes (and listed in _calc_attributes list)

        Args:
            query (str): sql query
            args (list): parameters of the sql query
            package_request (PackageRequest): keep only entries which match package_request
            one(bool): if True, return the highest available version (if package_request is not None, use it to compare packages)

        Result:
            PackageEntry or list of PackageEntry

        >>> waptdb = WaptDB(':memory:')
        >>> waptdb.add_package_entry(PackageEntry('toto','0',repo='main'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','2',repo='main'))
        >>> waptdb.add_package_entry(PackageEntry('dummy','1',repo='main'))
        >>> waptdb.query_package_entry("select * from wapt_package where package=?",["dummy"])
        [PackageEntry('dummy','2'), PackageEntry('dummy','1')]
        >>> waptdb.query_package_entry("select * from wapt_package where package=?",["dummy"],one=True)
        PackageEntry('dummy','2')
        """
        result = []

        cur = self.execute(query, args)
        for row in cur.fetchall():
            pe = PackageEntry()
            rec_dict = dict((cur.description[idx][0], value) for idx, value in enumerate(row))
            for k in rec_dict:
                setattr(pe, k, rec_dict[k])
                # add joined field to calculated attributes list
                if not k in pe.all_attributes:
                    pe._calculated_attributes.append(k)
            if package_request is None or package_request.is_matched_by(pe):
                result.append(pe)

        if one and result:
            if not package_request:
                result = sorted(result)[-1]
            else:
                result = sorted(result, key=package_request.get_package_compare_key)[-1]

        return result

    def purge_repo(self, repo_name):
        """remove references to repo repo_name

        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> waptdb.purge_repo('main')
        """
        with self:
            self.execute('delete from wapt_package where repo=?', (repo_name,))

    def params(self, packagename):
        """Return install parameters associated with a package"""
        with self:
            cur = self.execute("""select install_params from wapt_localstatus where package=?""", (packagename,))
            rows = cur.fetchall()
            if rows:
                return ujson.loads(rows[0][0])


    def get_packages_from_uuids(self,uuids):
        with self:
            cur = self.query_package_entry("""select * from wapt_packages where package_uuid in (%s)"""  % ','.join('?'*len(uuids)), uuids)
            rows = cur.fetchall()
            return list(rows)

    def get_not_installed_from_uuids(self,uuids):
        with self:
            cur = self.query_package_entry("""select p.* from wapt_packages p
            left join wapt_localstatus s on s.package_uuid=p.package_uuid
             where p.package_uuid in (%s) and s.id is null"""  % ','.join('?'*len(uuids)), uuids)
            rows = cur.fetchall()
            return list(rows)

    def get_status_revision(self):
        q = self.execute("""select cast(value as integer) from wapt_params where name='status_revision' limit 1""").fetchone()
        if q:
            return q[0]
        else:
            return None


class WaptServer(BaseObjectClass):
    """Manage connection to waptserver"""

    def __init__(self, url=None, proxies={'http': None, 'https': None}, timeout=5.0, dnsdomain=None, name='waptserver'):
        if url and url[-1] == '/':
            url = url.rstrip('/')
        self._server_url = url

        self.name = name

        self.proxies = proxies
        self.timeout = timeout
        self.use_kerberos = False
        self.verify_cert = True

        self.client_certificate = None
        self.client_private_key = None

        self.interactive_session = False
        self.ask_user_password_hook = None

        self.private_key_password_callback = None

        self.capture_external_ip_callback = None

        if dnsdomain:
            self.dnsdomain = dnsdomain
        else:
            self.dnsdomain = setuphelpers.get_domain()
        self.clear_session()

    def auth(self, action=None, enable_password_callback=True):
        """Return an authenticator for the action.
        This is basically a tuple (user,password) or a more sophisticated AuthBase descendent.
        The motivation for action is to not request password from user if not needed.
        Or enable kerberos for specific endpoint.

        Args:
            action (str): for which an authenticator is requested

        Returns:
            tuple or requests.auth.AuthBase descendant instance

        """
        if self._server_url:
            if action in ('add_host_kerberos', 'add_host'):
                if not (sys.platform == 'win32'):
                    try:
                        # TODO found other method for TGS
                        setuphelpers.get_domain_info()
                    except:
                        pass
                scheme = urllib.parse.urlparse(self._server_url).scheme
                if scheme == 'https' and has_kerberos and self.use_kerberos:
                    # TODO : simple auth if kerberos is not available...
                    return requests_kerberos.HTTPKerberosAuth(mutual_authentication=requests_kerberos.DISABLED)
            if enable_password_callback:
                return self.ask_user_password(action)
            else:
                return None
        else:
            return None

    def get_private_key_password(self, location, identity):
        if self.private_key_password_callback is not None:
            return self.private_key_password_callback(location, identity)
        else:
            return None

    def clear_session(self):
        self._session = None
        self._session_url = None
        self._session_client_certificate = None
        self._session_use_ssl_auth = None

    def get_requests_session(self, use_ssl_auth=True):
        # don't use cached session if parameters have changed
        if use_ssl_auth != self._session_use_ssl_auth or \
                (self._session_use_ssl_auth and self._session_client_certificate != self.client_certificate):
            self.clear_session()

        if self._session is None:
            url = self.server_url
            if use_ssl_auth:
                if self.client_private_key and is_pem_key_encrypted(self.client_private_key):
                    password = self.get_private_key_password(url, self.client_private_key)
                else:
                    password = None
                cert = (self.client_certificate, self.client_private_key, password)
            else:
                cert = None
            self._session = get_requests_client_cert_session(url=url, cert=cert, verify=self.verify_cert, proxies=self.proxies)
            self._session_use_ssl_auth = use_ssl_auth
            self._session_url = url
            self._session_client_certificate = self.client_certificate
        self._session.headers = default_http_headers()
        return self._session

    def save_server_certificate(self, server_ssl_dir=None, overwrite=False):
        """Retrieve certificate of https server for further checks

        Args:
            server_ssl_dir (str): Directory where to save x509 certificate file

        Returns:
            str : full path to x509 certificate file.

        """
        certs = get_peer_cert_chain_from_server(self.server_url)
        if certs:
            new_cert = certs[0]
            url = urllib.parse.urlparse(self.server_url)
            pem_fn = os.path.join(server_ssl_dir, new_cert.cn.replace('*','wildcard') +'.crt')

            if not fnmatch.fnmatch(url.hostname, new_cert.cn) :
                logger.warning('Warning, certificate CN %s sent by server does not match URL host %s' % (new_cert.cn, url.hostname))

            if not os.path.isdir(server_ssl_dir):
                os.makedirs(server_ssl_dir)
            if os.path.isfile(pem_fn):
                try:
                    # compare current and new cert
                    old_cert = SSLCertificate(pem_fn)
                    if old_cert.modulus != new_cert.modulus:
                        if not overwrite:
                            raise Exception('Can not save server certificate, a file with same name but from diffrent key already exists in %s' % pem_fn)
                        else:
                            logger.info('Overwriting old server certificate %s with new one %s' % (old_cert.fingerprint, new_cert.fingerprint))
                    return pem_fn
                except Exception as e:
                    logger.critical('save_server_certificate : %s' % repr(e))
                    raise
            # write full chain
            with open(pem_fn, 'w',encoding = 'utf8') as f:
                f.write(get_cert_chain_as_pem(certs))
            logger.info('New certificate %s with fingerprint %s saved to %s' % (new_cert, new_cert.fingerprint, pem_fn))
            return pem_fn
        else:
            return None

    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self.clear_session()

    @property
    def server_url(self):
        """Return fixed url if any

        >>> server = WaptServer(timeout=4)
        >>> print server.server_url
        https://wapt.tranquil.it
        """
        return self._server_url


    @server_url.setter
    def server_url(self, value):
        """Wapt main repository URL
        The URL is explicitly set (stored in private _server_url)

        Returns:
            str : URL of wapt server root
        """
        # remove / at the end
        if value:
            value = value.rstrip('/')
        if value != self._server_url:
            self.clear_session()
        self._server_url = value

    def load_config(self, config, section='global'):
        """Load waptserver configuration from inifile
        """
        if not section:
            section = 'global'
        if config.has_section(section):
            self.name = section
            if config.has_option(section, 'wapt_server'):
                # if defined but empty, look in dns srv
                url = config.get(section, 'wapt_server')
                if url:
                    self._server_url = url
                else:
                    self._server_url = None
            else:
                # no server at all
                self._server_url = ''

            if config.has_option(section, 'use_kerberos'):
                self.use_kerberos = config.getboolean(section, 'use_kerberos')

            if config.has_option(section, 'use_http_proxy_for_server') and config.getboolean(section, 'use_http_proxy_for_server'):
                if config.has_option(section, 'http_proxy'):
                    self.proxies = {'http': config.get(section, 'http_proxy'), 'https': config.get(section, 'http_proxy')}
                else:
                    self.proxies = None
            else:
                self.proxies = {'http': None, 'https': None}

            if config.has_option(section, 'wapt_server_timeout'):
                self.timeout = config.getfloat(section, 'wapt_server_timeout')

            if config.has_option(section, 'dnsdomain'):
                self.dnsdomain = config.get(section, 'dnsdomain')

            if config.has_option(section, 'verify_cert'):
                self.verify_cert = get_verify_cert(config.get(section, 'verify_cert'))

            if config.has_option(section, 'client_certificate') and config.get(section, 'client_certificate'):
                self.client_certificate = config.get(section, 'client_certificate')

            if config.has_option(section, 'client_private_key') and config.get(section, 'client_private_key'):
                self.client_private_key = config.get(section, 'client_private_key')
            self.clear_session()
        return self

    def load_config_from_file(self, config_filename, section='global'):
        """Load waptserver configuration from an inifile located at config_filename

        Args:
            config_filename (str) : path to wapt inifile
            section (str): ini section from which to get parameters. default to 'global'

        Returns:
            WaptServer: self

        """
        ini = RawConfigParser()
        ini.read(config_filename)
        self.load_config(ini, section)
        return self

    def get(self, action, auth=None, timeout=None, use_ssl_auth=True, enable_capture_external_ip = True, enable_password_callback=True, decode_json=True):
        """Make a get http request to the server, and return result decoded from json
        This assuems remo


        Args:
            action (str): doc part of the url
            auth (tuple): authentication passed to requests (user,password)
            enable_capture_external_ip (bool) : if true and callback is defined, try to get external IP from X-Remote-IP header
                                                  and set it though self.capture_external_ip_callback
            enable_password_callback (bool) : if true, password callback will be called if needed.

        Returns:
            dict : response returned from server as json data.

        """
        if self.server_url:
            with self.get_requests_session(use_ssl_auth=use_ssl_auth) as session:
                req = session.get("%s/%s" % (self.server_url, action),
                                  timeout=timeout or self.timeout,
                                  auth=auth,
                                  allow_redirects=True)
                if req.status_code == 401:
                    req = session.get("%s/%s" % (self.server_url, action),
                                      timeout=timeout or self.timeout,
                                      auth=self.auth(action=action, enable_password_callback=enable_password_callback),
                                      allow_redirects=True)

                # if ssl auth has issue, retry without ssl_auth
                if req.status_code == 400 and use_ssl_auth:
                    with self.get_requests_session(use_ssl_auth=False) as session2:
                        req = session2.get("%s/%s" % (self.server_url, action),
                                           timeout=timeout or self.timeout,
                                           auth=auth,
                                           allow_redirects=True)
                        if req.status_code == 401:
                            req = session2.get("%s/%s" % (self.server_url, action),
                                               timeout=timeout or self.timeout,
                                               auth=self.auth(action=action, enable_password_callback=enable_password_callback),
                                               allow_redirects=True)

                req.raise_for_status()
                if enable_capture_external_ip and req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                if decode_json:
                    return ujson.loads(req.content)
                else:
                    return req.content
        else:
            raise EWaptBadSetup('Wapt server url not defined')

    def head(self, action, auth=None, timeout=None, use_ssl_auth=True, enable_capture_external_ip=True, enable_password_callback=True):
        """ """
        if self.server_url:
            with self.get_requests_session(use_ssl_auth=use_ssl_auth) as session:
                req = session.head("%s/%s" % (self.server_url, action),
                                   timeout=timeout or self.timeout,
                                   auth=auth,
                                   allow_redirects=True)
                if req.status_code == 401:
                    req = session.head("%s/%s" % (self.server_url, action),
                                       timeout=timeout or self.timeout,
                                       auth=self.auth(action=action, enable_password_callback=enable_password_callback),
                                       allow_redirects=True)

                req.raise_for_status()
                if enable_capture_external_ip and req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                return req.headers
        else:
            raise EWaptBadSetup('Wapt server url not defined')

    def post(self, action, data=None, files=None, auth=None, timeout=None, signature=None, signer=None, content_length=None, use_ssl_auth=True, enable_capture_external_ip=True, enable_password_callback=True,max_retry_count=3):
        """Post data to waptserver using http POST method

        Add a signature to the posted data using host certificate.

        Posted Body is gzipped

        Args:
            action (str): doc part of the url
            data (str) : posted data body
            files (list or dict) : list of filenames

        Returns:
            dict : response returned from server as json data.

        """
        if self.server_url:
            with self.get_requests_session(use_ssl_auth=use_ssl_auth) as session:
                if data:
                    if action == 'add_host_kerberos':
                        try:
                            __, krb_context = kerberos.authGSSClientInit("HTTP@%s" % str(self.server_url).split('//', 1)[1].split(':')[0])
                            kerberos.authGSSClientStep(krb_context, "")
                            negotiate_details = kerberos.authGSSClientResponse(krb_context)
                            session.headers.update({"Authorization": "Negotiate " + negotiate_details})
                        except:
                            pass

                    session.headers.update({
                        'Content-type': 'binary/octet-stream',
                        'Content-transfer-encoding': 'binary',
                    })

                    if isinstance(data, str):
                        data = data.encode('utf-8')
                    if isinstance(data, bytes):
                        session.headers['Content-Encoding'] = 'gzip'
                        data = zlib.compress(data)

                if signature:
                    session.headers.update({
                        'X-Signature': base64.b64encode(signature),
                    })
                if signer:
                    session.headers.update({
                        'X-Signer': signer,
                    })

                if content_length is not None:
                    session.headers['Content-Length'] = "%s" % content_length

                if isinstance(files, list):
                    files_dict = {}
                    for fn in files:
                        with open(fn, 'rb') as f:
                            files_dict[os.path.basename(fn)] = f.read()
                elif isinstance(files, dict):
                    files_dict = files
                else:
                    files_dict = None

                # check if auth is required before sending data in chunk
                retry_count = 0
                if files_dict:
                    while True:
                        req = session.head("%s/%s" % (self.server_url, action),
                                           timeout=timeout or self.timeout,
                                           auth=auth,
                                           allow_redirects=True)
                        if req.status_code == 401:
                            retry_count += 1
                            if retry_count >= 3:
                                raise EWaptBadServerAuthentication('Authentication failed on server %s for action %s' % (self.server_url, action))
                            auth = self.auth(action=action, enable_password_callback=enable_password_callback)
                        else:
                            break

                if type(data) is FileChunks:
                    filechunks = data
                    data = filechunks.get()

                while True:
                    req = session.post("%s/%s" % (self.server_url, action),
                                       data=data,
                                       files=files_dict,
                                       timeout=timeout or self.timeout,
                                       auth=auth,
                                       allow_redirects=True)

                    if (req.status_code == 401) and (retry_count < max_retry_count):
                        retry_count += 1
                        if retry_count >= 3:
                            raise EWaptBadServerAuthentication('Authentication failed on server %s for action %s' % (self.server_url, action))
                        if 'filechunks' in locals():
                            filechunks.reopen()
                            data = filechunks.get()
                        auth = self.auth(action=action, enable_password_callback=enable_password_callback)
                    else:
                        break
                req.raise_for_status()
                # requires that nginx reverse proxy set this 'X-Remote-IP' header.
                if enable_capture_external_ip and req.headers.get('X-Remote-IP') and self.capture_external_ip_callback:
                    self.capture_external_ip_callback(req.headers['X-Remote-IP'])
                return ujson.loads(req.content)
        else:
            raise EWaptBadSetup('Wapt server url not defined')

    def client_auth(self):
        """Return SSL pair (cert,key) filenames for client side SSL auth

        Returns:
            tuple: (cert path,key path,strkeypassword)
        """
        if self.client_certificate and os.path.isfile(self.client_certificate):
            if self.client_private_key is None:
                cert = SSLCertificate(self.client_certificate)
                key = cert.matching_key_in_dirs(password_callback=self.get_private_key_password)
                self.client_private_key = key.private_key_filename
            return (self.client_certificate, self.client_private_key, self.get_private_key_password(self.server_url, self.client_certificate))
        else:
            return None

    def available(self):
        if self.server_url:
            with self.get_requests_session() as session:
                try:
                    req = session.head("%s/ping" % (self.server_url),
                                       timeout=self.timeout,
                                       auth=None,
                                       allow_redirects=True)
                    if req.status_code == 401:
                        req = session.head("%s/ping" % (self.server_url),
                                           timeout=self.timeout,
                                           auth=self.auth(action='ping'),
                                           allow_redirects=True)
                    # try without ssl_auth (self signed client cert)
                    if req.status_code == 400:
                        with self.get_requests_session(use_ssl_auth=False) as session2:
                            req = session2.head("%s/ping" % (self.server_url),
                                                timeout=self.timeout,
                                                auth=None,
                                                allow_redirects=True)
                        if req.status_code == 401:
                            req = session2.head("%s/ping" % (self.server_url),
                                                timeout=self.timeout,
                                                auth=self.auth(action='ping'),
                                                allow_redirects=True)

                    req.raise_for_status()
                    return True
                except Exception as e:
                    #logger.debug(traceback.format_exc())
                    logger.debug('Wapt server %s unavailable (%s)' % (self._server_url, e))
                    return False
        else:
            logger.debug('Wapt server is unavailable because no URL is defined')
            return False

    def as_dict(self):
        result = {}
        attributes = ['server_url', 'proxies', 'dnsdomain']
        for att in attributes:
            result[att] = getattr(self, att)
        return result

    def upload_packages(self, packages, auth=None, timeout=None, progress_hook=None):
        """Upload a list of PackageEntry with local wapt build/signed files

        Returns:
            dict: {'ok','errors'} list of http post upload results
        """
        if not isinstance(packages, list):
            packages = [packages]

        files = {}

        ok = []
        errors = []

        if auth is None:
            # call the callback to get a tuple (user,pwd)
            auth = self.ask_user_password()

        for package in packages:
            if not isinstance(package, PackageEntry):
                pe = PackageEntry().load_control_from_wapt(package)
                package_filename = package
            else:
                pe = package
                package_filename = pe.localpath

            # TODO : issue if more hosts to upload than allowed open file handles.
            if pe.localpath and os.path.isfile(pe.localpath):
                if pe.section in ['host', 'group', 'unit', 'profile']:
                    # small local files, don't stream, we will upload many at once with form encoded files
                    with open(pe.localpath, 'rb') as f:
                        files[os.path.basename(package_filename)] = f.read()
                else:
                    # stream it immediately
                    logger.debug('Uploading %s to server %s' % (pe.localpath, self.server_url))
                    res = self.post('api/v3/upload_packages', data=FileChunks(pe.localpath, progress_hook=progress_hook).get(), auth=auth, timeout=300)
                    if not res['success']:
                        errors.append(res)
                        logger.critical('Error when uploading package %s: %s' % (pe.localpath, res['msg']))
                    else:
                        ok.append(res)
            elif pe._package_content is not None:
                # cached package content for hosts
                files[os.path.basename(package_filename)] = pe._package_content
            else:
                raise EWaptMissingLocalWaptFile('No content to upload for %s' % pe.asrequirement())

        if files:
            try:
                logger.debug('Uploading %s files to server %s' % (len(files), self.server_url))
                res = self.post('api/v3/upload_packages', files=files, auth=auth, timeout=300)
                if not res['success']:
                    errors.append(res)
                    logger.critical('Error when uploading packages: %s' % (res['msg']))
                else:
                    ok.append(res)
            finally:
                pass
        return dict(ok=ok, errors=errors)

    def ask_user_password(self, action=None):
        """Ask for basic auth if server requires it"""
        if self.ask_user_password_hook is not None:
            return self.ask_user_password_hook(action)  # pylint: disable=not-callable
        elif self.interactive_session:
            user = input('Please provide username for action "%s" on server %s: ' % (action, self.server_url))
            if user:
                password = getpass.getpass('Password: ')
                if user and password:
                    return (ensure_unicode(user).encode('utf8'), ensure_unicode(password).encode('utf8'))
                else:
                    return None
        else:
            return None

    def __repr__(self):
        try:
            return '<WaptServer %s verify_cert=%s client_cert_path=%s>' % (self.server_url, self.verify_cert, self.client_certificate)
        except:
            return '<WaptServer %s>' % 'unknown'


class WaptRepo(WaptRemoteRepo):
    """Gives access to a remote http repository, with a zipped Packages packages index
    Find its repo_url based on
    * repo_url explicit setting in ini config section [<name>]
    * if there is some rules use rules
    >>> repo = WaptRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> packages = repo.packages()
    >>> len(packages)
    """

    def __init__(self, url=None, name='wapt', verify_cert=None, http_proxy=None, timeout=None, cabundle=None, config=None, section=None, WAPT=None):
        """Initialize a repo at url "url".

        Args:
            name (str): internal local name of this repository
            url  (str): http URL to the repository.
                 If url is None, the url is requested at the server.
            http_proxy (str): URL to http proxy or None if no proxy.
            timeout (float): timeout in seconds for the connection to the rmeote repository
            wapt_server (str): WAPT Server URL to use for autodiscovery if url is not supplied.

        .. versionchanged:: 1.4.0
           authorized_certs (list):  list of trusted SSL certificates to filter out untrusted entries.
                                 if None, no check is performed. All antries are accepted.
        .. versionchanged:: 1.5.0
           cabundle (SSLCABundle):  list of trusted SSL ca certificates to filter out untrusted entries.
                                     if None, no check is performed. All antries are accepted.

        """
        self._WAPT = None
        self.WAPT = WAPT
        # create additional properties
        self._rules = None
        self._cached_wapt_repo_url = None
        self._repo_url_already_calculated = False
        self._cached_http_proxy = None
        WaptRemoteRepo.__init__(self, url=url, name=name, verify_cert=verify_cert, http_proxy=http_proxy, timeout=timeout, cabundle=cabundle, config=config, section=section)

    def reset_network(self):
        """called by wapt when network configuration has changed"""
        self._rules = None
        self._cached_wapt_repo_url = None
        self._repo_url_already_calculated = False
        self._cached_http_proxy = None
        self._packages = None
        self._packages_date = None

    @property
    def WAPT(self):
        return self._WAPT

    @WAPT.setter
    def WAPT(self, value):
        if value != self.WAPT:
            self._WAPT = value

    def rulesdb(self):
        """
        Get rules from DB
        """
        if self.name in ('wapt', 'wapt-host', 'waptwua'):
            if self.WAPT is not None:
                rules = self.WAPT.waptdb.get_param('repo_rules-wapt')
                return rules if isinstance(rules, list) else []
        return []

    @property
    def rules(self):
        if self._rules is None:
            all_rules = self.rulesdb()
            self._rules = []
            for rule in all_rules:
                if self.name in rule['repositories']:
                    self._rules.append(rule)
        return self._rules

    @property
    def cached_wapt_repo_url(self):
        if self._repo_url_already_calculated:
            return self._cached_wapt_repo_url
        else:
            return self.find_wapt_repo_url() if self.WAPT is not None and self.WAPT.use_repo_rules and self.rules else None

    @cached_wapt_repo_url.setter
    def cached_wapt_repo_url(self, value):
        if value != self._cached_wapt_repo_url:
            if value:
                value = value.rstrip('/')
            self._cached_wapt_repo_url = value

    @property
    def repo_url(self):
        """Repository URL

        Fixed url if none is set in wapt-get.ini by querying the server.

        The URL is queried once and then cached into a local property.

        Returns:
            str: url to the repository

        >>> repo = WaptRepo(name='wapt',timeout=4)
        >>> print repo.wapt_server
        http://wapt.wapt.fr/
        >>> repo = WaptRepo(name='wapt',timeout=4)
        >>> print repo.wapt_server
        http://wapt.wapt.fr/
        >>> print repo.repo_url
        http://srvwapt.tranquilit.local/wapt
        """
        calculated_repo = self.cached_wapt_repo_url
        return calculated_repo if calculated_repo else self._repo_url

    @repo_url.setter
    def repo_url(self, value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self.reset_network()
            self._repo_url = value

    @property
    def proxies(self):
        """dict for http proxies url suitable for requests based on the http_proxy repo attribute

        Returns:
            dict: {'http':'http://proxy:port','https':'http://proxy:port'}
        """
        if self._cached_http_proxy:
            proxy = self._cached_http_proxy
        elif self.http_proxy:
            proxy = self.http_proxy
        else:
            proxy = None
        return {'http': proxy, 'https': proxy}

    def find_wapt_repo_url(self):
        """Find a wapt_repo_url from rules
        Returns:
            str: URL to the repo.
        """
        def rule_agent_ip(rule):
            try:
                ip_network = ipaddress.ip_network(rule['value'])
            except ValueError:
                return False
            for ip in get_main_ip(urllib.parse.urlparse(rule['repo_url']).netloc):
                if ipaddress.ip_address(ip) in ip_network:
                    return True
            return False

        def rule_domain(rule):
            return setuphelpers.get_domain().lower() == rule['value'].lower()

        def rule_hostname(rule):
            return fnmatch.fnmatch(setuphelpers.get_hostname().lower(), rule['value'].lower())

        def rule_public_ip(rule):
            ip = self.WAPT.waptdb.get_param('last_external_ip')
            return ip and (ipaddress.ip_address(ip) in ipaddress.ip_network(rule['value']))

        def rule_site(rule):
            return self.WAPT.get_host_site().lower() == rule['value'].lower()

        def check_rule(rule_condition, rule):
            return {
                'AGENT IP': rule_agent_ip,
                'DOMAIN': rule_domain,
                'HOSTNAME': rule_hostname,
                'PUBLIC IP': rule_public_ip,
                'SITE': rule_site
            }[rule_condition](rule)

        self._repo_url_already_calculated = True
        for rule in sorted(self.rules, key=itemgetter('sequence')):
            try:
                if (not(rule.get('negation', False)) == check_rule(rule['condition'], rule)) and \
                        (rule.get('no_fallback', False) or \
                        ((self.name == 'waptwua' and ('download.windowsupdate.com' in rule['repo_url'])) or \
                        super(WaptRepo, self).is_available(url=rule['repo_url'], http_proxy=rule['http_proxy'] if rule.get('has_proxy', False) else None) is not None)):
                    self.cached_wapt_repo_url = rule['repo_url'].rstrip('/')+'-host' if isinstance(self, WaptHostRepo) else rule['repo_url']
                    rule['active_rule'] = True
                    self._cached_http_proxy = rule['http_proxy'] if rule.get('has_proxy', False) else None
                    return self.cached_wapt_repo_url
            except Exception as e:
                logger.critical("The rule %s failed for repo %s with repo_url %s : %s" % (rule['name'], self.name, rule['repo_url'], str(e)))
                rule['exception'] = str(e)
        self.cached_wapt_repo_url = None
        self._cached_http_proxy = None
        return None

    def load_config(self, config, section=None):
        """Load waptrepo configuration from inifile section.

        Use name of repo as section name if section is not provided.
        Use 'global' if no section named section in ini file
        """
        if not section:
            section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            section = 'global'

        if config.has_option(section, 'repo_url'):
            self._repo_url = config.get(section, 'repo_url')
        elif config.has_option('global', 'repo_url'):
            self._repo_url = config.get('global', 'repo_url')

        WaptRemoteRepo.load_config(self, config, section)
        return self

    def as_dict(self):
        result = super(WaptRepo, self).as_dict()
        result.update(
            {
                'repo_url': self.repo_url,
                'rules': self._rules,
            })
        return result

    def __repr__(self):
        try:
            return '<WaptRepo %s verify_cert=%s client_cert_path=%s>' % (self.repo_url, self.verify_cert, self.client_certificate)
        except:
            return '<WaptRepo unknown>'


class WaptHostRepo(WaptRepo):
    """Dummy http repository for host packages

    >>> host_repo = WaptHostRepo(name='wapt-host',host_id=['0D2972AC-0993-0C61-9633-529FB1A177E3','4C4C4544-004E-3510-8051-C7C04F325131'])
    >>> host_repo.load_config_from_file(r'C:\\Users\htouvet\AppData\Local\waptconsole\waptconsole.ini')
    >>> host_repo.packages()
    [PackageEntry('0D2972AC-0993-0C61-9633-529FB1A177E3','10') ,
     PackageEntry('4C4C4544-004E-3510-8051-C7C04F325131','30') ]
    """

    def __init__(self, url=None, name='wapt-host', verify_cert=None, http_proxy=None, timeout=None, host_id=None, cabundle=None, config=None, section=None, host_key=None, WAPT=None):
        self._host_id = None
        self.host_key = None
        WaptRepo.__init__(self, url=url, name=name, verify_cert=verify_cert, http_proxy=http_proxy, timeout=timeout, cabundle=cabundle, config=config, section=section, WAPT=WAPT)
        self.host_id = host_id

        if host_key:
            self.host_key = host_key

    def host_package_url(self, host_id=None):
        if host_id is None:
            if self.host_id and isinstance(self.host_id, list):
                host_id = self.host_id[0]
            else:
                host_id = self.host_id
        return "%s/%s.wapt" % (self.repo_url, host_id)

    def is_available(self):
        logger.debug('Checking availability of %s' % (self.name))
        try:
            host_package_url = self.host_package_url()
            with self.get_requests_session() as session:
                logger.debug('Trying to get  host package for %s at %s' % (self.host_id, host_package_url))
                req = session.head(host_package_url,
                                   timeout=self.timeout,
                                   allow_redirects=True)
                req.raise_for_status()
                packages_last_modified = req.headers.get('last-modified')

                return httpdatetime2isodate(packages_last_modified)
        except requests.HTTPError:
            logger.info('No host package available at this time for %s on %s' % (self.host_id, self.name))
            return None

    def load_config(self, config, section=None):
        """Load waptrepo configuration from inifile section.

        Use name of repo as section name if section is not provided.
        Use 'global' if no section named section in ini file
        """
        if not section:
            section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            if config.has_section('wapt-main'):
                section = 'wapt-main'
            else:
                section = 'global'

        WaptRepo.load_config(self, config, section)
        return self

    @property
    def repo_url(self):
        # hack to get implicit repo_url from main repo_url
        repo_url = super(WaptHostRepo, self).repo_url
        if repo_url and self._section in ['wapt-main', 'global'] and not repo_url.endswith('-host'):
            return repo_url+'-host'
        else:
            return repo_url

    @repo_url.setter
    def repo_url(self, value):
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self.reset_network()
            self._repo_url = value

    @property
    def host_id(self):
        return self._host_id

    @host_id.setter
    def host_id(self, value):
        if value != self._host_id:
            self._packages = None
            self._packages_date = None
            self._index = {}
            self._index_by_uuid = {}
        self._host_id = value

    def _load_packages_index(self):
        self._packages = []
        self._index = {}
        self._index_by_uuid = {}
        self.discarded = []
        if not self.repo_url:
            raise EWaptException('URL for WaptHostRepo repository %s is empty. Either add a wapt-host section in ini, or add a correct wapt_server and rules' % (self.name))
        if self.host_id and not isinstance(self.host_id, list):
            host_ids = [self.host_id]
        else:
            host_ids = self.host_id

        with self.get_requests_session() as session:
            for host_id in host_ids:
                host_package_url = self.host_package_url(host_id)
                logger.debug('Trying to get  host package for %s at %s' % (host_id, host_package_url))
                host_package = session.get(host_package_url,
                                           timeout=self.timeout,
                                           allow_redirects=True,
                                           )

                # prepare a package entry for further check
                package = PackageEntry()
                package.package = host_id
                package.repo = self.name
                package.repo_url = self.repo_url

                if host_package.status_code == 404:
                    # host package not found
                    logger.info('No host package found for %s' % host_id)
                    package._packages_date = '1900-01-01T00:00:00'
                    package._package_content = None
                    self._packages_date = package._packages_date
                else:
                    # for other than not found error, add to the discarded list.
                    # this can be consulted for mass changes to not recreate host packages because of temporary failures
                    try:
                        host_package.raise_for_status()
                    except requests.HTTPError as e:
                        logger.info('Discarding package for %s: error %s' % (package.package, e))
                        self.discarded.append(package)
                        continue

                    content = host_package.content

                    if not content.startswith(zipfile.stringFileHeader):
                        # try to decrypt package data
                        if self.host_key:
                            _host_package_content = self.host_key.decrypt_fernet(content)
                        else:
                            raise EWaptNotAPackage('Package for %s does not look like a Zip file and no key is available to try to decrypt it' % host_id)
                    else:
                        _host_package_content = content

                    # Packages file is a zipfile with one Packages file inside
                    with CustomZipFile(io.BytesIO(_host_package_content)) as zip:
                        control_data = codecs.decode(zip.read(name='WAPT/control'), 'UTF-8')
                        package._load_control(control_data)
                        package.filename = package.make_package_filename()

                        try:
                            cert_data = zip.read(name='WAPT/certificate.crt')
                            signers_bundle = SSLCABundle()
                            signers_bundle.add_certificates_from_pem(cert_data)
                        except Exception as e:
                            logger.warning('Error reading host package certificate: %s' % repr(e))
                            signers_bundle = None

                    if self.is_locally_allowed_package(package):
                        try:
                            if self.cabundle is not None:
                                package.check_control_signature(self.cabundle, signers_bundle=signers_bundle)
                            self._add_package(package)

                            # keep content with index as it should be small
                            package._package_content = _host_package_content
                            package._packages_date = httpdatetime2isodate(host_package.headers.get('last-modified', None))

                            # TODO better
                            self._packages_date = package._packages_date

                        except (SSLVerifyException, EWaptNotSigned) as e:
                            logger.critical("Control data of package %s on repository %s is either corrupted or doesn't match any of the expected certificates %s" % (package.asrequirement(), self.name, self.cabundle))
                            logger.debug("%s: %s" % (package.asrequirement(),e))
                            self.discarded.append(package)
                    else:
                        logger.info('Discarding %s on repo "%s" because of local whitelist/blacklist rules' % (package.asrequirement(), self.name))
                        self.discarded.append(package)

    def download_packages(self, package_requests, target_dir=None, usecache=True, printhook=None):
        """Download a list of packages from repo

        Args:
            package_request (list,PackageEntry): a list of PackageEntry to download
            target_dir (str): where to store downloaded Wapt Package files
            usecache (bool): wether to try to use cached Wapt files if checksum is ok
            printhook (callable): to show progress of download

        Returns:
            dict: {"downloaded":[local filenames],"skipped":[filenames in cache],"errors":[],"packages":self.packages()}
        """
        if not isinstance(package_requests, (list, tuple)):
            package_requests = [package_requests]
        if not target_dir:
            target_dir = tempfile.mkdtemp()
        downloaded = []
        errors = []

        self._load_packages_index()

        # if multithread... we don't have host package in memory cache from last self._load_packages_index
        for pr in package_requests:
            for pe in self.packages():
                if ((isinstance(pr, PackageEntry) and (pe == pr)) or
                        (isinstance(pr, str) and pe.match(pr))):

                    pfn = os.path.join(target_dir, pe.make_package_filename())
                    if not pfn.endswith('.wapt'):
                        raise EWaptNotAPackage('The file %s does not have a .wapt extension' % pfn)

                    if pe._package_content is not None:
                        with open(pfn, 'wb') as package_zip:
                            package_zip.write(pe._package_content)
                        pe.localpath = pfn
                        # for further reference
                        if isinstance(pr, PackageEntry):
                            pr.localpath = pfn
                        downloaded.append(pfn)
                        if not os.path.isfile(pfn):
                            logger.warning('Unable to write host package %s into %s' % (pr.asrequirement(), pfn))
                            errors.append(pfn)
                    else:
                        logger.warning('No host package content for %s' % (pr.asrequirement(),))
                    break

        return {"downloaded": downloaded, "skipped": [], "errors": [], "packages": self.packages()}

    def __repr__(self):
        return '<WaptHostRepo %s for host_id %s >' % (self.repo_url, self.host_id)


class WaptPackageInstallLogger(LogOutput):
    """Context handler to log all print messages to a wapt package install log

    Args:
        wapt_context (Wapt): Wapt instance
        package_name (str): name of running or installed package local status where to log status and output
    >>>
    """

    def __init__(self, console, wapt_context=None, install_id=None, user=None, running_status='RUNNING', exit_status='OK', error_status='ERROR'):
        self.wapt_context = wapt_context
        self.install_id = install_id
        self.last_stdout_line = ''

        self.user = user
        if self.user is None:
            self.user = setuphelpers.get_current_user()

        def update_install_status(append_line=None, set_status=None, context=None):
            if self.wapt_context:
                self.wapt_context.update_package_install_status(
                    rowid=context.install_id,
                    set_status=set_status,
                    append_line=append_line)

                self.wapt_context.runstatus = append_line or ''

                if append_line and hasattr(self.wapt_context, 'events') and self.wapt_context.events:
                    self.wapt_context.events.post_event('PRINT', ensure_unicode(append_line))

        LogOutput.__init__(self, console=console,
                           update_status_hook=update_install_status,
                           context=self,
                           running_status=running_status,
                           exit_status=exit_status,
                           error_status=error_status)


class WaptPackageSessionSetupLogger(LogOutput):
    """Context handler to log all print messages to a wapt package install log

    Args:
        wapt_context (Wapt): Wapt instance
        package_name (str): name of running or installed package local status where to log status and output
    >>>
    """

    def __init__(self, console, waptsessiondb, install_id, running_status='RUNNING', exit_status=None, error_status='ERROR'):
        self.waptsessiondb = waptsessiondb
        self.install_id = install_id

        def update_install_status(append_line=None, set_status=None, context=None):
            self.waptsessiondb.update_install_status(
                rowid=context.install_id,
                set_status=set_status,
                append_line=append_line)

        LogOutput.__init__(self, console=console,
                           update_status_hook=update_install_status,
                           context=self,
                           running_status=running_status,
                           exit_status=exit_status,
                           error_status=error_status)


class WaptPackageAuditLogger(LogOutput):
    """Context handler to log all print messages to a wapt package audit log

    Args:
        console (file) : sys.stderr
        wapt_context (Wapt): Wapt instance
        install_id (int): name of running or installed package local status where to log status and output
    >>>
    """

    def __init__(self, console, wapt_context=None, install_id=None, user=None, running_status='RUNNING', exit_status=None, error_status='ERROR'):
        self.wapt_context = wapt_context
        self.install_id = install_id

        self.user = user
        if self.user is None:
            self.user = setuphelpers.get_current_user()

        def update_audit_status(append_line=None, set_status=None, context=None):
            self.wapt_context.waptdb.update_audit_status(
                rowid=context.install_id,
                set_status=set_status,
                append_line=append_line)

        LogOutput.__init__(self, console=console,
                           update_status_hook=update_audit_status,
                           context=self,
                           running_status=running_status,
                           exit_status=exit_status,
                           error_status=error_status)

######################


class Wapt(BaseObjectClass):
    """Global WAPT engine"""
    global_attributes = ['wapt_base_dir', 'waptserver', 'config_filename', 'proxies', 'repositories', 'personal_certificate_path',
                        'public_certs_dir', 'packages_cache_dir', 'dbpath',
                        'http_proxy','use_http_proxy_for_repo','use_http_proxy_for_server',
                        'limit_bandwidth',
                        'waptservice_user','waptservice_password','waptservice_admin_filter','waptservice_port','waptservice_poll_timeout',
                        'locales','custom_tags','packages_whitelist','packages_blacklist','maturities',
                        'host_uuid','use_fqdn_as_uuid','use_hostpackages','use_ad_groups','use_repo_rules',
                        'host_profiles','host_organizational_unit_dn','host_ad_site',
                        'allow_user_service_restart','allow_remote_shutdown','allow_remote_reboot',
                        'ldap_auth_server','ldap_auth_base_dn','ldap_auth_ssl_enabled','verify_cert_ldap',
                        'loglevel','loglevel_waptcore','loglevel_waptservice','loglevel_wapttasks','loglevel_waptws','loglevel_waptdb','loglevel_websocket','loglevel_waitress','log_to_windows_events',
                        'download_after_update_with_waptupdate_task_period',
                        'websockets_ping','websockets_retry_delay','websockets_check_config_interval','websockets_hurry_interval',
                        'notify_user',
                        'waptaudit_task_period',
                        'signature_clockskew',
                        'wol_relay',
                        'hiberboot_enabled','max_gpo_script_wait','pre_shutdown_timeout',
                        'minimum_battery_percent',
                        'uninstallkey_timeout',
                        'check_certificates_validity',
                        'token_lifetime',
                        'repositories',
                        'trust_all_certs_in_pems',
                        'include_dmi_inventory',
                        'include_wmi_inventory',
                        'wapt_temp_dir'
                        ]


    def __init__(self, config_filename=None, defaults=None, disable_update_server_status=True, wapt_base_dir=None, dbpath=None):
        """Initialize engine with a configParser instance (inifile) and other defaults in a dictionary
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> updates = wapt.update()
        >>> 'count' in updates and 'added' in updates and 'upgrades' in updates and 'date' in updates and 'removed' in updates
        True
        """
        # used to signal to cancel current operations ASAP
        self.task_is_cancelled = threading.Event()

        assert not config_filename or isinstance(config_filename, str)
        self._waptdb = None
        self._waptsessiondb = None
        self._dbpath = dbpath
        # cached runstatus to avoid setting in db if not changed.
        self._runstatus = None
        if wapt_base_dir:
            self.wapt_base_dir = wapt_base_dir
        else:
            self.wapt_base_dir = os.path.dirname(os.path.abspath(waptutils__file__))

        self.config = None
        self.config_filename = config_filename
        if not self.config_filename:
            self.config_filename = self.default_config_filename()


        self.private_dir = os.path.join(self.wapt_base_dir, 'private')
        self.persistent_root_dir = os.path.join(self.wapt_base_dir, 'private', 'persistent')
        self.token_lifetime = 24*60*60

        self.disable_update_server_status = disable_update_server_status
        self.configs_dir = os.path.join(self.wapt_base_dir, 'conf.d')


        self.load_config(config_filename=self.config_filename,merge_config_packages=False)

        if not os.path.exists(self.packages_cache_dir):
            os.makedirs(self.packages_cache_dir)
        if self.wapt_temp_dir and not os.path.exists(self.wapt_temp_dir):
            os.makedirs(self.wapt_temp_dir)



        self.options = OptionParser()
        self.options.force = False

        self._last_date_wmi_send = None
        self._last_date_dmi_send = None


        # list of process pids launched by run command
        self.pidlist = []

        # events handler
        self.events = None

        self.progress_hook = None

        if sys.platform == 'win32':
            pythoncom.CoInitialize()


    def reset_settings(self):
        self.config=None
        self._host_uuid = None

        self._merge_config_packages = True

        self.use_hostpackages = True
        self.use_ad_groups = False
        self.waptaudit_task_period = "2h"

        self._repositories = None

        self._wua_repository = None

        self.upload_cmd = None
        self.upload_cmd_host = self.upload_cmd
        self.after_upload = None
        self.proxies = None
        self.language = setuphelpers.get_language()
        self.locales = [setuphelpers.get_language()]
        self.maturities = ['PROD', '']
        # default maturity when importing or creating new package
        self.default_maturity = ''

        self.filter_on_host_cap = True

        self.use_http_proxy_for_repo = False
        self.use_http_proxy_for_server = False

        self.public_certs_dir = None

        self.forced_uuid = None
        self.use_fqdn_as_uuid = False

        # to redirect stdout
        self.redirect_stdout_to = None

        # where to pre-download the packages
        self.packages_cache_dir = os.path.join(os.path.dirname(self.config_filename), 'cache')
        # where to unzip packages for installation
        self.wapt_temp_dir = None

        # to allow/restrict installation, supplied to packages
        self.user = setuphelpers.get_current_user()
        self.usergroups = None

        # host key cache
        self._host_key = None
        self._host_key_timestamp = None

        self._host_certificate = None
        self._host_certificate_timestamp = None

        # for private key password dialog tales (location,indentity) parameters
        self._private_key_password_callback = None

        # keep private key in cache
        self._private_key_cache = None

        self._cabundle = None
        self.check_certificates_validity = False

        self._waptserver = None

        self.packages_whitelist = None
        self.packages_blacklist = None
        self._host_profiles = None

        self.use_repo_rules = False

        # if True: trust all certificates in each PEM file of wapt/ssl
        # if False: trust only the first certificate of each file.
        self.trust_all_certs_in_pems = False

        self.include_dmi_inventory = False
        self.include_wmi_inventory = False

    @property
    def cabundle(self):
        # lazy loading to handle config changes
        if self._cabundle is None:
            self._cabundle = SSLCABundle()
            self._cabundle.add_pems(self.public_certs_dir,trust_first=True,trust_all=self.trust_all_certs_in_pems,load_keys=False)
        return self._cabundle

    @property
    def merged_config_hash(self):
        return self.read_param('merged_config_hash')

    @merged_config_hash.setter
    def merged_config_hash(self,value):
        if self.read_param('merged_config_hash') != value:
            return self.write_param('merged_config_hash',value)

    def get_config_files_list(self):
        return [d for d in (self.config_filename, self.configs_dir, self.public_certs_dir, self.get_host_certificate_filename()) if d and (os.path.isfile(d) or os.path.isdir(d))]

    def get_config_hash(self):
        return get_files_timestamp_sha256(self.get_config_files_list())

    def default_config_filename(self):
        return os.path.join(self.wapt_base_dir, 'wapt-get.ini')

    @property
    def private_key_password_callback(self):
        return self._private_key_password_callback

    @private_key_password_callback.setter
    def private_key_password_callback(self, value):
        self._private_key_password_callback = value
        if self._waptserver:
            self._waptserver.private_key_password_callback = value
        if self._repositories:
            for repo in self._repositories:
                repo.private_key_password_callback = value

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        pass

    def as_dict(self):
        result = {}
        for att in self.global_attributes:
            if hasattr(self, att):
                result[att] = getattr(self, att)
        return result

    @property
    def dbpath(self):
        if self._waptdb:
            return self._waptdb.dbpath
        elif self._dbpath:
            return self._dbpath
        else:
            return None

    @dbpath.setter
    def dbpath(self, value):
        # check if not changed
        if self._waptdb and self._waptdb.dbpath == value:
            return
        # updated : reset db
        self._waptdb = None
        self._dbpath = value

    @property
    def host_profiles(self):
        result = []
        if self._host_profiles is not None:
            result.extend(self._host_profiles)

        if self.use_ad_groups:
            result.extend(self.get_cache_domain_info()['groups'])

        return result

    def set_client_cert_auth(self, connection, force=False):
        """Set client side ssl authentication for a waptserver or a waptrepo using
        host_certificate if client_certificate is not yet set in config and host certificate is able to do client_auth

        Args:
            connection: object with client_certificate, client_private_key and client_auth

        """
        try:
            # use implicit host client certificate if not already set by config
            if force or connection.client_certificate is None:
                if os.path.isfile(self.get_host_certificate_filename()) and os.path.isfile(self.get_host_key_filename()):
                    crt = self.get_host_certificate()
                    if crt.is_client_auth:
                        logger.debug('Using host certificate %s for repo %s auth' % (self.get_host_key_filename(), connection.name))
                        connection.client_certificate = self.get_host_certificate_filename()
                        connection.client_private_key = self.get_host_key_filename()
                    else:
                        logger.warning('Host client certificate %s has not client_auth capability, not using it for auth on %s' % (self.get_host_certificate_filename(), connection.name))
                else:
                    logger.debug('Host certificate %s not found, not using it for auth on repo %s' % (self.get_host_certificate_filename(), connection.name))
            connection.private_key_password_callback = self.private_key_password_callback
        except Exception as e:
            logger.debug('Unable to use client certificate auth: %s' % e)

    def save_external_ip(self, ip):
        self.waptdb.set_param('last_external_ip', ip)

    def save_last_domain_info_date(self, lastdate):
        self.waptdb.set_param('last_domain_info_date', lastdate)

    def save_domain_info(self, info):
        self.waptdb.set_param('domain_info', info)

    def load_config(self, config_filename=None, merge_config_packages=None):
        """Load configuration parameters from supplied inifilename
        """
        self.reset_settings()

        if merge_config_packages is None:
            merge_config_packages = self._merge_config_packages
        # default config file
        defaults = {
            'loglevel': 'warning',
            'log_to_windows_events': '0',
            'use_http_proxy_for_repo': '0',
            'use_http_proxy_for_server': '0',
            'tray_check_interval': 2,
            'use_hostpackages': '1',
            'use_ad_groups': '0',
            'timeout': 10.0,
            'wapt_server_timeout': 30.0,
            'maturities': 'PROD',
            'default_maturity': '',
            'http_proxy': '',
            'public_certs_dir': os.path.join(self.wapt_base_dir, 'ssl'),
            'private_dir': os.path.join(self.wapt_base_dir, 'private'),
            'persistent_root_dir': os.path.join(self.wapt_base_dir, 'private', 'persistent'),
            'token_lifetime': 24*60*60,  # 24 hours
            'trust_all_certs_in_pems': '0',

            # optional...
            'default_sources_root': 'c:\\waptdev' if (os.name == 'nt') else os.path.join(os.path.expanduser('~'), 'waptdev'),
            'default_package_prefix': 'tis',
            'default_sources_suffix': 'wapt',
            'default_sources_url': '',
            'upload_cmd': '',
            'upload_cmd_host': '',
            'after_upload': '',
            'personal_certificate_path': '',
            'check_certificates_validity': '1',

            'use_fqdn_as_uuid': '0',
            'uninstallkey_timeout': 120,
        }

        if not self.config:
            self.config = RawConfigParser(defaults=defaults)

        if config_filename:
            self.config_filename = config_filename

        if self.config_filename:
            relative_configs_dir = os.path.join(os.path.dirname(self.config_filename),'conf.d')
            if os.path.isdir(relative_configs_dir):
                self.configs_dir = relative_configs_dir

        if merge_config_packages and self.configs_dir:
            update_ini_from_json_config(self.config_filename,self.configs_dir)

        if os.path.isfile(self.config_filename):
            with open(self.config_filename,'r',encoding='utf8') as f:
                self.config.readfp(f)

        # lazzy loading
        self._repositories = None

        if self.config.has_option('global','wapt_base_dir') and self.config.get('global', 'wapt_base_dir') != '':
            self.wapt_base_dir = self.config.get('global','wapt_base_dir')

        # chicken and eggs issue. in dev mode, we don't want to override dbapth=':memory:'
        if self.dbpath != ':memory:':
            if self.config.has_option('global', 'dbpath') and self.config.get('global', 'dbpath') != '':
                self.dbpath = self.config.get('global', 'dbpath')
            else:
                self.dbpath = os.path.join(self.wapt_base_dir, 'db', 'waptdb.sqlite')

        if self.config.has_option('global', 'private_dir') and self.config.get('global', 'private_dir') != '':
            self.private_dir = self.config.get('global', 'private_dir')
        else:
            self.private_dir = os.path.join(self.wapt_base_dir, 'private')

        if self.config.has_option('global', 'persistent_root_dir') and self.config.get('global', 'persistent_root_dir') != '':
            self.persistent_root_dir = self.config.get('global', 'persistent_root_dir')
        else:
            self.persistent_root_dir = os.path.join(self.private_dir, 'persistent')

        if self.config.has_option('global', 'uuid'):
            self.forced_uuid = self.config.get('global', 'uuid')
        else:
            # force reset to None if config file is changed at runtime
            self.forced_uuid = None

        if self.config.has_option('global', 'use_fqdn_as_uuid'):
            self.use_fqdn_as_uuid = self.config.getboolean('global', 'use_fqdn_as_uuid')

        if self.config.has_option('global', 'uninstallkey_timeout'):
            self.uninstallkey_timeout = self.config.getint('global', 'uninstallkey_timeout')

        # must have a matching key either in same file or in same directory
        # see self.private_key()
        if self.config.has_option('global', 'personal_certificate_path'):
            self.personal_certificate_path = self.config.get('global', 'personal_certificate_path')

        # be smart with old config
        if not self.personal_certificate_path and self.config.has_option('global', 'private_key'):
            pk = self.config.get('global', 'private_key')
            if pk and os.path.isfile(pk):
                (root, ext) = os.path.splitext(pk)
                if os.path.isfile(root+'.crt'):
                    self.personal_certificate_path = root+'.crt'

        if self.config.has_option('global', 'public_certs_dir') and self.config.get('global', 'public_certs_dir') != '':
            self.public_certs_dir = self.config.get('global','public_certs_dir')
        else:
            self.public_certs_dir = os.path.join(self.wapt_base_dir, 'ssl')

        self._cabundle = None

        self.trust_all_certs_in_pems = False
        # set this to True for backward compatibility.
        # but it's more secure to only trust first.
        if self.config.has_option('global', 'trust_all_certs_in_pems'):
            self.trust_all_certs_in_pems = self.config.getboolean('global', 'trust_all_certs_in_pems')

        if self.config.has_option('global', 'check_certificates_validity'):
            self.check_certificates_validity = self.config.getboolean('global', 'check_certificates_validity')

        if self.config.has_option('global', 'upload_cmd'):
            self.upload_cmd = self.config.get('global', 'upload_cmd')

        if self.config.has_option('global', 'upload_cmd_host'):
            self.upload_cmd_host = self.config.get('global', 'upload_cmd_host')

        if self.config.has_option('global', 'after_upload'):
            self.after_upload = self.config.get('global', 'after_upload')

        self.use_http_proxy_for_repo = self.config.getboolean('global', 'use_http_proxy_for_repo')
        self.use_http_proxy_for_server = self.config.getboolean('global', 'use_http_proxy_for_server')

        if self.config.has_option('global', 'http_proxy'):
            self.proxies = {'http': self.config.get('global', 'http_proxy'), 'https': self.config.get('global', 'http_proxy')}
        else:
            self.proxies = None

        # force reset to None if config file is changed at runtime
        self._waptserver = None

        if self.config.has_option('global', 'language'):
            self.language = self.config.get('global', 'language')

        # for testing
        if self.config.has_option('global', 'fake_hostname'):
            self._set_fake_hostname(self.config.get('global', 'fake_hostname'))

        # allow to fake a host Oragnaizational Unit when the computer is not part of an AD, but we want to put host in a OU.
        if self.config.has_option('global', 'host_organizational_unit_dn'):
            forced_host_organizational_unit_dn = self.config.get('global', 'host_organizational_unit_dn')
            if forced_host_organizational_unit_dn != self.host_organizational_unit_dn:
                logger.info('Forced forced_host_organizational_unit_dn DB %s' % forced_host_organizational_unit_dn)
                self.host_organizational_unit_dn = forced_host_organizational_unit_dn
        else:
            # force reset to None if config file is changed at runtime
            try:
                del(self.host_organizational_unit_dn)
            except:
                # error writing to db because of write access ?
                logger.warning('forced OU DN in local wapt db is not matching wapt-get.ini value')

        if self.config.has_option('global', 'packages_whitelist'):
            self.packages_whitelist = ensure_list(self.config.get('global', 'packages_whitelist'), allow_none=True)

        if self.config.has_option('global', 'packages_blacklist'):
            self.packages_blacklist = ensure_list(self.config.get('global', 'packages_blacklist'), allow_none=True)

        if self.config.has_option('global', 'host_profiles'):
            self._host_profiles = ensure_list(self.config.get('global', 'host_profiles'), allow_none=True)

        if self.config.has_option('global', 'locales'):
            self.locales = ensure_list(self.config.get('global', 'locales'), allow_none=True)

        if self.config.has_option('global', 'maturities'):
            self.maturities = ensure_list(self.config.get('global', 'maturities'), allow_none=True)
            if not self.maturities:
                self.maturities = ['PROD']

        if self.config.has_option('global', 'default_maturity'):
            self.default_maturity = self.config.get('global', 'default_maturity')

        if self.config.has_option('global', 'token_lifetime'):
            self.token_lifetime = self.config.getint('global', 'token_lifetime')

        if self.config.has_option('global', 'use_hostpackages'):
            self.use_hostpackages = self.config.getboolean('global', 'use_hostpackages')

        if self.config.has_option('global', 'use_ad_groups'):
            self.use_ad_groups = self.config.getboolean('global', 'use_ad_groups')

        if self.config.has_option('global', 'waptaudit_task_period'):
            self.waptaudit_task_period = self.config.get('global', 'waptaudit_task_period')

        self.waptwua_enabled = None
        if self.config.has_section('waptwua'):
            if self.config.has_option('waptwua', 'enabled'):
                self.waptwua_enabled = self.config.getboolean('waptwua', 'enabled')

        self.use_repo_rules = False
        if self.config.has_option('global', 'use_repo_rules'):
            self.use_repo_rules = self.config.getboolean('global', 'use_repo_rules')

        self.host_ad_site = None
        if self.config.has_option('global', 'host_ad_site'):
            self.host_ad_site = self.config.get('global', 'host_ad_site')

        self.editor_for_packages = None
        if self.config.has_option('global', 'editor_for_packages'):
            self.editor_for_packages = self.config.get('global', 'editor_for_packages')

        self.limit_bandwidth = None
        if self.config.has_option('global', 'limit_bandwidth'):
            self.limit_bandwidth = self.config.getfloat('global', 'limit_bandwidth')

        if self.config.has_option('global', 'redirect_stdout_to'):
            self.redirect_stdout_to = self.config.get('global', 'redirect_stdout_to')

        if self.config.has_option('global', 'custom_tags'):
            self.custom_tags = ensure_list(self.config.get('global', 'custom_tags'), allow_none=True)
        else:
            self.custom_tags = []

        if self.config.has_option('global', 'packages_cache_dir'):
            self.packages_cache_dir = self.config.get('global', 'packages_cache_dir')

        if self.config.has_option('global', 'wapt_temp_dir'):
            self.wapt_temp_dir = self.config.get('global', 'wapt_temp_dir')

        if self.config.has_option('global', 'include_dmi_inventory'):
            self.include_dmi_inventory = self.config.getboolean('global', 'include_dmi_inventory')

        if self.config.has_option('global', 'include_wmi_inventory'):
            self.include_wmi_inventory = self.config.getboolean('global', 'include_wmi_inventory')

        # clear host key cache
        self._host_key = None

        # clear host filter for packages
        self._packages_filter_for_host = None

        # keep the timestamp of last read config files to reload it if it is changed
        self.loaded_config_hash = self.get_config_hash()

        # backup in DB the merged hash
        if merge_config_packages and self.configs_dir and self.merged_config_hash != self.loaded_config_hash:
            self.merged_config_hash = self.loaded_config_hash

        return self

    def server_uuid(self):
        res = self.read_param('server_uuid')
        if not res and self.waptserver:
            res = self.waptserver.get('ping')['result']['uuid']
            if res:
                self.write_param('server_uuid',res)
        return res

    def is_enterprise(self):
        try:
            # get from database
            licences = self.read_param('licences')
            if licences is None:
                licences = self.update_licences()
            if licences:
                if not waptlicences:
                    return False
                waptlicences.check_valid_licences_count(jsondump(licences),self.server_uuid(),36000)
                return waptlicences.is_enterprise()
            else:
                return False
        except Exception as e:
            logger.warning('Unable to get licence status: %s' % e)
            return False

    @property
    def waptserver(self):
        if self._waptserver is None and self.config.has_option('global', 'wapt_server'):
            self._waptserver = WaptServer().load_config(self.config)
            self._waptserver.capture_external_ip_callback = self.save_external_ip
            self.set_client_cert_auth(self._waptserver)
        return self._waptserver

    @property
    def repositories(self):
        if self._repositories is None:
            # Get the configuration of all repositories (url, ...)
            # TODO : make this lazzy...
            self._repositories = []
            # secondary
            if self.config.has_section('global') and self.config.has_option('global', 'repositories'):
                repository_names = ensure_list(self.config.get('global', 'repositories'))
                logger.info('Other repositories : %s' % (repository_names,))
                for name in repository_names:
                    if name:
                        w = WaptRepo(name=name, WAPT=self, config=self.config, section=name)
                        self.set_client_cert_auth(w)
                        self._repositories.append(w)
                        logger.info('    %s:%s' % (w.name, w._repo_url))
            else:
                repository_names = []

            # last is main repository so it overrides the secondary repositories
            if self.config.has_option('global', 'repo_url') and not 'wapt' in repository_names:
                w = WaptRepo(name='wapt', WAPT=self, config=self.config)
                self._repositories.append(w)
                self.set_client_cert_auth(w)
                logger.info('Main repository: %s' % (w.repo_url,))

            if self.use_hostpackages:
                self.add_hosts_repo()

        return self._repositories

    @property
    def wua_repository(self):
        if self._wua_repository is None:
            for r in self.repositories:
                if r.name == 'waptwua':
                    self._wua_repository = r
                    break

            if self._wua_repository is None:
                self._wua_repository = WaptRepo(name='waptwua', WAPT=self, config=self.config)

                # Fix tls client auth
                self.set_client_cert_auth(self._wua_repository)

                # Fix verify_cert
                if self._wua_repository.verify_cert in [None,1,'1',True] and self.config.has_option('global','verify_cert'):
                    self._wua_repository.verify_cert = get_verify_cert(self.config.get('global','verify_cert'))

                # Fix proxies
                if not self._wua_repository.http_proxy and self.config.get('global','use_http_proxy_for_repo') and self.config.get('global','http_proxy') != '':
                    self._wua_repository.http_proxy = self.config.get('global','http_proxy')

            logger.info('WAPTWUA repository: %s' % (self._wua_repository.repo_url,))
        return self._wua_repository

    def write_config(self, config_filename=None):
        """Update configuration parameters to supplied inifilename
        """
        def _encode_ini_value(value, key=None):
            if isinstance(value, list):
                return ','.join(value)
            elif value is None:
                return ''
            elif isinstance(value,bool):
                if value:
                    return '1'
                else:
                    return '0'
            else:
                return str(value)

        for key in self.config.defaults():
            if hasattr(self, key) and _encode_ini_value(getattr(self, key)) != _encode_ini_value(self.config.defaults()[key]):
                logger.debug('update config global.%s : %s' % (key, getattr(self, key)))
                self.config.set('global', key, _encode_ini_value(getattr(self, key), key))
        repositories_names = ','.join([r.name for r in self.repositories if r.name not in ('global', 'wapt-host')])
        if self.config.has_option('global', 'repositories') and repositories_names != '':
            self.config.set('global', 'repositories', _encode_ini_value(repositories_names))

        if config_filename is None:
            config_filename = self.config_filename

        if config_filename is not None:
            with open(config_filename, 'w', encoding='utf8') as f:
                self.config.write(f)
            self.loaded_config_hash = self.get_config_hash()

    def _set_fake_hostname(self, fqdn):
        if sys.platform == 'win32':
            import setuphelpers_windows
            setuphelpers_windows._fake_hostname = fqdn
        else:
            setuphelpers._fake_hostname = fqdn
        logger.warning('Using test fake hostname and uuid: %s' % fqdn)
        self.use_fqdn_as_uuid = True
        logger.debug('Host uuid is now: %s' % self.host_uuid)
        logger.debug('Host computer_name is now: %s' % setuphelpers.get_computername())

    def get_token_secret_key(self) -> str:
        kfn = os.path.join(self.private_dir, 'token_secret_key')
        if not os.path.isfile(kfn):
            if not os.path.isdir(self.private_dir):
                os.makedirs(self.private_dir)
            result = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(64))
            with open(kfn, 'w') as f:
                f.write(result)
            return result
        else:
            with open(kfn, 'r') as f:
                return f.read()

    def add_hosts_repo(self) -> WaptHostRepo:
        """Add an automatic host repository, remove existing WaptHostRepo last one before"""
        # avoid calling getter as the getter is calling this method.
        while self._repositories and isinstance(self._repositories[-1], WaptHostRepo):
            del self._repositories[-1]

        if self.config.has_section('wapt-host'):
            section = 'wapt-host'
        else:
            section = None

        if (self.waptserver and self.waptserver.server_url) or section:
            try:
                # don't create key if not exist at this step
                host_key = self.get_host_key(False)
            except Exception as e:
                logger.debug('Unable to get or create host key: %s' % e)
                # unable to access or create host key
                host_key = None

            host_repo = WaptHostRepo(name='wapt-host', config=self.config, host_id=self.host_packagename(), host_key=host_key, WAPT=self)
            self._repositories.append(host_repo)

            # in case host repo is calculated from server url (no specific section) and main repor_url is set
            if section is None and self.waptserver and self.waptserver.server_url:
                host_repo.repo_url = self.waptserver.server_url+'/wapt-host'

            self.set_client_cert_auth(host_repo)

        else:
            host_repo = None

        return host_repo

    def reload_config_if_updated(self):
        """Check if config file has been updated,
        Return None if config has not changed or date of new config file if reloaded

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.reload_config_if_updated()

        """
        new_config_hash = self.get_config_hash()
        if new_config_hash != self.loaded_config_hash:
            tasks_logger.info('Reloading waptcore configuration for Wapt instance thread %s' % threading.get_ident())

            self.load_config(merge_config_packages = new_config_hash != self.merged_config_hash)
            return True
        else:
            return False

    @property
    def waptdb(self) -> WaptDB:
        """Wapt database"""
        if not self._waptdb:
            self._waptdb = WaptDB(dbpath=self.dbpath)
            if self._waptdb.db_version < self._waptdb.curr_db_version:
                logger.info('Upgrading db structure from %s to %s' % (self._waptdb.db_version, self._waptdb.curr_db_version))
                self._waptdb.upgradedb()
                # for backward compat
                self._waptdb.execute("""update wapt_localstatus set status_revision=(select cast(value as integer) from wapt_params where name='status_revision') where status_revision is null""")

        return self._waptdb

    @property
    def waptsessiondb(self) -> WaptSessionDB:
        """Wapt user session database"""
        if not self._waptsessiondb:
            self._waptsessiondb = WaptSessionDB(username=setuphelpers.get_current_user())
            if self._waptsessiondb.db_version < self._waptsessiondb.curr_db_version:
                logger.info('Upgrading db structure from %s to %s' % (self._waptsessiondb.db_version, self._waptsessiondb.curr_db_version))
                self._waptsessiondb.upgradedb()
        return self._waptsessiondb

    @property
    def runstatus(self) -> str:
        """returns the current run status for tray display"""
        return self.read_param('runstatus', '')

    @runstatus.setter
    def runstatus(self, waptstatus):
        """Stores in local db the current run status for tray display"""
        if self.runstatus != waptstatus:
            logger.info('Status : %s' % ensure_unicode(waptstatus))
            self.write_param('runstatus', waptstatus)

    def get_hardware_uuid(self):
        """Return '' if no hardware uuid can be found"""
        new_hardware_uuid = ''
        try:
            if waptlicences:
                new_hardware_uuid = waptlicences.get_bios_infos()['uuid']
                new_hardware_uuid = new_hardware_uuid.lower()
        except:
            pass

        if not new_hardware_uuid:
            try:
                if os.name == 'nt':
                    inv = setuphelpers.wmi_info_basic()
                    new_hardware_uuid = inv.get('System_Information',[{}])[0].get('UUID','').lower()
                    if not new_hardware_uuid:
                        inv = setuphelpers.dmi_info()
                        new_hardware_uuid = inv.get('System_Information',{}).get('UUID','').lower()
                else:
                    inv = setuphelpers.dmi_info()
                    new_hardware_uuid = inv.get('System_Information',{}).get('UUID','').lower()

                if not new_hardware_uuid or new_hardware_uuid in [u.lower() for u in bad_uuid] or (new_hardware_uuid and ' ' in new_hardware_uuid):
                    logger.info('UUID is a bad uuid' % new_hardware_uuid)
                    new_hardware_uuid = ''

            except:
                new_hardware_uuid = ''

        return new_hardware_uuid

    @property
    def host_uuid(self) -> str:
        previous_uuid = self.read_param('uuid') or None
        # we ignore changes of char case
        if self._host_uuid is None or previous_uuid is None or self._host_uuid.lower() != previous_uuid.lower():
            # hostname and hardware uuid last time uuid was set
            registered_hostname = self.read_param('hostname')
            registered_hardware_uuid = self.read_param('hardware_uuid',None)
            current_hostname = setuphelpers.get_hostname()
            new_hardware_uuid = self.get_hardware_uuid()
            if not new_hardware_uuid is None and registered_hardware_uuid is not None:
                new_hardware_uuid = registered_hardware_uuid


            # track changes case insensitive to handle old data
            if  (
                    registered_hostname is None or registered_hostname.lower() != current_hostname.lower() or
                    registered_hardware_uuid is None or registered_hardware_uuid.lower() != new_hardware_uuid.lower() or
                    (self.forced_uuid is not None and self.forced_uuid != previous_uuid) or
                    (self.use_fqdn_as_uuid and previous_uuid.lower() != current_hostname.lower()) or
                    previous_uuid is None
                ):
                try:
                    # calc the new uuid
                    new_uuid = None
                    # we take in account forced uuid
                    # forced uuid is for testing.
                    if self.forced_uuid:
                        new_uuid = self.forced_uuid.lower()
                    elif self.use_fqdn_as_uuid:
                        new_uuid = current_hostname.lower()

                    # we detect current host changes in case wapt has been cloned on another hardware.
                    if not new_uuid:
                        new_uuid = new_hardware_uuid

                    # preserve initial case to preserve backward compatibility
                    if previous_uuid and new_uuid and previous_uuid.lower() == new_uuid.lower():
                        new_uuid = previous_uuid

                    if not new_uuid:
                        new_uuid = self.generate_host_uuid()

                    self.write_param('uuid', new_uuid)
                    self.write_param('hostname', current_hostname)
                    self.write_param('hardware_uuid', new_hardware_uuid)
                except:
                    # no write access
                    pass
                self._host_uuid = new_uuid
            else:
                self._host_uuid = previous_uuid
        return self._host_uuid

    @host_uuid.setter
    def host_uuid(self, value):
        self._host_uuid= None
        self.write_param('uuid',value)
        self.write_param('hostname', setuphelpers.get_hostname())
        self.write_param('hardware_uuid', self.get_hardware_uuid())

    @host_uuid.deleter
    def host_uuid(self):
        self._host_uuid= None
        self.forced_uuid = None
        self.delete_param('uuid')

    def generate_host_uuid(self):
        """Regenerate a random UUID for this host or force with supplied one.

        Normally, the UUID is taken from BIOS through wmi.

        In case bios returns some duplicates or garbage, it can be useful to
        force a random uuid. This is stored as uuid key in wapt-get.ini.

        In case we want to link th host with a an existing record on server, we
        can force a old UUID.

        """
        auuid = ('rnd-%s' % str(uuid.uuid4())).lower()
        self.host_uuid = auuid
        return auuid

    def reset_host_uuid(self,new_uuid=None):
        """Reset host uuid to bios provided UUID.
        If it was forced in ini file, remove setting from ini file.
        """
        self.delete_param('uuid')
        self.delete_param('hardware_uuid')
        self.delete_param('hostname')
        self._host_uuid = None
        self.forced_uuid = None
        try:
            ini = RawConfigParser()
            ini.read(self.config_filename)
            if ini.has_option('global', 'uuid') or ini.has_option('default_global', 'uuid'):
                if ini.has_option('global', 'uuid'):
                    ini.remove_option('global', 'uuid')
                if ini.has_option('default_global', 'uuid'):
                    ini.remove_option('default_global', 'uuid')
                with open(self.config_filename, 'w') as f:
                    ini.write(f)
        except:
            pass
        if not new_uuid is None:
            self.host_uuid = new_uuid
        return self.host_uuid

    @property
    def host_organizational_unit_dn(self):
        """Get host org unit DN from wapt-get.ini [global] host_organizational_unit_dn if defined
        or from registry as supplied by AD / GPO process
        """

        host_organizational_unit_dn = self.read_param('host_organizational_unit_dn', None)
        if host_organizational_unit_dn:
            return host_organizational_unit_dn

        if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
            gpo_host_dn = self.get_cache_domain_info()['ou']
        else:
            gpo_host_dn = setuphelpers.registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine', 'Distinguished-Name')

        if gpo_host_dn:
            try:
                default_organizational_unit_dn = ','.join(gpo_host_dn.split(',')[1:])
            except:
                default_organizational_unit_dn = None
        else:
            default_organizational_unit_dn = None

        return default_organizational_unit_dn

    @host_organizational_unit_dn.setter
    def host_organizational_unit_dn(self, value):
        self.write_param('host_organizational_unit_dn', value)

    @host_organizational_unit_dn.deleter
    def host_organizational_unit_dn(self):
        self.delete_param('host_organizational_unit_dn')

    def reset_host_organizational_unit_dn(self):
        """Reset forced host_organizational_unit_dn to AD / GPO registry defaults.
        If it was forced in ini file, remove setting from ini file.
        """
        del(self.host_organizational_unit_dn)
        ini = RawConfigParser()
        ini.read(self.config_filename)
        if ini.has_option('global', 'host_organizational_unit_dn'):
            ini.remove_option('global', 'host_organizational_unit_dn')
            with open(self.config_filename, 'w') as f:
                ini.write(f)
                f.close()

        return self.host_dn

    @property
    def host_dn(self):
        result = 'CN=%s' % setuphelpers.get_computername().upper()
        org_unit = self.host_organizational_unit_dn
        if org_unit:
            result = result + ',' + org_unit
        return result

    @property
    def host_site(self):
        return self.get_host_site()

    def http_upload_package(self, packages, wapt_server_user=None, wapt_server_passwd=None, progress_hook=None):
        r"""Upload a package or host package to the waptserver.

        Args:
            packages (str or list): list of filepaths or PackageEntry to wapt packages to upload
            wapt_server_user (str)   : user for basic auth on waptserver
            wapt_server_passwd (str) : password for basic auth on waptserver

        Returns:


        >>> from common import *
        >>> wapt = Wapt(config_filename = r'C:\tranquilit\wapt\tests\wapt-get.ini')
        >>> r = wapt.update()
        >>> d = wapt.duplicate_package('tis-wapttest','toto')
        >>> print d
        {'target': u'c:\\users\\htouvet\\appdata\\local\\temp\\toto.wapt', 'package': PackageEntry('toto','119')}
        >>> wapt.http_upload_package(d['package'],wapt_server_user='admin',wapt_server_passwd='password')
        """
        if not isinstance(packages, list):
            packages = [packages]

        # force auth before trying to upload to avoid uncessary upload buffering server side before it send a 401.
        auth = None
        if wapt_server_user:
            auth = (ensure_unicode(wapt_server_user).encode('utf8'), ensure_unicode(wapt_server_passwd).encode('utf8'))
        else:
            auth = self.waptserver.ask_user_password('%s/%s' % (self.waptserver.server_url, 'api/v3/upload_xxx'))

        files = {}
        is_hosts = None

        def upload_progress_hook(filename, amount_seen, file_size):
            if progress_hook:
                return progress_hook(True, amount_seen, file_size, 'Uploading package %s' % filename)
            else:
                return False

        if not progress_hook:
            upload_progress_hook = None

        for package in packages:
            if not isinstance(package, PackageEntry):
                pe = PackageEntry(waptfile=package)
                package_filename = package
            else:
                pe = package
                package_filename = pe.localpath

            if is_hosts is None and pe.section == 'host':
                is_hosts = True

            if is_hosts:
                # small files
                with open(package_filename, 'rb') as f:
                    files[os.path.basename(package_filename)] = f.read()
            else:
                # stream
                #with open(package_filename,'rb') as f:
                    #files[os.path.basename(package_filename)] = f
                files[os.path.basename(package_filename)] = FileChunks(package_filename, progress_hook=upload_progress_hook)

        res = {}
        if not files:
            raise Exception('No package to upload')

        try:
            if is_hosts:
                logger.info('Uploading %s host packages' % len(files))
                # single shot
                res = self.waptserver.post('api/v3/upload_hosts', files=files, auth=auth, timeout=300, enable_capture_external_ip=False)

                if not res['success']:
                    raise Exception('Error when uploading host packages: %s' % (res['msg']))
            else:
                ok = []
                errors = []
                for (fn, f) in files.items():
                    res_partiel = self.waptserver.post('api/v3/upload_packages', data=f, auth=auth, timeout=300, enable_capture_external_ip=False)
                    if not res_partiel['success']:
                        errors.append(res_partiel)
                    else:
                        ok.append(res_partiel)
                res = {'success': len(errors) == 0, 'result': {'ok': ok, 'errors': errors}, 'msg': '%s Packages uploaded, %s errors' % (len(ok), len(errors))}
        #except requests.exceptions.HTTPError as e:
        #    logger.error('Error: couldn\'t upload package(s) {0}: server side error, error code : {1}, message : {2} '.format(packages, e.response.status_code, e.response.text))
        finally:
            for f in list(files.values()):
                if isinstance(f, FileChunks):
                    f.close()
        return res


    def upload_package(self, filenames, wapt_server_user=None, wapt_server_passwd=None):
        """Method to upload a package using Shell command (like scp) instead of http upload
            You must define first a command in inifile with the form :
                upload_cmd="c:\Program Files"\putty\pscp -v -l waptserver %(waptfile)s srvwapt:/var/www/%(waptdir)s/
            or
                upload_cmd="C:\Program Files\WinSCP\WinSCP.exe" root@wapt.tranquilit.local /upload %(waptfile)s
            You can define a "after_upload" shell command. Typical use is to update the Packages index
                after_upload="c:\Program Files"\putty\plink -v -l waptserver srvwapt.tranquilit.local "python /opt/wapt/wapt-scanpackages.py /var/www/%(waptdir)s/"
        """
        if self.upload_cmd:
            args = dict(filenames=" ".join('"%s"' % fn for fn in filenames),)
            return dict(status='OK', message=ensure_unicode(self.run(self.upload_cmd % args)))
        else:
            return self.http_upload_package(filenames, wapt_server_user=wapt_server_user, wapt_server_passwd=wapt_server_passwd)

    def check_install_running(self, max_ttl=60):
        """ Check if an install is in progress, return list of pids of install in progress
            Kill old stucked wapt-get processes/children and update db status
            max_ttl is maximum age of wapt-get in minutes
        """

        logger.debug('Checking if old install in progress')
        # kill old wapt-get
        mindate = time.time() - max_ttl*60

        killed = []
        for p in psutil.process_iter():
            try:
                if p.pid != os.getpid() and (p.create_time() < mindate) and p.name() in ('wapt-get', 'wapt-get.exe'):
                    logger.debug('Killing process tree of pid %i' % p.pid)
                    killtree(p.pid)
                    logger.debug('Killing pid %i' % p.pid)
                    killed.append(p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # reset install_status
        logger.debug('reset stalled install_status in database')
        init_run_pids = self.waptdb.query("""\
           select process_id from wapt_localstatus
              where install_status in ('INIT','RUNNING')
           """)

        all_pids = psutil.pids()
        reset_error = []
        result = []
        for rec in init_run_pids:
            # check if process is no more running
            if not rec['process_id'] in all_pids or rec['process_id'] in killed:
                reset_error.append(rec['process_id'])
            else:
                # install in progress
                result.append(rec['process_id'])

        if reset_error:
            with self.waptdb:
                self.waptdb.execute("""\
                      update wapt_localstatus
                        set install_status=coalesce('ERROR',install_status) where process_id in (?)
                    """, (','.join([str(p) for p in reset_error]),))

            self.runstatus = ''

        # return pids of install in progress
        return result

    @property
    def pre_shutdown_timeout(self):
        """get / set the pre shutdown timeout shutdown tasks.
        """
        if setuphelpers.reg_key_exists(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\gpsvc'):
            with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\gpsvc') as key:
                ms = int(setuphelpers.reg_getvalue(key, 'PreshutdownTimeout', 0))
                if ms:
                    return ms / (60*1000)
                else:
                    return None
        else:
            return None

    @pre_shutdown_timeout.setter
    def pre_shutdown_timeout(self, minutes):
        """Set PreshutdownTimeout"""
        if setuphelpers.reg_key_exists(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\gpsvc'):
            key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\gpsvc', sam=setuphelpers.KEY_WRITE)
            if not key:
                raise Exception('The PreshutdownTimeout can only be changed with System Account rights')
            setuphelpers.reg_setvalue(key, 'PreshutdownTimeout', minutes*60*1000, setuphelpers.REG_DWORD)

    @property
    def max_gpo_script_wait(self):
        """get / set the MaxGPOScriptWait.
        """
        with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') as key:
            ms = int(setuphelpers.reg_getvalue(key, 'MaxGPOScriptWait', 0))
            if ms:
                return ms / (60*1000)
            else:
                return None

    @max_gpo_script_wait.setter
    def max_gpo_script_wait(self, minutes):
        """Set MaxGPOScriptWait"""
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', sam=setuphelpers.KEY_WRITE)
        if not key:
            raise Exception('The MaxGPOScriptWait can only be changed with System Account rights')
        setuphelpers.reg_setvalue(key, 'MaxGPOScriptWait', minutes*60*1000, setuphelpers.REG_DWORD)

    @property
    def hiberboot_enabled(self):
        """get HiberbootEnabled.
        """
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Power')
        if not key:
            return None
        try:
            return winreg.QueryValueEx(key, 'HiberbootEnabled')[0]
        except:
            return None

    @hiberboot_enabled.setter
    def hiberboot_enabled(self, enabled):
        """Set HiberbootEnabled (0/1)"""
        key = setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Session Manager\Power', sam=setuphelpers.KEY_WRITE)
        if key:
            setuphelpers.reg_setvalue(key, 'HiberbootEnabled', 1 if enabled else 0, setuphelpers.REG_DWORD)

    def registry_uninstall_snapshot(self):
        """Return list of uninstall ID from registry
             launched before and after an installation to capture uninstallkey
        """
        result = []
        with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
            try:
                i = 0
                while True:
                    subkey = EnumKey(key, i)
                    result.append(subkey)
                    i += 1
            except WindowsError as e:
                # WindowsError: [Errno 259] No more data is available
                if e.winerror == 259:
                    pass
                else:
                    raise

        if platform.machine() == 'AMD64':
            with setuphelpers.reg_openkey_noredir(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall") as key:
                try:
                    i = 0
                    while True:
                        subkey = EnumKey(key, i)
                        result.append(subkey)
                        i += 1
                except WindowsError as e:
                    # WindowsError: [Errno 259] No more data is available
                    if e.winerror == 259:
                        pass
                    else:
                        raise
        return result

    def uninstall_cmd(self, guid):
        """return the (quiet) command stored in registry to uninstall a software given its registry key"""
        return setuphelpers.uninstall_cmd(guid)

    def set_local_password(self, user='admin', pwd='password'):
        """Set admin/password local auth for waptservice in ini file as a sha256 hex hash"""
        conf = RawConfigParser()
        conf.read(self.config_filename)
        conf.set('global', 'waptservice_user', user)
        conf.set('global', 'waptservice_password', hashlib.sha256(pwd.encode('utf8')).hexdigest())
        with open(self.config_filename, 'w',encoding='utf8') as f:
            conf.write(f)

    def reset_local_password(self):
        """Remove the local waptservice auth from ini file"""
        conf = RawConfigParser()
        conf.read(self.config_filename)
        if conf.has_option('global', 'waptservice_user'):
            conf.remove_option('global', 'waptservice_user')
        if conf.has_option('global', 'waptservice_password'):
            conf.remove_option('global', 'waptservice_password')
        with open(self.config_filename, 'w', encoding='utf8') as f:
            conf.write(f)

    def check_cancelled(self, msg='Task cancelled'):
        if self.task_is_cancelled.is_set():
            raise EWaptCancelled(msg)

    def run(self, *arg, **args):
        if platform.system() == 'Windows':
            return ensure_unicode(run(*arg, pidlist=self.pidlist,**args))
        return ensure_unicode(run(*arg, **args))

    def run_notfatal(self, *cmd, **args):
        """Runs the command and wait for it termination
        returns output, don't raise exception if exitcode is not null but return '' """
        try:
            return self.run(*cmd, accept_returncodes=None, **args)
        except Exception as e:
            return ensure_unicode(e)

    def install_wapt(self, fname, params_dict={}, explicit_by=None, force=None):
        """Install a single wapt package given its WAPT filename.
        return install status

        Args:
            fname (str): Path to wapt Zip file or unzipped development directory
            params (dict): custom parameters for the install function
            explicit_by (str): identify who has initiated the install

        Returns:
            str:  'OK','ERROR'

        Raises:

            EWaptMissingCertificate
            EWaptNeedsNewerAgent
            EWaptUnavailablePackage
            EWaptConflictingPackage
            EWaptBadPackageAttribute
            EWaptException
            various Exception depending on setup script
        """
        install_id = None
        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        self.check_cancelled('Install of %s cancelled before starting up' % ensure_unicode(fname))
        logger.info("Register start of install %s as user %s to local DB with params %s" % (ensure_unicode(fname), setuphelpers.get_current_user(), params_dict))
        logger.info("Interactive user:%s, usergroups %s" % (self.user, self.usergroups))

        #if sys.platform == 'win32':
        #    previous_uninstall = self.registry_uninstall_snapshot()

        try:
            if not self.cabundle:
                raise EWaptMissingCertificate('install_wapt %s: No public Key provided for package signature checking.' % (fname,))

            entry = PackageEntry(waptfile=fname)
            if not entry.package_uuid:
                entry.make_uuid()
                logger.info('No uuid, generating package uuid on the fly: %s' % entry.package_uuid)
            self.runstatus = "Installing package %s version %s ..." % (entry.package, entry.version)

            params = self.get_previous_package_params(entry)
            params.update(params_dict)

            install_id = self.waptdb.add_start_install(
                entry,
                params_dict=params,
                explicit_by=explicit_by,
            )

            # we setup a redirection of stdout to catch print output from install scripts
            with WaptPackageInstallLogger(sys.stderr, wapt_context=self, install_id=install_id, user=self.user, exit_status=None) as dblogger:
                if entry.min_wapt_version and Version(entry.min_wapt_version) > Version(__version__):
                    raise EWaptNeedsNewerAgent('This package requires a newer Wapt agent. Minimum version: %s' % entry.min_wapt_version)

                depends = ensure_list(entry.depends)
                conflicts = ensure_list(entry.conflicts)

                missing_depends = [p for p in depends if not self.is_installed(p)]
                installed_conflicts = [p for p in conflicts if self.is_installed(p)]

                if missing_depends:
                    raise EWaptUnavailablePackage('Missing dependencies: %s' % (','.join(missing_depends,)))

                if installed_conflicts:
                    raise EWaptConflictingPackage('Conflicting packages installed: %s' % (','.join(installed_conflicts,)))

                free_disk_space = setuphelpers.get_disk_free_space(os.path.abspath(os.path.join(self.config_filename, os.pardir)))
                if entry.installed_size and free_disk_space < entry.installed_size :
                    raise EWaptDiskSpace('This package requires at least %s free space. Your drive where WAPT is installed has only %s free space' %
                                         (format_bytes(entry.installed_size), format_bytes(free_disk_space)))

                entry.check_package_attributes()

                errors = []
                if not self.host_capabilities().is_matching_package(entry, errors_list=errors):
                    raise EWaptBadPackageAttribute('This package have an attribute in the control file incompatible with your host capabilities: \n%s' % ",".join(errors))

                # don't check in developper mode
                if os.path.isfile(fname):
                    cert = entry.check_control_signature(self.cabundle)
                    logger.info('Control data for package %s verified by certificate %s' % (setuphelpers.ensure_unicode(fname), cert))
                else:
                    logger.info('Developper mode, don''t check control signature for %s' % setuphelpers.ensure_unicode(fname))

                self.check_cancelled()

                logger.info("Installing package %s" % (ensure_unicode(fname),))
                # case where fname is a wapt zipped file, else directory (during developement)
                istemporary = False

                if os.path.isfile(fname):
                    # check signature and files when unzipping
                    packagetempdir = entry.unzip_package(cabundle=self.cabundle, target_dir = tempfile.mkdtemp(prefix='wapt',dir=self.wapt_temp_dir))
                    istemporary = True
                elif os.path.isdir(fname):
                    packagetempdir = fname
                else:
                    raise EWaptNotAPackage('%s is not a file nor a directory, aborting.' % ensure_unicode(fname))

                try:
                    previous_cwd = os.getcwd()
                    self.check_cancelled()

                    exitstatus = None
                    new_uninstall_key = None
                    uninstallstring = None

                    persistent_source_dir = os.path.join(packagetempdir, 'WAPT', 'persistent')

                    if entry.package_uuid:
                        persistent_dir = os.path.join(self.persistent_root_dir, entry.package_uuid)

                        if os.path.isdir(persistent_dir):
                            logger.debug('Removing existing persistent dir %s' % persistent_dir)
                            shutil.rmtree(persistent_dir, ignore_errors=False)

                        # install persistent files
                        if os.path.isdir(persistent_source_dir):
                            logger.info('Copy persistent package data to %s' % persistent_dir)
                            shutil.copytree(persistent_source_dir, persistent_dir)
                        else:
                            # create always
                            os.makedirs(persistent_dir)

                    else:
                        persistent_dir = persistent_source_dir

                    setup_filename = os.path.join(packagetempdir, 'setup.py')

                    # take in account the case we have no setup.py
                    if os.path.isfile(setup_filename):
                        os.chdir(os.path.dirname(setup_filename))
                        if not os.getcwd() in sys.path:
                            sys.path.append(os.getcwd())

                        # import the setup module from package file
                        logger.info("  sourcing install file %s " % ensure_unicode(setup_filename))
                        setup = import_setup(setup_filename)
                        required_params = []

                        # be sure some minimal functions are available in setup module at install step
                        setattr(setup, 'basedir', os.path.dirname(setup_filename))
                        # redefine run to add reference to wapt.pidlist
                        setattr(setup, 'run', self.run)
                        setattr(setup, 'run_notfatal', self.run_notfatal)

                        if not hasattr(setup, 'uninstallkey'):
                            setup.uninstallkey = []

                        # to set some contextual default arguments
                        def with_install_context(func, impacted_process=None, uninstallkeylist=None, force=None, pidlist=None):
                            def new_func(*args, **kwargs):
                                if impacted_process and not 'killbefore' in kwargs:
                                    kwargs['killbefore'] = ensure_list(impacted_process)
                                if uninstallkeylist is not None and not 'uninstallkeylist' in kwargs:
                                    kwargs['uninstallkeylist'] = uninstallkeylist
                                if force is not None and not 'force' in kwargs:
                                    kwargs['force'] = force
                                if pidlist is not None and not 'pidlist' in kwargs:
                                    kwargs['pidlist'] = pidlist
                                return func(*args, **kwargs)
                            return new_func

                        if sys.platform == 'win32':
                            setattr(setup, 'install_msi_if_needed', with_install_context(
                                    setuphelpers.install_msi_if_needed,
                                    impacted_process=ensure_list(entry.impacted_process),
                                    uninstallkeylist=setup.uninstallkey,
                                    force=force,
                                    pidlist=self.pidlist))
                            setattr(setup, 'install_exe_if_needed', with_install_context(
                                    setuphelpers.install_exe_if_needed,
                                    impacted_process=ensure_list(entry.impacted_process),
                                    uninstallkeylist=setup.uninstallkey,
                                    force=force,
                                    pidlist=self.pidlist))

                        if sys.platform == 'darwin':
                            setattr(setup, 'install_dmg', with_install_context(setuphelpers.install_dmg,
                                impacted_process=ensure_list(entry.impacted_process),
                                uninstallkeylist=setup.uninstallkey,
                                force=force))
                            setattr(setup, 'install_pkg', with_install_context(setuphelpers.install_pkg,
                                impacted_process=ensure_list(entry.impacted_process),
                                uninstallkeylist=setup.uninstallkey,
                                force=force))
                            setattr(setup, 'install_app', with_install_context(setuphelpers.install_app,
                                impacted_process=ensure_list(entry.impacted_process),
                                uninstallkeylist=setup.uninstallkey,
                                force=force))


                        setattr(setup, 'WAPT', self)
                        setattr(setup, 'control', entry)
                        setattr(setup, 'language', self.language)
                        setattr(setup, 'force', force)

                        setattr(setup, 'user', explicit_by or self.user)
                        setattr(setup, 'usergroups', self.usergroups)

                        setattr(setup, 'persistent_source_dir', persistent_source_dir)
                        setattr(setup, 'persistent_dir', persistent_dir)

                        # get definitions of required parameters from setup module
                        if hasattr(setup, 'required_params'):
                            required_params = setup.required_params

                        # get value of required parameters if not already supplied
                        for p in required_params:
                            if not p in params:
                                if not is_system_user():
                                    params[p] = input("%s: " % p)
                                else:
                                    raise EWaptException('Required parameters %s is not supplied' % p)
                        logger.info('Install parameters : %s' % (params,))

                        # set params dictionary
                        if not hasattr(setup, 'params'):
                            # create a params variable for the setup module
                            setattr(setup, 'params', params)
                        else:
                            # update the already created params with additional params from command line
                            setup.params.update(params)

                        # store source of install and params in DB for future use (upgrade, session_setup, uninstall)
                        self.waptdb.store_setuppy(install_id, setuppy=codecs.open(setup_filename, 'r', encoding='utf-8').read(), install_params=params)

                        with _disable_file_system_redirection():
                            try:
                                logger.info("  executing install script")
                                exitstatus = setup.install()
                            except Exception as e:
                                logger.critical('Fatal error in install script: %s:\n%s' % (ensure_unicode(e), ensure_unicode(traceback.format_exc())))
                                raise

                        if exitstatus is None or exitstatus == 0:
                            dblogger.exit_status = 'OK'
                        else:
                            dblogger.exit_status = exitstatus

                        if sys.platform == 'win32':
                            # get uninstallkey from setup module (string or array of strings)
                            if hasattr(setup, 'uninstallkey'):
                                new_uninstall_key = ensure_list(setup.uninstallkey)[:]
                                # check that uninstallkey(s) are in registry
                                key_errors = []
                                for key in new_uninstall_key:
                                    if not setuphelpers.uninstall_key_exists(uninstallkey=key):
                                        key_errors.append(key)
                                if key_errors:
                                    if len(key_errors) > 1:
                                        raise EWaptException('The uninstall keys: \n%s\n have not been found in system registry after softwares installation.' % ('\n'.join(key_errors),))
                                    else:
                                        raise EWaptException('The uninstall key: %s has not been found in system registry after software installation.' % (' '.join(key_errors),))

                        else:
                            if sys.platform == 'darwin':
                                if hasattr(setup, 'uninstallkey'):

                                    new_uninstall_key = ensure_list(setup.uninstallkey)[:]
                                    key_errors = []
                                    for key in new_uninstall_key:
                                        if not setuphelpers.uninstall_key_exists(key):
                                            key_errors.append(key)
                                    if key_errors :
                                        if len(key_errors) > 1:
                                            raise EWaptException('The uninstall keys: \n%s\n have not been found in system after softwares installation.' % ('\n'.join(key_errors),))
                                        else:
                                            raise EWaptException('The uninstall key: %s has not been found in system after software installation.' % (' '.join(key_errors),))
                            else:
                                new_uninstall_key = []

                        # get uninstallstring from setup module (string or array of strings)
                        if hasattr(setup, 'uninstallstring'):
                            uninstallstring = setup.uninstallstring[:]
                        else:
                            uninstallstring = None

                        logger.info('  uninstall keys : %s' % (new_uninstall_key,))
                        logger.info('  uninstall strings : %s' % (uninstallstring,))

                        logger.info("Install script finished with status %s" % dblogger.exit_status)
                    else:
                        logger.info('No setup.py')
                        dblogger.exit_status = 'OK'

                    if entry.package_uuid:
                        for row in self.waptdb.query('select persistent_dir from wapt_localstatus l where l.package=? and l.package_uuid<>?', (entry.package, entry.package_uuid)):
                            if row['persistent_dir'] and os.path.isdir(os.path.abspath(row['persistent_dir'])):
                                logger.info('Cleanup of previous versions of %s  persistent dir: %s' % (entry.package, row['persistent_dir']))
                                shutil.rmtree(os.path.abspath(row['persistent_dir']))

                    self.waptdb.update_install_status(install_id,
                                                      uninstall_key=jsondump(new_uninstall_key), persistent_dir=persistent_dir)

                finally:
                    if istemporary:
                        os.chdir(previous_cwd)
                        logger.debug("Cleaning package tmp dir")
                        # trying 3 times to remove
                        cnt = 3
                        while cnt > 0:
                            try:
                                shutil.rmtree(packagetempdir)
                                break
                            except Exception as e:
                                cnt -= 1
                                time.sleep(2)
                                logger.warning(e)
                        else:
                            logger.error("Unable to clean tmp dir")

            # end
            return self.waptdb.install_status(install_id)

        except Exception as e:
            if install_id:
                try:
                    self.waptdb.update_install_status(install_id, set_status='ERROR', append_line=ensure_unicode(e))
                except Exception as e2:
                    logger.critical(ensure_unicode(e2))
            else:
                logger.critical(ensure_unicode(e))
            raise e

        finally:
            gc.collect()
            if 'setup' in dir() and setup is not None:
                setup_name = setup.__name__[:]
                logger.debug('Removing module: %s, refcnt: %s' % (setup_name, sys.getrefcount(setup)))
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]

            sys.path = oldpath
            self.store_upgrade_status()
            self.runstatus = ''

    def running_tasks(self):
        """return current install tasks"""
        running = self.waptdb.query_package_entry("""\
           select * from wapt_localstatus
              where install_status in ('INIT','DOWNLOAD','RUNNING')
           """)
        return running

    def error_packages(self):
        """return install tasks with error status"""
        q = self.waptdb.query_package_entry("""\
           select * from wapt_localstatus
              where install_status in ('ERROR')
           """)
        return q

    def store_upgrade_status(self, upgrades=None):
        """Stores in DB the current pending upgrades and running installs for
          query by waptservice"""
        try:
            status = {
                "running_tasks": ["%s : %s" % (p.asrequirement(), p.install_status) for p in self.running_tasks()],
                "errors": ["%s" % p.asrequirement() for p in self.error_packages()],
                "date": datetime2isodate(),
            }
            if upgrades is None:
                upgrades = self.list_upgrade()

            status["upgrades"] = upgrades['upgrade']+upgrades['install']+upgrades['additional']
            status["pending"] = upgrades
            logger.debug("store status in DB")
            self.write_param('last_update_status', status)
            return status
        except Exception as e:
            logger.critical('Unable to store status of update in DB : %s' % ensure_unicode(e))
            if logger.level == logging.DEBUG:
                raise

    def read_upgrade_status(self):
        """Return last stored pending updates status

        Returns:
            dict: {running_tasks errors pending (dict) upgrades (list)}

        """
        return self.read_param('last_update_status', ptype='json')

    def get_sources(self, package):
        """Download sources of package (if referenced in package as a https svn)
        in the current directory

        Args:
            package (str or PackageRequest): package to get sources for

        Returns:
            str : checkout directory path

        """
        sources_url = None
        entry = None
        entries = self.waptdb.packages_matching(package)
        if entries:
            entry = entries[-1]
            if entry.sources:
                sources_url = entry.sources
        if not sources_url:
            if self.config.has_option('global', 'default_sources_url'):
                sources_url = self.config.get('global', 'default_sources_url') % {'packagename': package}

        if not sources_url:
            raise Exception('No sources defined in package control file and no default_sources_url in config file')
        if "PROGRAMW6432" in os.environ:
            svncmd = os.path.join(os.environ['PROGRAMW6432'], 'TortoiseSVN', 'bin', 'svn.exe')
        else:
            svncmd = os.path.join(os.environ['PROGRAMFILES'], 'TortoiseSVN', 'bin', 'svn.exe')
        logger.debug('svn command : %s' % svncmd)
        if not os.path.isfile(svncmd):
            raise Exception('svn.exe command not available, please install TortoiseSVN with commandline tools')

        # checkout directory
        if entry:
            co_dir = self.get_default_development_dir(entry.package, section=entry.section)
        else:
            co_dir = self.get_default_development_dir(package)

        logger.info('sources : %s' % sources_url)
        logger.info('checkout dir : %s' % co_dir)
        # if already checked out...
        if os.path.isdir(os.path.join(co_dir, '.svn')):
            print((self.run('"%s" up "%s"' % (svncmd, co_dir))))
        else:
            print((self.run('"%s" co "%s" "%s"' % (svncmd, sources_url, co_dir))))
        return co_dir

    def last_install_log(self, packagename):
        r"""Get the printed output of the last install of package named packagename

        Args:
            packagename (str): name of package to query
        Returns:
            dict: {status,log} of the last install of a package

        >>> w = Wapt()
        >>> w.last_install_log('tis-7zip')
        ???
        {'install_status': u'OK', 'install_output': u'Installing 7-Zip 9.38.0-1\n7-Zip already installed, skipping msi install\n',install_params: ''}

        """
        q = self.waptdb.query("""\
           select   rowid,package,version,architecture,maturity,locale,install_status,
                    install_output,install_params,explicit_by,uninstall_key,install_date,
                    last_audit_status,last_audit_on,last_audit_output,next_audit_on,package_uuid
           from wapt_localstatus
           where package=? order by install_date desc limit 1
           """, (packagename,))
        if not q:
            raise Exception("Package %s not found in local DB status" % packagename)
        return q[0]

    def cleanup(self, obsolete_only=False):
        """Remove cached WAPT files from local disk

        Args:
           obsolete_only (boolean):  If True, remove packages which are either no more available,
                                     or installed at a equal or newer version

        Returns:
            list: list of filenames of removed packages

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> l = wapt.download_packages(wapt.check_downloads())
        >>> res = wapt.cleanup(True)
        """
        result = []
        logger.info('Cleaning up WAPT cache directory')
        cachepath = self.packages_cache_dir

        upgrade_actions = self.list_upgrade()
        futures = upgrade_actions['install'] +\
            upgrade_actions['upgrade'] +\
            upgrade_actions['additional']

        def in_futures(pe):
            for p in futures:
                if pe.match(p):
                    return True
            return False

        for f in glob.glob(os.path.join(cachepath, '*.wapt')):
            if os.path.isfile(f):
                can_remove = True
                if obsolete_only:
                    try:
                        # check if cached package could be installed at next ugrade
                        pe = PackageEntry().load_control_from_wapt(f)
                        pe_installed = self.is_installed(pe.package)
                        can_remove = not in_futures(pe) and ((pe_installed and pe <= pe_installed) or not self.is_available(pe.asrequirement()))
                    except:
                        # if error... control file in wapt file is corrupted.
                        continue
                if can_remove:
                    logger.debug('Removing %s' % f)
                    try:
                        os.remove(f)
                        result.append(f)
                    except Exception as e:
                        logger.warning('Unable to remove %s : %s' % (f, ensure_unicode(e)))
        return result

    def _update_db(self, repo, force=False, current_datetime=None):
        """Get Packages from http repo and update local package database
        return last-update header

        The local status DB is updated. Date of index is stored in params table
        for further checks.

        Args:
            force (bool): get index from remote repo even if creation date is not newer
                          than the datetime stored in local status database
            waptdb (WaptDB): instance of Wapt status database.
            current_datetime (str): iso current datetime for package date filters (valid_from, valid_until)

        Returns:
            isodatetime: date of Packages index

        >>> import common
        >>> repo = common.WaptRepo('wapt','http://wapt/wapt')
        >>> localdb = common.WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> last_update = repo.is_available()
        >>> repo.update_db(waptdb=localdb) == last_update
        True
        """

        last_modified = self.waptdb.get_param('last-packages_date-%s' % (repo.name))

        # Check if updated
        #  next_update_is_forced by previous update if there was some valid_from, valid_until, force_install in future
        if force or self.waptdb.get_param('next_update_is_forced-%s' % repo.name) or repo.need_update(last_modified):
            old_status = repo.invalidate_packages_cache()
            discarded = []

            self._packages_filter_for_host = None

            if self.filter_on_host_cap:
                host_capabilities = self.host_capabilities()
            else:
                host_capabilities = None

            with self.waptdb:
                try:
                    logger.info('Read Packages index file for repo %s' % repo.name)
                    last_modified = repo.packages_date()
                    if not current_datetime:
                        current_datetime = datetime2isodate()

                    self.waptdb.purge_repo(repo.name)
                    repo_packages = repo.packages()
                    discarded.extend(repo.discarded)

                    next_update_on = '9999-12-31'
                    next_update_is_forced = False
                    for package in repo_packages:
                        # if there are time related restriction, we should check again at that time in the future.
                        if package.valid_from and package.valid_from > current_datetime:
                            next_update_on = min(next_update_on, package.valid_from)
                            next_update_is_forced = True
                        if package.valid_until and package.valid_until > current_datetime:
                            next_update_on = min(next_update_on, package.valid_until)
                            next_update_is_forced = True
                        if package.forced_install_on and package.forced_install_on > current_datetime:
                            next_update_on = min(next_update_on, package.forced_install_on)
                            next_update_is_forced = True

                        if self.filter_on_host_cap:
                            if not host_capabilities.is_matching_package(package, current_datetime):
                                discarded.append(package)
                                continue
                        try:
                            self.waptdb.add_package_entry(package, self.language)
                        except Exception as e:
                            logger.critical('Error adding entry %s to local DB for repo %s : discarding : %s' % (package.asrequirement(), repo.name, e))
                            discarded.append(package)

                    self.waptdb.set_param('last-packages_date-%s' % repo.name, repo.packages_date())
                    self.waptdb.set_param('next-update-%s' % repo.name, next_update_on)
                    self.waptdb.set_param('next_update_is_forced-%s' % repo.name, next_update_is_forced)
                    self.waptdb.set_param('last-discarded-count-%s' % repo.name, len(discarded))

                    return (last_modified, next_update_on,len(discarded))
                except Exception as e:
                    logger.info('Unable to update repository status of %s, error %s' % (repo._repo_url, e))
                    # put back cached status data
                    for (k, v) in old_status.items():
                        setattr(repo, k, v)
                    raise
        else:
            return (self.waptdb.get_param('last-packages_date-%s' % repo.name),
                    self.waptdb.get_param('next-update-%s' % repo.name, '9999-12-31'),
                    self.waptdb.get_param('last-discarded-count-%s' % repo.name,0)
                    )


    def get_host_locales(self):
        return ensure_list(self.locales)

    def get_host_site(self):
        if self.host_ad_site:
            return self.host_ad_site
        if sys.platform == 'win32':
            return setuphelpers.registry_readstring(setuphelpers.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine', 'Site-Name')
        else:
            return self.get_cache_domain_info()['site']
        return None

    def get_host_certificate_fingerprint(self):
        result = self.read_param('host_certificate_fingerprint')
        if result is None:
            result = self.get_host_certificate().fingerprint
            self.write_param('host_certificate_fingerprint', result)
        return result

    def get_host_certificate_authority_key_identifier(self):
        result = self.read_param('host_certificate_authority_key_identifier')
        if result is None:
            result = codecs.encode(self.get_host_certificate().authority_key_identifier or b'', 'hex').decode('ascii')
            self.write_param('host_certificate_authority_key_identifier', result)
        return result

    def host_capabilities(self):
        """Return the current capabilities of host taken in account to determine packages list and whether update should be forced (when filter criteria are updated)
        This includes host certificate,architecture,locale,authorized certificates

        Returns:
            dict
        """
        # be sure to copy and not only reference...
        tags = self.custom_tags[:]

        if platform.system() == 'Linux':
            tags += [(setuphelpers.get_distrib_linux()+'-'+setuphelpers.get_code_name_version()).lower(), setuphelpers.get_distrib_linux().lower(), setuphelpers.get_distrib_linux().lower()+setuphelpers.get_distrib_version().split('.')[0], setuphelpers.get_distrib_linux().lower()+'-'+setuphelpers.get_distrib_version().split('.')[0]]
            if setuphelpers.is_debian_based():
                tags += ['debian_based']
            elif setuphelpers.is_rhel_based():
                tags += ['rhel_based', 'redhat_based']
            tags += ['linux', 'unix']
            os_name = setuphelpers.get_distrib_linux()
        elif platform.system() == 'Darwin':
            tags += ['macos', 'mac', 'darwin', 'unix']
            release_name = setuphelpers.get_release_name()
            if release_name:
                tags += [release_name]
            os_name = "macos"
        elif platform.system() == 'Windows':
            tags += [('windows' + '-' + platform.release()).lower(), ('win' + '-' + platform.release()).lower(), ('w' + '-' + platform.release()).lower(), ('windows' + platform.release()).lower(), ('win' + platform.release()).lower(), ('w' + platform.release()).lower(), 'windows', 'win', 'w']
            os_name = "windows"

        return HostCapabilities(
            uuid=self.host_uuid,
            language=self.language,
            os=os_name,
            tags=tags,
            os_version=setuphelpers.get_os_version(),
            kernel_version=setuphelpers.get_kernel_version() if os.name != 'nt' else None,
            architecture=setuphelpers.get_host_architecture(),
            dn=self.host_dn,
            fqdn=setuphelpers.get_hostname(),
            site=self.get_host_site(),
            wapt_version=Version(__version__, 3),
            wapt_edition=self.get_wapt_edition(),
            packages_trusted_ca_fingerprints=[c.fingerprint for c in self.authorized_certificates()],
            packages_blacklist=self.packages_blacklist,
            packages_whitelist=self.packages_whitelist,
            packages_locales=self.locales,
            packages_maturities=self.maturities,
            use_hostpackages=self.use_hostpackages,
            host_profiles=self.host_profiles,
            host_certificate_fingerprint=self.get_host_certificate_fingerprint(),
            host_certificate_authority_key_identifier=self.get_host_certificate_authority_key_identifier(),
            host_packages_names=self.get_host_packages_names(),
        )

    def packages_filter_for_host(self):
        """Returns a PackageRequest object based on host capabilities to filter applicable packages from a repo

        Returns:
            PackageRequest
        """
        if self._packages_filter_for_host is None:
            self._packages_filter_for_host = self.host_capabilities().get_package_request_filter()
        return self._packages_filter_for_host

    def get_wapt_edition(self):
        return 'enterprise' if self.is_enterprise() else 'discovery'

    def host_capabilities_fingerprint(self):
        """Return a fingerprint representing the current capabilities of host
        This includes host certificate,architecture,locale,authorized certificates

        Returns:
            str

        """
        return self.host_capabilities().fingerprint()

    def is_locally_allowed_package(self, package):
        """Return True if package is not in blacklist and is in whitelist if whitelist is not None
        packages_whitelist and packages_blacklist are list of package name wildcards (file style wildcards)
        blacklist is taken in account first if defined.
        whitelist is taken in acoount if not None, else all not blacklisted package names are allowed.
        """
        if self.packages_blacklist is not None:
            for bl in self.packages_blacklist:
                if glob.fnmatch.fnmatch(package.package, bl):
                    return False
        if self.packages_whitelist is None:
            return True
        else:
            for wl in self.packages_whitelist:
                if glob.fnmatch.fnmatch(package.package, wl):
                    return True
        return False

    def _update_repos_list(self, force=False, current_datetime=None):
        """update the packages database with Packages files from the Wapt repos list
        removes obsolete records for repositories which are no more referenced

        Args:
            force : update repository even if date of packages index is same as
                    last retrieved date

        Returns:
            dict:   update_db results for each repository name
                    which has been accessed.

        >>> wapt = Wapt(config_filename = 'c:/tranquilit/wapt/tests/wapt-get.ini' )
        >>> res = wapt._update_repos_list()
        {'wapt': '2018-02-13T11:22:00', 'wapt-host': u'2018-02-09T10:55:04'}
        """
        if self.filter_on_host_cap:
            # force update if host capabilities have changed and requires a new filering of packages
            new_capa = self.host_capabilities_fingerprint()
            old_capa = self.read_param('host_capabilities_fingerprint')
            if not force and old_capa != new_capa:
                logger.info('Host capabilities have changed since last update, forcing update')
                force = True

        with self.waptdb:
            result = {}
            logger.debug('Remove unknown repositories from packages table and params (%s)' % (','.join('"%s"' % r.name for r in self.repositories),))
            obsolete = self.waptdb.query('select count(*) as cnt from wapt_package where repo not in (%s) or repo is null' % (','.join('"%s"' % r.name for r in self.repositories)))
            if obsolete and obsolete[0]['cnt']:
                self.waptdb.execute('delete from wapt_package where repo not in (%s)  or repo is null' % (','.join('"%s"' % r.name for r in self.repositories)))
            obsolete = self.waptdb.query('select count(*) as cnt from wapt_params where name like "last-url-%%" and name not in (%s)' % (','.join('"last-url-%s"' % r.name for r in self.repositories)))
            if obsolete and obsolete[0]['cnt']:
                self.waptdb.execute('delete from wapt_params where name like "last-url-%%" and name not in (%s)' % (','.join('"last-url-%s"' % r.name for r in self.repositories)))

            # to check the next time we should update the local repositories
            next_update_on = '9999-12-31'

            if not current_datetime:
                current_datetime = datetime2isodate()

            total_discarded = 0
            for repo in self.repositories:
                try:
                    (result[repo.name], repo_next_update_on, discarded) = self._update_db(repo, force=force, current_datetime=current_datetime)
                    total_discarded += discarded
                    next_update_on = min(next_update_on, repo_next_update_on)
                except Exception as e:
                    logger.critical('Error merging Packages from %s into db: %s' % (repo.name, ensure_unicode(e)))
            if self.filter_on_host_cap:
                self.write_param('host_capabilities_fingerprint', new_capa)
                self.write_param('last_update_config_fingerprint', self.merged_config_hash )
            self.write_param('next_update_on', next_update_on)
            self.waptdb.set_param('last-discarded-count', total_discarded)
        return result

    def update_repo_rules(self, force=False):
        if self.waptserver:
            try:
                rules = self.waptserver.get('rules.json', enable_password_callback=False)
                new_rules_hash = sha256_for_data(json.dumps(rules, sort_keys=True))
                old_rules_hash = self.read_param('repo_rules_sha256-wapt')
                if force or (new_rules_hash != old_rules_hash):
                    rules_verified = []
                    for rule in rules:
                        try:
                            signer_cert_chain = get_cert_chain_from_pem(rule['signer_certificate'])
                            chain = self.cabundle.check_certificates_chain(signer_cert_chain)
                            rule['verified_by'] = chain[0].verify_claim(rule, required_attributes=rule['signed_attributes'])
                            rules_verified.append(rule)
                            rule['active_rule'] = False
                        except:
                            logger.debug('Cert is not trusted or bad signature for : \n%s' % (rule))
                    self.write_param('repo_rules-wapt', rules_verified)
                    self.write_param('repo_rules_sha256-wapt', new_rules_hash)
                    for repo in self._repositories:
                        repo.reset_network()
                    self.wua_repository.reset_network()
                    return True
                else:
                    return False
            except:
                return False

    def update_licences(self,force=False):
        try:
            if self.waptserver:
                licences = self.waptserver.get('licences.json', enable_password_callback=False)
                self.write_param('licences',licences)
                return licences
            else:
                return None
        except:
            return None

    def update(self, force=False, register=True):
        """Update local database with packages definition from repositories

        Args:
            force (boolean):    update even if Packages index on repository has not been
                                updated since last update (based on http headers)
            register (boolean): Send informations about status of local packages to waptserver
        .. versionadded 1.3.10::
            filter_on_host_cap (boolean) : restrict list of retrieved packages to those matching current os / architecture

        Returns;
            list of (host package entry,entry date on server)

        Returns:
            dict: {"added","removed","count","repos","upgrades","date"}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> updates = wapt.update()
        >>> 'count' in updates and 'added' in updates and 'upgrades' in updates and 'date' in updates and 'removed' in updates
        True

        """
        if self.use_repo_rules and self.waptserver:
            self.update_repo_rules(force=force)

        self.update_licences(force=force)

        # check date of wsus
        if sys.platform == 'win32' and  WaptWUA is not None and self.waptwua_enabled:
            if self.is_enterprise():
                try:
                    wuaclient = WaptWUA(self)
                    repo = wuaclient.wuarepo()
                    if repo:
                        with repo.get_requests_session() as session:
                            cab_new_date = wuaclient.get_wsusscn2cab_date_from_server(repo, session)
                            if cab_new_date:
                                cab_current_date = ensure_unicode(self.read_param('waptwua.wsusscn2cab_date'))
                                if cab_new_date > cab_current_date:
                                    self.write_param('waptwua.status', 'NEED-SCAN')
                except Exception as e:
                    logger.debug('Unable to get wsusscn2cab.cab date from server: %s' % e)


        previous = self.waptdb.known_packages()
        # (main repo is at the end so that it will used in priority)
        next_update_on = self._update_repos_list(force=force)

        current = self.waptdb.known_packages()
        result = {
            "added":   [current[package_uuid] for package_uuid in current if not package_uuid in previous],
            "removed": [previous[package_uuid] for package_uuid in previous if not package_uuid in current],
            "discarded_count": self.read_param('last-discarded-count'),
            "count": len(current),
            "repos": [r.name for r in self.repositories],
            "upgrades": self.list_upgrade(),
            "date": datetime2isodate(),
            "next_update_on": next_update_on,
        }

        self.store_upgrade_status(result['upgrades'])

        if self.waptserver and not self.disable_update_server_status and register:
            try:
                self.update_server_status(include_wmi=None,include_dmi=None)
            except Exception as e:
                logger.info('Unable to contact server to register current packages status')
                logger.debug('Unable to update server with current status : %s' % e)
                if logger.level == logging.DEBUG:
                    raise
        return result

    def update_crls(self, force=False):
        # retrieve CRL
        # TODO : to be moved to an abstracted wapt https client
        crl_dir = setuphelpers.makepath(self.wapt_base_dir, 'ssl', 'crl')
        result = []
        for cert in self.cabundle.certificates():
            crl_urls = cert.crl_urls()
            for url in crl_urls:
                crl_filename = setuphelpers.makepath(crl_dir, sha256_for_data(str(url))+'.crl')
                if os.path.isfile(crl_filename):
                    ssl_crl = SSLCRL(crl_filename)
                else:
                    ssl_crl = None

                if force or not ssl_crl or ssl_crl.next_update > datetime.datetime.utcnow():
                    try:
                        # need update
                        if not os.path.isdir(crl_dir):
                            os.makedirs(crl_dir)
                        logger.debug('Download CRL %s' % (url,))
                        wget(url, target=crl_filename, limit_bandwidth=self.limit_bandwidth)
                        ssl_crl = SSLCRL(crl_filename)
                        result.append(ssl_crl)
                    except Exception as e:
                        logger.warning('Unable to download CRL from %s: %s' % (url, repr(e)))
                        if ssl_crl:
                            result.append(ssl_crl)
                        pass
                elif ssl_crl:
                    # not changed
                    result.append(ssl_crl)
        return result

    def check_all_depends_conflicts(self):
        """Check the whole dependencies/conflicts tree for installed packages


        """
        installed_packages = self.installed(True)

        all_depends = defaultdict(list)
        all_conflicts = defaultdict(list)
        all_missing = defaultdict(list)

        if self.use_hostpackages:
            for p in self.get_host_packages():
                all_depends[p.asrequirement()].append(None)
                (depends, conflicts, missing) = self.waptdb.build_depends(p.asrequirement())
                for d in depends:
                    if not p in all_depends[d]:
                        all_depends[d].append(p.asrequirement())
                for c in conflicts:
                    if not p in all_conflicts[c]:
                        all_conflicts[c].append(p.asrequirement())
                for m in missing:
                    if not m in all_missing:
                        all_missing[m].append(p.asrequirement())

        for p in installed_packages:
            if self.is_locally_allowed_package(p):
                if not p.asrequirement() in all_depends:
                    all_depends[p.asrequirement()] = []
            else:
                if not p.asrequirement() in all_conflicts:
                    all_conflicts[p.asrequirement()] = []

            (depends, conflicts, missing) = self.waptdb.build_depends(p.asrequirement())
            for d in depends:
                if not p in all_depends[d]:
                    all_depends[d].append(p.asrequirement())
            for c in conflicts:
                if not p in all_conflicts[c]:
                    all_conflicts[c].append(p.asrequirement())
            for m in missing:
                if not m in all_missing:
                    all_missing[m].append(p.asrequirement())

        return (all_depends, all_conflicts, all_missing)

    def check_depends(self, apackages, forceupgrade=False, force=False, assume_removed=[], package_request_filter=None):
        """Given a list of packagename or requirement "name (=version)",
        return a dictionnary of {'additional' 'upgrade' 'install' 'skipped' 'unavailable','remove'} of
        [packagerequest,matching PackageEntry]

        Args:
            apackages (str or list): list of packages for which to check missing dependencies.
            forceupgrade (boolean): if True, check if the current installed packages is the latest available
            force (boolean): if True, install the latest version even if the package is already there and match the requirement
            assume_removed (list): list of packagename which are assumed to be absent even if they are actually installed to check the
                                    consequences of removal of packages, implies force=True
            package_request_filter (PackageRequest): additional filter to apply to packages to sort by locales/arch/mat preferences
                                                       if None, get active host filter
        Returns:
            dict : {'additional' 'upgrade' 'install' 'skipped' 'unavailable', 'remove'} with list of [packagerequest,matching PackageEntry]

        """
        if apackages is None:
            apackages = []

        # additional global scoping
        if package_request_filter is None:
            package_request_filter = self.packages_filter_for_host()

        package_requests = self._ensure_package_requests_list(apackages, package_request_filter=package_request_filter)

        if not isinstance(assume_removed, list):
            assume_removed = [assume_removed]
        if assume_removed:
            force = True
        # packages to install after skipping already installed ones
        skipped = []
        unavailable = []
        additional_install = []
        to_upgrade = []
        to_remove = []
        packages = []

        # search for most recent matching package to install
        for package_request in package_requests:
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(package_request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches and not forceupgrade:
                skipped.append((package_request, old_matches))
            else:
                new_availables = self.waptdb.packages_matching(package_request)
                if new_availables:
                    if force or not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        if not (package_request, new_availables[-1]) in packages:
                            packages.append((package_request, new_availables[-1]))
                    else:
                        skipped.append((package_request, old_matches))
                else:
                    if (package_request, None) not in unavailable:
                        unavailable.append((package_request, None))

        # get dependencies of not installed top packages
        if forceupgrade:
            (depends, conflicts, missing) = self.waptdb.build_depends(package_requests)
        else:
            (depends, conflicts, missing) = self.waptdb.build_depends([p[0] for p in packages])

        for p in missing:
            if (p, None) not in unavailable:
                unavailable.append((p, None))

        # search for most recent matching package to install
        for request in depends:
            package_request = PackageRequest(request=request, copy_from=package_request_filter)
            # get the current installed package matching the request
            old_matches = self.waptdb.installed_matching(package_request)

            # removes "assumed removed" packages
            if old_matches:
                for packagename in assume_removed:
                    if old_matches.match(packagename):
                        old_matches = None
                        break

            # current installed matches
            if not force and old_matches:
                skipped.append((package_request, old_matches))
            else:
                # check if installable or upgradable ?
                new_availables = self.waptdb.packages_matching(package_request)
                if new_availables:
                    if not old_matches or (forceupgrade and old_matches < new_availables[-1]):
                        additional_install.append((package_request, new_availables[-1]))
                    else:
                        skipped.append((package_request, old_matches))
                else:
                    unavailable.append((package_request, None))

        # check new conflicts which should force removal
        all_new = additional_install+to_upgrade+packages

        def remove_matching(package, req_pe_list):
            todel = []
            for req, pe in req_pe_list:
                if pe.match(package):
                    todel.append((req, pe))
            for e in todel:
                req_pe_list.remove(e)

        for (request, pe) in all_new:
            conflicts = ensure_list(pe.conflicts)
            for conflict in conflicts:
                installed_conflict = self.waptdb.installed_matching(conflict,include_errors=True)
                if installed_conflict and not ((conflict, installed_conflict)) in to_remove:
                    to_remove.append((conflict, installed_conflict))
                remove_matching(conflict, to_upgrade)
                remove_matching(conflict, additional_install)
                remove_matching(conflict, skipped)

        result = {'additional': additional_install, 'upgrade': to_upgrade, 'install': packages, 'skipped': skipped, 'unavailable': unavailable, 'remove': to_remove}
        return result

    def check_remove(self, apackages):
        """Return a list of additional package to remove if apackages are removed

        Args:
            apackages (str or list of req or PackageRequest): list of packages for which parent dependencies will be checked.

        Returns:
            list: list of PackageRequest with broken dependencies

        """
        if not isinstance(apackages, list):
            apackages = [apackages]
        result = []

        package_requests = self._ensure_package_requests_list(apackages, PackageRequest())

        installed = []
        for p in self.installed():
            for req in package_requests:
                if req.is_matched_by(p):
                    continue

            installed.append(p)

        for pe in installed:
            # test for each installed package if the removal would imply a reinstall
            test = self.check_depends(pe, assume_removed=apackages, package_request_filter=PackageRequest())
            # get package names only
            reinstall = [p[0] for p in (test['upgrade'] + test['additional'])]
            for pr in reinstall:
                if pr in package_requests and not pe in result:
                    result.append(pe)
        return result

    def check_install(self, apackages=None, force=True, forceupgrade=True):
        """Return a list of actions required for install of apackages list of packages
        if apackages is None, check for all pending updates.

        Args:
            apackages (str or list): list of packages or None to check pending install/upgrades
            force (boolean): if True, already installed package listed in apackages
                                will be considered to be reinstalled
            forceupgrade: if True, all dependencies are upgraded to latest version,
                          even if current version comply with depends requirements
        Returns:
            dict: with keys ['skipped', 'additional', 'remove', 'upgrade', 'install', 'unavailable'] and list of
                        (package requirements, PackageEntry)

        """
        if apackages is None:
            actions = self.list_upgrade()
            apackages = actions['install']+actions['additional']+actions['upgrade']

        actions = self.check_depends(apackages, force=force, forceupgrade=forceupgrade)
        return actions

    def packages_matching(self, package_request=None, query=None, args=()):
        """Returns the list of known packages Entries matching a PackageRequest

        Args:
            package_request (PackageRequest): request

        Returns:
            list (of PackageEntry)
        """
        if isinstance(package_request, str):
            package_request = PackageRequest(request=package_request)

        if query is None:
            if package_request is not None and package_request.package:
                query = 'select * from wapt_package where package=?'
                args = (package_request.package,)
            else:
                query = 'select * from wapt_package'
                args = ()

        return self.waptdb.query_package_entry(query=query, args=args, package_request=package_request)

    def _ensure_package_requests_list(self, package_requests_or_str, package_request_filter=None, keep_package_entries=False):
        """Takes a list of packages request as string, or PackageRequest or PackageEntry
        and return a list of PackageRequest

        Args:
            package_requests ( (list of) str,PackageEntry,PackageRequest)
            package_request_filter ( PackageRequest) : additional filter. If None, takes the host filter.

        Returns:
            list of PackageEntry
        """
        if package_request_filter is None and self.filter_on_host_cap:
            package_request_filter = self.packages_filter_for_host()

        package_requests = []
        if not isinstance(package_requests_or_str, list):
            package_requests_or_str = [package_requests_or_str]

        for req in package_requests_or_str:
            if isinstance(req, PackageEntry):
                if keep_package_entries:
                    package_requests.append(req)
                else:
                    package_requests.append(PackageRequest(request=req.asrequirement(), copy_from=package_request_filter))
            elif isinstance(req, str):
                package_requests.append(PackageRequest(request=req, copy_from=package_request_filter))
            elif isinstance(req, PackageRequest):
                package_requests.append(req)
            else:
                raise Exception('Unsupported request %s for check_depends' % req)
        return package_requests


    def install(self, apackages=None,
                force=False,
                params_dict={},
                download_only=False,
                usecache=True,
                printhook=None,
                installed_by=None,
                only_priorities=None,
                only_if_not_process_running=False,
                process_dependencies=True):
        """Install a list of packages and its dependencies
        removes first packages which are in conflicts package attribute

        Returns a dictionary of (package requirement,package) with 'install','skipped','additional'

        Args:
            apackages (list or str): list of packages requirements "packagename(=version)" or list of PackageEntry.
            force (bool) : reinstalls the packages even if it is already installed
            params_dict (dict) : parameters passed to the install() procedure in the packages setup.py of all packages
                          as params variables and as "setup module" attributes
            download_only (bool) : don't install package, but only download them
            usecache (bool) : use the already downloaded packages if available in cache directory
            printhook (func) : hook for progress print

        Returns:
            dict: with keys ['skipped', 'additional', 'remove', 'upgrade', 'install', 'unavailable'] and list of
                        (package requirements, PackageEntry)

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> res = wapt.install(['tis-wapttest'],usecache=False,printhook=nullhook,params_dict=dict(company='toto'))
        >>> isinstance(res['upgrade'],list) and isinstance(res['errors'],list) and isinstance(res['additional'],list) and isinstance(res['install'],list) and isinstance(res['unavailable'],list)
        True
        >>> res = wapt.remove('tis-wapttest')
        >>> res == {'removed': ['tis-wapttest'], 'errors': []}
        True
        """

        apackages = self._ensure_package_requests_list(apackages, keep_package_entries=True)
        # ensure that apackages is a list of package requirements (strings)
        logger.info('Trying to install %s with force=%s, only_priorities=%s, only_if_not_process_running=%s' % (repr(apackages), force, only_priorities, only_if_not_process_running))
        actions = self.check_depends(apackages = apackages, force=force or download_only, forceupgrade=True)

        actions['errors'] = []

        packages = actions['install']
        skipped = actions['skipped']
        not_allowed = []
        actions['not_allowed'] = not_allowed

        if process_dependencies:
            to_upgrade = actions['upgrade']
            additional_install = actions['additional']
        else:
            to_upgrade = []
            additional_install = []

        # removal from conflicts
        to_remove = actions['remove']
        for (request, pe) in to_remove:
            logger.info('Removing conflicting package %s' % request)
            try:
                res = self.remove(request, force=True, only_priorities=only_priorities, only_if_not_process_running=only_if_not_process_running)
                actions['errors'].extend(res['errors'])
                actions['not_allowed'].extend(res.get('not_allowed', []))
                if res['errors']:
                    print('Error removing %s:%s' % (request, ensure_unicode(res['errors'])))
                if res['not_allowed']:
                    raise Exception('Removal of %s is not allowed' % repr(res['not_allowed']))
            except Exception as e:
                print('Error removing %s:%s' % (request, ensure_unicode(e)))
                if not force:
                    raise

        to_install = []

        def is_process_running(processes):
            processes = ensure_list(processes)
            for p in processes:
                if isrunning(p):
                    return p
            return None

        def is_allowed(package):
            prio_allowed = only_priorities is None or package.priority in only_priorities
            if not prio_allowed:
                print('ERROR: Install of %s is not allowed at this stage because priority %s is not selected.' % (package.package, package.priority))
                return False
            install_process_blocked_by = only_if_not_process_running and package.impacted_process and is_process_running(package.impacted_process)
            if install_process_blocked_by:
                print('ERROR: Install of %s is not allowed at this stage because %s is running.' % (package.package, install_process_blocked_by))
                return False
            return True

        for p in additional_install:
            if is_allowed(p[1]):
                to_install.append(p)
            else:
                not_allowed.append(p)

        for p in to_upgrade:
            if is_allowed(p[1]):
                to_install.append(p)
            else:
                not_allowed.append(p)

        for p in packages:
            if is_allowed(p[1]):
                to_install.append(p)
            else:
                not_allowed.append(p)

        # get package entries to install to_install is a list of (request,package)
        packages = [p[1] for p in to_install]

        downloaded = self.download_packages(packages, usecache=usecache, printhook=printhook)
        if downloaded.get('errors', []):
            logger.critical('Error downloading some files : %s' % (downloaded['errors'],))
            for request in downloaded.get('errors', []):
                actions['errors'].append([request, None])

        # check downloaded packages signatures and merge control data in local database
        for fname in downloaded['downloaded'] + downloaded['skipped']:
            pe = PackageEntry(waptfile=fname)
            pe.check_control_signature(self.cabundle)

        actions['downloads'] = downloaded
        logger.debug('Downloaded : %s' % (downloaded,))

        if not download_only:
            # switch to manual mode
            for (request, p) in skipped:
                if request in apackages and not p.explicit_by:
                    logger.info('switch to manual mode for %s' % (request,))
                    self.waptdb.switch_to_explicit_mode(p.package, installed_by or self.user)

            for (request, p) in to_install:
                try:
                    if not p.localpath or not os.path.isfile(p.localpath):
                        raise EWaptDownloadError('Package file %s not downloaded properly.' % p.filename)
                    result = self.install_wapt(p.localpath,
                                               params_dict=params_dict,
                                               explicit_by=installed_by or self.user,
                                               force=force
                                               )
                    if result['install_status'] == 'OK':
                        if p.localpath.startswith(self.packages_cache_dir):
                            logger.info('Delete %s' % p.localpath)
                            os.remove(p.localpath)

                    if result:
                        for k in result.as_dict():
                            p[k] = result[k]

                    if not result or result['install_status'] != 'OK':
                        actions['errors'].append([request, p])
                        logger.critical('Package %s not installed due to errors' % (request,))
                except Exception as e:
                    actions['errors'].append([request, p, ensure_unicode(traceback.format_exc())])
                    logger.critical('Package %s not installed due to errors : %s' % (request, ensure_unicode(e)))
                    if logger.level == logging.DEBUG:
                        raise
            return actions
        else:
            logger.info('Download only, no install performed')
            return actions

    def download_packages(self, package_requests, usecache=True, printhook=None):
        r"""Download a list of packages (requests are of the form packagename(=version) )
        If several packages are matching a request, the highest/latest only is kept.

        Args:
            package_requests (str or list): list of packages to prefetch
            usecache (boolean) : if True, don't download package if already in cache
            printhook (func) : callback with signature report(received,total,speed,url) to display progress

        Returns:
            dict: with keys {"downloaded,"skipped","errors","packages"} and list of PackageEntry.

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],usecache=False,printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """

        package_requests = self._ensure_package_requests_list(package_requests, keep_package_entries=True)

        downloaded = []
        skipped = []
        errors = []
        packages = []

        for p in package_requests:
            if isinstance(p, PackageRequest):
                mp = self.waptdb.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p, 'Unavailable package %s' % (p,)))
                    logger.critical('Unavailable package %s' % (p,))
            elif isinstance(p, PackageEntry):
                packages.append(p)
            else:
                raise Exception('Invalid package request %s' % p)

        def report(received, total, speed, url):
            self.check_cancelled()
            try:
                if total > 1:
                    stat = '%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url, received, total, 100.0*received/total, speed)
                    print(stat)
                else:
                    stat = ''
                self.runstatus = 'Downloading %s : %s' % (entry.package, stat)
            except:
                self.runstatus = 'Downloading %s' % (entry.package,)

        if not printhook:
            printhook = report

        for entry in packages:
            self.check_cancelled()

            if platform.system() == 'Windows':
                target_dir = self.packages_cache_dir
            else:
                if os.geteuid() == 0:
                    target_dir = self.packages_cache_dir
                else:
                    target_dir = os.path.join(os.path.expanduser("~"), "waptdev")
                    if not os.path.isdir(target_dir):
                        os.mkdir(target_dir)

            # use specific repository settings for download
            res = self.get_repo(entry.repo).download_packages(entry,
                                                              target_dir=target_dir,
                                                              usecache=usecache,
                                                              printhook=printhook)

            downloaded.extend(res['downloaded'])
            skipped.extend(res['skipped'])
            errors.extend(res['errors'])

        return {"downloaded": downloaded, "skipped": skipped, "errors": errors, "packages": packages}

    def download_icons(self, package_requests, usecache=True, printhook=None):
        r"""Download a list of package icons (requests are of the form packagename (>version) )
        returns a dict of {"downloaded,"skipped","errors"}

        Args:
            package_requests (str or list): list of packages to prefetch
            usecache (boolean) : if True, don't download package if already in cache
            printhook (func) : callback with signature report(received,total,speed,url) to display progress

        Returns:
            dict: with keys {"downloaded,"skipped","errors","packages"} and list of PackageEntry.

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> def nullhook(*args):
        ...     pass
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],usecache=False,printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """

        package_requests = self._ensure_package_requests_list(package_requests, keep_package_entries=True)

        downloaded = []
        skipped = []
        errors = []
        packages = []

        for p in package_requests:
            if isinstance(p, PackageRequest):
                mp = self.waptdb.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p, 'Unavailable package %s' % (p,)))
                    logger.critical('Unavailable package %s' % (p,))
            elif isinstance(p, PackageEntry):
                packages.append(p)
            else:
                raise Exception('Invalid package request %s' % p)

        for entry in packages:
            self.check_cancelled()

            def report(received, total, speed, url):
                self.check_cancelled()
                try:
                    if total > 1:
                        stat = '%s : %i / %i (%.0f%%) (%.0f KB/s)\r' % (url, received, total, 100.0*received/total, speed)
                        print(stat)
                    else:
                        stat = ''
                    self.runstatus = 'Downloading %s : %s' % (entry.package, stat)
                except:
                    self.runstatus = 'Downloading %s' % (entry.package,)
            """
            if not printhook:
                printhook = report
            """
            target_dir = os.path.join(self.packages_cache_dir, 'icons')

            res = self.get_repo(entry.repo).download_icons(entry,
                                                           target_dir=target_dir,
                                                           usecache=usecache,
                                                           printhook=printhook)

            downloaded.extend(res['downloaded'])
            skipped.extend(res['skipped'])
            errors.extend(res['errors'])

        return {"downloaded": downloaded, "skipped": skipped, "errors": errors, "packages": packages}

    def get_repo(self, repo_name):
        for r in self.repositories:
            if r.name == repo_name:
                return r
        return None

    def _get_uninstallkeylist(self, uninstall_key_str):
        """Decode uninstallkey list from db field
        For historical reasons, this field is encoded as str(pythonlist)
        or sometimes simple repr of a str

        ..Changed 1.6.2.8:: uninstallkeylist is a json representation of list.

        Returns:
            list
        """
        if uninstall_key_str:
            if uninstall_key_str.startswith("['") or uninstall_key_str.startswith("[u'"):
                # python encoded repr of a list
                try:
                    # transform to a json like array.
                    guids = json.loads(uninstall_key_str.replace("[u'", "['").replace(", u'", ',"').replace("'", '"'))
                except:
                    guids = uninstall_key_str
            elif uninstall_key_str[0] in ["'", '"']:
                # simple python string, removes quotes
                guids = uninstall_key_str[1:-1]
            else:
                try:
                    # normal json encoded list
                    guids = ujson.loads(uninstall_key_str)
                except:
                    guids = uninstall_key_str

            if isinstance(guids, str):
                guids = [guids]
            return guids
        else:
            return []

    def remove(self,
               packages_list,
               force=False,
               only_priorities=None,
               only_if_not_process_running=False):
        """Removes a package giving its package name, unregister from local status DB

        Args:
            packages_list (str or list or path): packages to remove (package name,
                            list of package requirement, package entry or development directory)
            force : if True, unregister package from local status database, even if uninstall has failed

        Returns:
            dict: {'errors': [], 'removed': [], 'not_allowed': []}

        """
        result = {'removed': [], 'errors': [], 'not_allowed': []}
        if not isinstance(packages_list, list):
            packages_list = [packages_list]

        logger.info('Trying to remove %s with force=%s, only_priorities=%s, only_if_not_process_running=%s' % (repr(packages_list), force, only_priorities, only_if_not_process_running))

        def is_process_running(processes):
            processes = ensure_list(processes)
            for p in processes:
                if isrunning(p):
                    return p
            return None

        def is_allowed(dict_package):
            if only_priorities is not None and dict_package.get('priority') in only_priorities:
                print('Uninstall of %s not allowed because priority %s is not selected.' % (dict_package.get('package'), dict_package('priority')))
                return False

            uninstall_process_blocked_by = only_if_not_process_running and dict_package.get('impacted_process') and is_process_running(dict_package.get('impacted_process'))
            if uninstall_process_blocked_by:
                print('ERROR: Uninstall of %s is not allowed at this stage because %s is running.' % (dict_package.get('package'), uninstall_process_blocked_by))
                return False

            return True

        for package in packages_list:
            try:
                self.check_cancelled()
                # development mode, remove a package by its directory
                if isinstance(package, str) and os.path.isfile(os.path.join(package, 'WAPT', 'control')):
                    package = PackageEntry().load_control_from_wapt(package).package
                elif isinstance(package, PackageEntry):
                    package = package.package
                else:
                    pe = self.is_installed(package)
                    if pe:
                        package = pe.package

                q = self.waptdb.query("""\
                   select * from wapt_localstatus
                    where package=?
                   """, (package,))
                if not q:
                    logger.debug("Package %s not installed, removal aborted" % package)
                    return result

                # several versions installed of the same package... ?
                for mydict in q:
                    # check that removal is allowed...
                    if not is_allowed(mydict):
                        result['not_allowed'].append(mydict['package'])
                        continue
                    self.runstatus = "Removing package %s version %s from computer..." % (mydict['package'], mydict['version'])

                    # removes recursively meta packages which are not satisfied anymore
                    additional_removes = self.check_remove(package)

                    cant_remove = False
                    for parent_package in additional_removes:
                        if not is_allowed(parent_package):
                            cant_remove = True
                            result['not_allowed'].append(mydict['package'])
                            break
                    if cant_remove:
                        logger.info('Removal of %s is not allowed at this stage because one parent package can not be removed' % mydict['package'])
                        result['not_allowed'].append(mydict['package'])
                        continue

                    if mydict.get('impacted_process', None):
                        killalltasks(ensure_list(mydict['impacted_process']))

                    if mydict['uninstall_key']:
                        # cook the uninstall_key because could be either repr of python list or string
                        # should be now json list in DB
                        uninstall_keys = self._get_uninstallkeylist(mydict['uninstall_key'])
                        if uninstall_keys:
                            for uninstall_key in uninstall_keys:
                                if setuphelpers.uninstall_key_exists(uninstall_key):
                                    if sys.platform == 'win32':
                                        try:
                                            uninstall_cmd = self.uninstall_cmd(uninstall_key)
                                            if uninstall_cmd:
                                                logger.info('Launch uninstall cmd %s' % (uninstall_cmd,))
                                                # if running processes, kill them before launching uninstaller
                                                print(self.run(uninstall_cmd))
                                                setuphelpers.wait_uninstallkey_absent(uninstall_key,max_loop=self.config.getint('global', 'uninstallkey_timeout'))
                                                if setuphelpers.uninstall_key_exists(uninstall_key):
                                                    setuphelpers.error('Uninstallkey still present')
                                        except Exception as e:
                                            logger.critical("Critical error during uninstall: %s" % (ensure_unicode(e)))
                                            result['errors'].append((package,traceback.format_exc()))
                                            if not force:
                                                raise

                                    if sys.platform == 'darwin':
                                        try:
                                            if setuphelpers.uninstall_key_exists(uninstall_key):
                                                if uninstall_key.startswith('pkgid:'):
                                                    setuphelpers.uninstall_pkg(uninstall_key[6:])
                                                else:
                                                    if uninstall_key.startswith('/Applications/'):
                                                        setuphelpers.uninstall_app(uninstall_key[14:])

                                                if setuphelpers.uninstall_key_exists(uninstall_key):
                                                    setuphelpers.error('Uninstallkey still present')
                                        except Exception as e:
                                            logger.critical("Critical error during uninstall: %s" % (ensure_unicode(e)))
                                            result['errors'].append((package,traceback.format_exc()))
                                            if not force:
                                                raise

                    else:
                        logger.debug('uninstall key not registered in local DB status.')

                    if mydict['install_status'] != 'ERROR':
                        try:
                            self.uninstall(package)
                        except Exception as e:
                            logger.critical('Error running uninstall script: %s' % e)
                            result['errors'].append((package,traceback.format_exc()))
                            if not force:
                                raise

                    if mydict['persistent_dir']:
                        persistent_dir =  os.path.abspath(mydict['persistent_dir'])
                        # we remove only if persistent is from an installed package
                        if persistent_dir.startswith(self.persistent_root_dir) and os.path.isdir(persistent_dir):
                            logger.info('Remove package persistent dir %s' % persistent_dir)
                            shutil.rmtree(os.path.abspath(mydict['persistent_dir']))

                    logger.info('Remove status record from local DB for %s' % package)
                    if mydict['package_uuid']:
                        self.waptdb.remove_install_status(package_uuid=mydict['package_uuid'])
                    else:
                        # backard
                        self.waptdb.remove_install_status(package=package)

                    result['removed'].append(package)

                    if reversed(additional_removes):
                        logger.info('Additional packages to remove : %s' % additional_removes)
                        for apackage in additional_removes:
                            res = self.remove(apackage, force=True)
                            result['removed'].extend(res['removed'])
                            result['errors'].extend(res['errors'])

                return result
            finally:
                self.store_upgrade_status()
                self.runstatus = ''

    def host_packagename(self):
        """Return package name for current computer"""
        # return "%s" % (setuphelpers.get_hostname().lower())
        return "%s" % (self.host_uuid,)

    def get_host_packages_names(self):
        """Return list of implicit host package names based on computer UUID and AD Org Units

        Returns:
            list: list of str package names.
        """
        """Return list of implicit available host packages based on computer UUID and AD Org Units

        Returns:
            list: list of PackageEntry.
        """
        result = []
        host_package = self.host_packagename()
        result.append(host_package)

        # ini configured profiles
        if self.host_profiles:
            result.extend([make_valid_package_name(p) for p in self.host_profiles])

        previous_dn_part_type = ''
        host_dn = self.host_dn
        if host_dn:
            dn_parts = [elem[0]+'='+elem[1] for elem in ldap3.utils.dn.parse_dn(host_dn)]
            for i in range(1, len(dn_parts)):
                dn_part = dn_parts[i]
                dn_part_type, value = dn_part.split('=', 1)
                if dn_part_type.lower() == 'dc' and dn_part_type == previous_dn_part_type:
                    break
                level_dn = ','.join(dn_parts[i:])
                # spaces and
                result.append(make_valid_package_name(level_dn))
                previous_dn_part_type = dn_part_type
        return result

    def get_host_packages(self):
        """Return list of implicit available host packages based on computer UUID and AD Org Units

        Returns:
            list: list of PackageEntry.
        """
        result = []
        package_names = self.get_host_packages_names()
        for pn in package_names:
            packages = self.is_available(pn)
            if packages and packages[-1].section in ('host', 'unit', 'profile'):
                result.append(packages[-1])
        return result

    def get_outdated_host_packages(self):
        """Check and return the available host packages available and not installed"""

        result = []
        host_packages = self.get_host_packages()
        logger.debug('Checking availability of host packages "%s"' % (host_packages, ))
        for package in host_packages:
            if self.is_locally_allowed_package(package):
                logger.debug('Checking if %s is installed/outdated' % package.asrequirement())
                installed_package = self.is_installed(package.package)
                if not installed_package or installed_package < package:
                    result.append(package)
        return result

    def get_installed_host_packages(self):
        """Get the implicit package names (host and unit packages) which are installed but no longer relevant

        Returns:
            list: of installed package names
        """
        return [p.package for p in self.installed(True) if p.section in ('host', 'unit', 'profile')]

    def get_unrelevant_host_packages(self):
        """Get the implicit package names (host and unit packages) which are installed but no longer relevant

        Returns:
            list: of installed package names
        """
        installed_host_packages = self.get_installed_host_packages()
        expected_host_packages = self.get_host_packages_names()
        return [pn for pn in installed_host_packages if pn not in expected_host_packages]

    def upgrade(self, only_priorities=None, only_if_not_process_running=False):
        """Install "well known" host package from main repository if not already installed
        then query localstatus database for packages with a version older than repository
        and install all newest packages

        Args:
            priorities (list of str): If not None, upgrade only packages with these priorities.

        Returns:
            dict: {'upgrade': [], 'additional': [], 'downloads':
                        {'downloaded': [], 'skipped': [], 'errors': []},
                     'remove': [], 'skipped': [], 'install': [], 'errors': [], 'unavailable': []}
        """
        try:
            self.runstatus = 'Upgrade system'
            upgrades = self.list_upgrade()
            logger.debug('upgrades : %s' % upgrades)

            result = dict(
                install=[],
                upgrade=[],
                additional=[],
                remove=[],
                errors=[])

            if upgrades['remove']:
                self.runstatus = 'Removes outdated / conflicted packages'
                result = merge_dict(result, self.remove(upgrades['remove'], force=True))

            for key in ['additional', 'upgrade', 'install']:
                self.runstatus = 'Install %s packages' % key
                if upgrades[key]:
                    result = merge_dict(result, self.install(upgrades[key], process_dependencies=True))

            result = merge_dict(result, self.install(list(upgrades.keys()), force=True, only_priorities=only_priorities, only_if_not_process_running=only_if_not_process_running))
            self.store_upgrade_status()

            # merge results
            return result
        finally:
            self.runstatus = ''

    def install_immediate(self, force=False,only_priorities=None, only_if_not_process_running=False):
        """Install pending packages which must be forcibly installed at a specific time.

        Args:
            only_if_not_process_running: install package only if impacted_process are not running

        Returns:
            dict: {'upgrade': [], 'additional': [], 'downloads':
                        {'downloaded': [], 'skipped': [], 'errors': []},
                     'remove': [], 'skipped': [], 'install': [], 'errors': [], 'unavailable': []}

        """
        try:
            self.runstatus = 'Install immediate packages'
            upgrades = self.list_upgrade()
            package_uuids = upgrades.get('immediate_installs',[])
            logger.debug('Packages : %s' % package_uuids)

            result = self.install(package_uuids, force=force, only_priorities=only_priorities, only_if_not_process_running=only_if_not_process_running)
            self.store_upgrade_status()

            # merge results
            return result
        finally:
            self.runstatus = ''

    def list_upgrade(self,current_datetime = None):
        """Returns a list of package requirements for packages which should be installed / upgraded / removed

        Returns:
           dict: {'additional': [], 'install': [], 'remove': [], 'upgrade': []}
        """
        result = dict(
            install=[],
            upgrade=[],
            additional=[],
            remove=[],
            immediate_installs=[])
        # only most up to date (first one in list)
        # put 'host' package at the end.
        for current,next in self.waptdb.upgradeable_status():
            if not current.section in ('host', 'unit', 'profile'):
                result['upgrade'].append(next.asrequirement())
                #result['install'].append()


        to_remove = self.get_unrelevant_host_packages()
        result['remove'].extend(to_remove)
        if self.use_hostpackages:
            host_packages = self.get_outdated_host_packages()
            if host_packages:
                for p in host_packages:
                    if self.is_locally_allowed_package(p):
                        req = p.asrequirement()
                        if not req in result['install']+result['upgrade']+result['additional']:
                            result['install'].append(req)

        # get additional packages to install/upgrade based on new upgrades
        depends = self.check_depends(result['install']+result['upgrade']+result['additional'])
        if not current_datetime:
            current_datetime = datetime2isodate()

        # to not force install packages which can't be installed properly.
        install_errors_packages_uuid = [p['package_uuid'] for p in self.waptdb.query("select package_uuid from wapt_localstatus where install_status='ERROR'")]

        for l in ('upgrade', 'additional', 'install'):
            for (r, candidate) in depends[l]:
                req = candidate.asrequirement()
                if not req in result['install']+result['upgrade']+result['additional']:
                    result[l].append(req)
                if candidate and candidate.forced_install_on and not candidate.package_uuid in install_errors_packages_uuid and candidate.forced_install_on <= current_datetime and not candidate.package_uuid in result['immediate_installs']:
                    # explicit package_uuid request
                    result['immediate_installs'].append('{%s}' % candidate.package_uuid)

        result['remove'].extend([p[1].asrequirement() for p in depends['remove'] if p[1].package not in result['remove']])
        return result

    def search(self, searchwords=[], exclude_host_repo=True, section_filter=None, newest_only=False):
        """Returns a list of packages which have the searchwords in their description

        Args:
            searchwords (str or list): words to search in packages name or description
            exclude_host_repo (boolean): if True, don't search in host repoisitories.
            section_filter (str or list): restrict search to the specified package sections/categories

        Returns:
            list: list of PackageEntry

        """
        available = self.waptdb.packages_search(searchwords=searchwords, exclude_host_repo=exclude_host_repo, section_filter=section_filter)
        installed = {p.package_uuid: p for p in self.waptdb.installed(include_errors=True)}
        upgradable = self.waptdb.upgradeable()
        for p in available:
            if p.package_uuid in installed:
                current = installed[p.package_uuid]
                if p == current:
                    p['installed'] = current
                    if p.package in upgradable:
                        p['status'] = 'U'
                    else:
                        p['status'] = 'I'
                else:
                    p['installed'] = None
                    p['status'] = '-'
            else:
                p['installed'] = None
                p['status'] = '-'
        if newest_only:
            filtered = []
            last_package_ident = None
            for package in sorted(available, reverse=True, key=self.packages_filter_for_host().get_package_compare_key):
                if package.package_ident() != last_package_ident:
                    filtered.append(package)
                last_package_ident = package.package_ident()
            return list(reversed(filtered))
        else:
            return available

    def list(self, searchwords=[]):
        """Returns a list of installed packages which have the searchwords
        in their description

        Args:
            searchwords (list): list of words to llokup in package name and description
                                only entries which have words in the proper order are returned.

        Returns:
            list: list of PackageEntry matching the search words

        >>> w = Wapt()
        >>> w.list('zip')
        [PackageEntry('tis-7zip','16.4-8') ]
        """
        return self.waptdb.installed_search(searchwords=searchwords,)

    def check_downloads(self, apackages=None, usecache=True):
        """Return list of available package entries
        to match supplied packages requirements

        Args:
            apackages (list or str): list of packages
            usecache (bool) : returns only PackageEntry not yet in cache

        Returns:
            list: list of PackageEntry to download
        """
        result = []
        if apackages is None:
            actions = self.list_upgrade()
            apackages = actions['install']+actions['additional']+actions['upgrade']
        elif isinstance(apackages, str):
            apackages = ensure_list(apackages)
        elif isinstance(apackages, list):
            # ensure that apackages is a list of package requirements (strings)
            new_apackages = []
            for p in apackages:
                if isinstance(p, PackageEntry):
                    new_apackages.append(p.asrequirement())
                else:
                    new_apackages.append(p)
            apackages = new_apackages

        for p in apackages:
            entries = self.is_available(p)
            if entries:
                # download most recent
                entry = entries[-1]
                fullpackagepath = os.path.join(self.packages_cache_dir, entry.make_package_filename())
                if usecache and (os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath) == entry.size):
                    # check version
                    try:
                        cached = PackageEntry()
                        cached.load_control_from_wapt(fullpackagepath, calc_md5=False)
                        if entry != cached:
                            result.append(entry)
                    except Exception as e:
                        logger.warning('Unable to get version of cached package %s: %s' % (fullpackagepath, ensure_unicode(e),))
                        result.append(entry)
                else:
                    result.append(entry)
            else:
                logger.debug('check_downloads : Package %s is not available' % p)
        return result

    def download_upgrades(self):
        """Download packages that can be upgraded"""
        self.runstatus = 'Download upgrades'
        try:
            to_download = self.check_downloads()
            return self.download_packages(to_download)
        finally:
            self.runstatus = ''

    def authorized_certificates(self):
        """return a list of autorized package certificate issuers for this host
        check_certificates_validity enable date checking.
        """
        return [c for c in self.cabundle.trusted_certificates() if not self.check_certificates_validity or c.is_valid()]

    def trust_package_signer(self,cert):
        """Add a certificate to the list of trusted package signers certificates
        Stores the PEM encoded data in public_certs_dir directory.
        The certificate is added to this current Wapt.cabundle instance for immediate use (until config is reloaded)
        """

        added = self.cabundle.add_certificates(cert,trusted=True)
        for signer_cert in added:
            if signer_cert.public_cert_filename and os.path.isfile(signer_cert.public_cert_filename):
                shutil.copyfile(signer_cert.public_cert_filename,os.path.join(self.public_certs_dir,os.path.basename(signer_cert.public_cert_filename)))
            else:
                signer_cert.save_as_pem(os.path.join(self.public_certs_dir,signer_cert.fingerprint))

    def untrust_package_signer(self,cert):
        """Removes a certificate from the list of trusted package signers certificates based on the fingerprint of the certificate.
        Certs in ssl public_certs_dir with matching fingerprint are deleted.
        """
        removed = self.cabundle.remove_certificates(cert)
        # removed all crt files in ssl which have the fingerprint of actually untrusted certs
        for fn in glob.glob(os.path.join(self.public_certs_dir, '*.crt'))+glob.glob(os.path.join(self.public_certs_dir, '*.pem')):
            try:
                old_cert = SSLCertificate(crt_filename=fn)
                for crt in removed:
                    if old_cert.fingerprint == crt.fingerprint:
                        os.unlink(fn)
                        break
            except ValueError:
                pass

    def register_computer(self, description=None, retry_with_password=False):
        """Send computer informations to WAPT Server
        if description is provided, updates local registry with new description

        Returns:
            dict: response from server.

        >>> wapt = Wapt()
        >>> s = wapt.register_computer()
        >>>

        """
        if not self.waptserver:
            raise EWaptException('Unable to register: waptserver not defined')
        if not self.waptserver.available():
            raise EWaptException('Unable to register: waptserver %s not available' % self.waptserver.server_url)

        if description:
            self.write_param('host_description',description)
            try:
                setuphelpers.set_computer_description(description)
            except Exception as e:
                logger.info('Unable to change system computer description to %s: %s' % (description, e))

        if self.waptserver and self.waptserver.available():
            # force recalc uuid
            self._host_uuid = None

            # full inventory
            new_hashes = {}
            old_hashes = {}

            inv = self._get_host_status_data(old_hashes, new_hashes, force=True, included_keys=['wapt_status','host_capabilities'])
            inv['status_hashes'] = new_hashes

            inv['uuid'] = self.host_uuid
            inv['host_certificate'] = self.create_or_update_host_certificate()
            inv['host_certificate_signing_request'] = self.get_host_certificate_signing_request().as_pem()

            data = jsondump(inv).encode('utf8')
            if not self.waptserver.use_kerberos:
                urladdhost = 'add_host'
            else:
                urladdhost = 'add_host_kerberos'
            signature = self.sign_host_content(data)
            try:
                result = self.waptserver.post(urladdhost,
                                              data=data,
                                              signature=signature,
                                              signer=self.get_host_certificate().cn
                                              )
            except requests.HTTPError as e:
                if e.response.status_code in (403, 404) and urladdhost == 'add_host_kerberos' and retry_with_password:  # retry without kerberos
                    # retry without kerberos auth
                    result = self.waptserver.post('add_host',
                                                  data=data,
                                                  signature=signature,
                                                  signer=self.get_host_certificate().cn
                                                  )
                elif e.response.status_code in (400, 401):  # could be a bad certificate error, so retry without client side cert
                    # retry without ssl client auth
                    result = self.waptserver.post(urladdhost,
                                                  data=data,
                                                  signature=signature,
                                                  signer=self.get_host_certificate().cn,
                                                  use_ssl_auth=False
                                                  )
                else:
                    result = dict(
                                success=False,
                                msg='Error sending registration data: status %s' % (e.response.status_code,)
                            )
            if result and result['success']:
                # if server has changed, reset cached inventory hash_status
                if result['result'].get('server_uuid') !=  self.read_param('server_uuid'):
                    self.delete_param('last_update_server_hashes')
                    self.delete_param('last_audit_data_server_date')

                self.write_param('server_uuid', result['result'].get('server_uuid'))
                self.write_param('last_successful_register', datetime2isodate())
                result_data = result.get('result', {})
                if 'status_hashes' in result_data:
                    # invalidate unmatching hashes for next round.
                    self.write_param('last_update_server_hashes', result_data['status_hashes'])
                # stores last_audit_data_server_date to send only newer data on next update server status.
                self.write_param('last_audit_data_server_date',result_data.get('last_audit_data_server_date'))

                if 'host_certificate' in result_data:
                    # server has signed the certificate, we replace our self signed one.
                    new_host_cert = SSLCertificate(crt_string=result_data['host_certificate'].encode('utf8'))
                    tasks_logger.info('Got signed certificate from server. Issuer: %s. CN: %s' % (new_host_cert.issuer_cn, new_host_cert.cn))
                    host_key = self.get_host_key()

                    if new_host_cert.cn == self.host_uuid and new_host_cert.match_key(host_key):
                        # be sure we have on disk the current host key.
                        tasks_logger.info('Save host key to %s' % (self.get_host_key_filename(),))
                        host_key.save_as_pem(filename=self.get_host_key_filename())
                        tasks_logger.info('Save host cert to %s' % (self.get_host_certificate_filename(),))
                        open(self.get_host_certificate_filename(),'w').write(result_data['host_certificate'])

                        """
                        p12 = SSLPKCS12(filename = os.path.join(self.private_dir, self.host_uuid+'.p12'))
                        p12.certificate = new_host_cert
                        p12.private_key = host_key
                        p12.save_as_p12(friendly_name=self.host_uuid)
                        """

                        self._host_certificate = None
                        self._host_certificate_timestamp = None
                        self.write_param('host_certificate_fingerprint', new_host_cert.fingerprint)
                        self.write_param('host_certificate_authority_key_identifier', codecs.encode(new_host_cert.authority_key_identifier or b'', 'hex').decode('ascii'))

                        # use newly signed client side auth certificate
                        self.set_client_cert_auth(self.waptserver,force=True)
                        for repo in self.repositories:
                            self.set_client_cert_auth(repo,force=True)
                    else:
                        tasks_logger.info('Signed certificate %s does not match host uuid %s or key.' % (new_host_cert.cn,self.host_uuid))
            else: # register is not successful
                self.delete_param('last_successful_register')

            return result

        else:
            if not self.waptserver:
                return dict(
                    success=False,
                    msg='Error sending registration: No WAPT server defined'
                )
            else:
                return dict(
                    success=False,
                    msg='Error sending registration: WAPT server %s not available' % self.waptserver.server_url
                )

    def unregister_computer(self):
        """Remove computer informations from WAPT Server

        Returns:
            dict: response from server.

        >>> wapt = Wapt()
        >>> s = wapt.unregister_computer()
        >>>

        """
        if self.waptserver:
            data = jsondump({'uuids': [self.host_uuid], 'delete_packages': 1, 'delete_inventory': 1}).encode('utf8')
            result = self.waptserver.post('api/v3/hosts_delete',
                                          data=data,
                                          signature=self.sign_host_content(data),
                                          signer=self.get_host_certificate().cn
                                          )

            if result and result['success']:
                self.delete_param('last_update_server_hashes')
                self.delete_param('last_audit_data_server_date')
                self.delete_param('server_uuid')
                if os.path.isfile(self.get_host_certificate_filename()):
                    os.unlink(self.get_host_certificate_filename())
            return result

        else:
            return dict(
                success=False,
                msg='No WAPT server defined',
                data={},
            )

    def get_host_key_filename(self):
        """Full filepath of the host own RSA private key

        Returns:
            str
        """
        return os.path.join(self.private_dir, self.host_uuid+'.pem')

    def get_host_certificate_filename(self):
        """Full filepath of the host own certificate and RSA public key

        Returns:
            str
        """
        return os.path.join(self.private_dir, self.host_uuid+'.crt')

    def get_host_certificate(self):
        """Return the current host certificate.
        If the certificate does not yet exist, it is created as a self signed certificate
        and stored in get_host_certificate_filename path

        Returns:
            SSLCertificate: host public certificate.
        """
        cert_fn = self.get_host_certificate_filename()
        if not self._host_certificate or not os.path.isfile(cert_fn) or self._host_certificate_timestamp != os.stat(cert_fn).st_mtime:
            if not os.path.isfile(cert_fn):
                self.create_or_update_host_certificate()
            self._host_certificate = SSLCertificate(cert_fn)
            self._host_certificate_timestamp = os.stat(cert_fn).st_mtime
        return self._host_certificate

    def get_host_certificate_signing_request(self):
        """Return a CSR with CN and AltSubjectNames pointing to this host uuid

        Returns:
            SSLCertificateSigningRequest: host public certificate sigbinbg request.
        """
        host_key = self.get_host_key()
        csr = host_key.build_csr(
                cn=self.host_uuid,
                altnames=[setuphelpers.get_hostname()],
                is_ca=False,
                is_code_signing=False,
                is_client_auth=True,
                key_usages=['digital_signature', 'content_commitment', 'data_encipherment', 'key_encipherment'])
        return csr

    def create_or_update_host_certificate(self, force_recreate=False):
        """Create a rsa key pair for the host and a x509 certiticate.
            Location of key is <wapt_root>\private
            Should be kept secret
            restricted access to system account and administrators only.

        Args:
            force_recreate (bool): recreate key pair even if already exists for this FQDN.

        Returns:
            str: x509 certificate of this host.

        """
        crt_filename = self.get_host_certificate_filename()

        if force_recreate or not os.path.isfile(crt_filename):
            logger.info('Creates host keys pair and x509 certificate %s' % crt_filename)
            self._host_key = self.get_host_key()
            if not os.path.isdir(self.private_dir):
                os.makedirs(self.private_dir)
            crt = self._host_key.build_sign_certificate(
                ca_signing_key=None,
                ca_signing_cert=None,
                cn=self.host_uuid,
                altnames=[setuphelpers.get_hostname()],
                is_ca=True,
                is_code_signing=False,
                is_client_auth=True)
            crt.save_as_pem(crt_filename)
            self.write_param('host_certificate_fingerprint', crt.fingerprint)
            self.write_param('host_certificate_authority_key_identifier', codecs.encode(crt.authority_key_identifier or b'', 'hex').decode('ascii'))
        # check validity
        with open(crt_filename, 'rb') as f:
            return f.read()

    def get_host_key(self, create=True):
        """Return private key used to sign uploaded data from host
        Create key if it does not exists yet.

        Returns:
            SSLPrivateKey: Private key used to sign data posted by host.
        """
        key_filename = self.get_host_key_filename()
        if self._host_key is None or not os.path.isfile(key_filename) or self._host_key_timestamp != os.stat(key_filename).st_mtime:
            # create keys pair / certificate if not yet initialised

            if create and not os.path.isfile(key_filename):
                self._host_key = SSLPrivateKey(key_filename)
                self._host_key.create()
                if not os.path.isdir(os.path.dirname(key_filename)):
                    os.makedirs(os.path.dirname(key_filename))
                self._host_key.save_as_pem()
            elif os.path.isfile(key_filename):
                self._host_key = SSLPrivateKey(key_filename)
            self._host_key_timestamp != os.stat(key_filename).st_mtime

        return self._host_key

    def sign_host_content(self, data):
        """Sign data str with host private key with sha256 + RSA
        Args:
            data (bytes) : data to sign
        Returns
            bytes: signature of sha256 hash of data.
        """
        key = self.get_host_key()
        return key.sign_content(hexdigest_for_data(data, md='sha256'))

    def get_last_update_status(self):
        """Get update status of host as stored at the end of last operation.

        Returns:
            dict:
                'date': timestamp of last operation
                'runstatus': last printed message of wapt core
                'running_tasks': list of tasks
                'errors': list of packages not installed properly
                'upgrades': list of packages which need to be upgraded
        """
        status = self.read_param('last_update_status', {"date": "", "running_tasks": [], "errors": [], "upgrades": [],"immediate_installs": []}, ptype='json')
        status['runstatus'] = self.read_param('runstatus', '')
        status['audit_status'] = self.waptdb.audit_status()
        return status

    def _get_package_status_rowid(self, package_entry=None, package_name=None):
        """Return ID of package_status record for package_name

        Args:
            package_entry (PackageEntry): package entry to lookup by package_uuid or name
            package_name (str): explicit package name
            # todo: should be a PackageRequest

        Returns:
            int: rowid in local wapt_localstatus table
        """
        with self.waptdb as waptdb:
            if package_entry is not None and package_entry.package_uuid:
                cur = waptdb.execute("""select rowid from wapt_localstatus where package_uuid=?""", (package_entry.package_uuid,))
            else:
                cur = waptdb.execute("""select rowid from wapt_localstatus where package=?""", (package_entry.package if package_entry is not None else package_name,))
            pe = cur.fetchone()
            if not pe:
                return None
            else:
                return pe[0]

    def update_package_install_status(self, **kwargs):
        """Update the install status
        """

        return self.waptdb.update_install_status(**kwargs)

    def get_cache_domain_info(self, force=False):
        last_result = self.waptdb.get_param('domain_info')
        if not last_result:
            last_result = {'ou': '', 'site': '', 'groups': []}
        last_date = self.waptdb.get_param('last_domain_info_date', ptype='datetime')
        now = datetime.datetime.utcnow()
        if last_date:
            delta = now - last_date
        else:
            force = True
        maxdelta = 60 * 60 * 2
        if force or (delta.seconds > maxdelta):
            try:
                if sys.platform == 'win32':
                    if self.use_ad_groups:
                        last_result = {'groups': setuphelpers.get_computer_groups()}
                    else:
                        last_result = {'groups': []}
                else:
                    last_result = setuphelpers.get_domain_info()
            except:
                last_result = last_result
            self.save_last_domain_info_date(now)
            self.save_domain_info(last_result)
        return last_result

    def _get_new_audit_data(self,force=False):
        last_audit_data_server_date = self.read_param('last_audit_data_server_date')
        if force or not last_audit_data_server_date:
            last_audit_data_server_date = None
        if last_audit_data_server_date and last_audit_data_server_date > datetime2isodate():
            last_audit_data_server_date = datetime2isodate()
        return self.read_audit_data_since(last_audit_data_server_date)

    def get_cached_packages_uuids(self):
        r = WaptLocalRepo(self.packages_cache_dir)
        r.update_packages_index(include_certificates=False,include_crls=False,extract_icons=False)
        return [p.package_uuid for p in r.packages()]

    def _get_host_status_data(self, old_hashes, new_hashes, force=False, included_keys=None, excluded_keys=[]):
        """Build the data to send to server where update_server_status required

        Returns:
            dict
        """

        def _default_data_state(data):
            return hashlib.sha1(pickle.dumps(data)).hexdigest()

        def _add_data_if_updated(inv, key, data, old_hashes, new_hashes, force, data_state_func=_default_data_state):
            """Add the data to inv as key if modified since last update_server_status
            if data is None, nothing is added.
            if data_state_func is None, data is always added.
            """
            if data is not None:
                if data_state_func is not None:
                    newhash = data_state_func(data)
                    oldhash = old_hashes.get(key, None)
                    if force or oldhash != newhash:
                        if isinstance(data,dict):
                            data['updated_on'] = datetime2isodate()
                        inv[key] = data
                        new_hashes[key] = newhash
                else:
                    inv[key] = data
                    if isinstance(data,dict):
                        data['updated_on'] = datetime2isodate()
            elif data_state_func is None:
                inv[key] = data
                if isinstance(data,dict):
                    data['updated_on'] = datetime2isodate()

        def _get_host_info():
            host_info = setuphelpers.host_info()

            # optionally forced dn
            host_info['computer_ad_dn'] = self.host_dn
            host_info['computer_ad_site'] = self.host_site
            if not host_info.get('description'):
                host_info['description'] = self.read_param('host_description')
            host_info['repositories'] = ";".join([r.as_dict()['repo_url'] for r in self.repositories if not(r.as_dict()['repo_url'].endswith('-host'))])

            if self.use_ad_groups:
                host_info['computer_ad_groups'] = self.get_cache_domain_info()['groups']
            return host_info

        def _get_authorized_certificates_pems():
            return [c.as_pem() for c in self.authorized_certificates()]

        def _config_overview():
            return config_overview(self.wapt_base_dir, self.config_filename)

        def _wmi_info():
            return setuphelpers.wmi_info(exclude_subkeys=['OEMLogoBitmap','PrinterPaperNames','PaperSizesSupported'])

        def _packages_audit_status_delta():
            if not force:
                last_packages_audit_status_server_date = self.read_param('last_packages_audit_status_server_date')
            else:
                last_packages_audit_status_server_date = None
            result = self.waptdb.packages_audit_inventory(after_date=last_packages_audit_status_server_date)
            if len(result)>1:
                return result
            else:
                return None

        def _packages_install_status_delta():
            # for backward compat
            if force or not old_hashes.get('installed_packages_ids'):
                since_revision=None
            else:
                since_revision = old_hashes.get('installed_packages')
                if since_revision and not isinstance(since_revision,int):
                    since_revision = None

            result = self.waptdb.installed_packages_inventory(since_status_revision=since_revision)
            if len(result)>1:
                return result
            else:
                return None

        def _audit_data():
            result = list(self._get_new_audit_data(force=force))
            if len(result) > 1:
                return result
            else:
                return None

        inv = {
            'uuid': self.host_uuid,
            'computer_fqdn': ensure_unicode(setuphelpers.get_hostname())
            }

        status_revision = self.waptdb.get_status_revision()
        inv['status_revision'] = status_revision

        timing_store = {}

        data_defs = {
            'host_info': _get_host_info,
            'host_networking': setuphelpers.host_info_networking,
            'host_capabilities': self.host_capabilities,
            'host_metrics': setuphelpers.host_metrics,
            'wapt_status': self.wapt_status,
            'installed_softwares': self.merge_installed_softwares_and_wua_list,
            'installed_packages_ids': self.waptdb.installed_packages_ids,
            'installed_packages': (_packages_install_status_delta, lambda d: status_revision),
            'packages_audit_status': _packages_audit_status_delta,
            'last_update_status': self.get_last_update_status,
            'authorized_certificates': _get_authorized_certificates_pems,
            'configurations': _config_overview,
            'dmi': setuphelpers.dmi_info,
            'audit_data': _audit_data,
            #'host_info.list_services': setuphelpers.service_list,
            #'host_info.listening_sockets': setuphelpers.listening_sockets,
        }

        if os.name == 'nt':
            data_defs['wmi'] = _wmi_info

            if self.is_enterprise():
                wua_client = WaptWUA(self)
                data_defs['wuauserv_status'] = wua_client.get_wuauserv_status
                data_defs['waptwua_status'] = wua_client.stored_waptwua_status
                data_defs['waptwua_updates'] = wua_client.stored_updates
                data_defs['waptwua_updates_localstatus'] = wua_client.stored_updates_localstatus
                #data_defs['waptwua_rules_packages'] = wua_client.stored_waptwua_rules

        if included_keys is None:
            included_keys = [k for k in data_defs.keys() if not k in excluded_keys]

        # populate inventory
        for key in included_keys:
            if not key in excluded_keys:
                with Timeit(key,store=timing_store):
                    try:
                        if isinstance(data_defs[key],tuple):
                            # specific function to check data version
                            _add_data_if_updated(inv,key, data_defs[key][0](), old_hashes, new_hashes, force=force, data_state_func=data_defs[key][1])
                        else:
                            _add_data_if_updated(inv,key, data_defs[key](), old_hashes, new_hashes, force=force)

                    except Exception as e:
                        logger.critical('Unable to build status data for key %s: %s' % (key,repr(e)))

        return inv


    def update_server_status(self, force=False, include_wmi=None, include_dmi=None):
        """Send host_info, installed packages and installed softwares,
            and last update status informations to WAPT Server,
            but don't send register info like dmi or wmi.

        .. versionchanged:: 1.4.3
            if last status has been properly sent to server and data has not changed,
                don't push data again to server.
            the hash is stored in memory, so is not pass across threads or processes.

        >>> wapt = Wapt()
        >>> s = wapt.update_server_status()
        >>>
        """
        result = None
        sys.stdout.flush()
        try_register = False
        retry = True

        if not self.waptserver:
            return None

        if not self.waptserver_available():
            tasks_logger.info('WAPT Server is not available to store current host status')
            return None

        while retry:
            try:
                # avoid sending data to the server if it has not been updated.
                new_hashes = {}
                old_hashes = self.read_param('last_update_server_hashes', {}, ptype='json')

                excluded_keys = []

                if include_dmi is None:
                    include_dmi = self.include_dmi_inventory
                if include_wmi is None:
                    include_wmi = self.include_wmi_inventory

                if (not force) and self._last_date_wmi_send:
                    include_wmi = False

                if (not force) and self._last_date_dmi_send:
                    include_dmi = False

                if not include_dmi:
                    excluded_keys.append('dmi')
                if not include_wmi:
                    excluded_keys.append('wmi')

                inv = self._get_host_status_data(old_hashes, new_hashes, force=force, excluded_keys=excluded_keys)
                inv['status_hashes'] = new_hashes

                logger.info('Updated data keys : %s' % [k for k in new_hashes if k != new_hashes.get(k)])
                logger.info('Supplied data keys : %s' % list(inv.keys()))
                data = jsondump(inv).encode('utf8')
                logger.info('Sending %s bytes to server' % len(data))
                signature = self.sign_host_content(data)

                try:
                    result = self.waptserver.post('update_host',
                                                  data=data,
                                                  signature=signature,
                                                  signer=self.get_host_certificate().cn
                                                  )

                    if result and result['success']:
                        retry = False
                        # stores for next round.
                        self.write_param('server_uuid', result['result'].get('server_uuid'))
                        self.write_param('last_update_server_status_timestamp', datetime.datetime.utcnow())
                        # stores last_audit_data_server_date to send only newer data on next update server status.
                        last_audit_data_server_date = result['result'].get('last_audit_data_server_date')
                        if last_audit_data_server_date is not None:
                            self.write_param('last_audit_data_server_date',last_audit_data_server_date)
                        last_packages_audit_status_server_date = result['result'].get('last_packages_audit_status_server_date')
                        if last_packages_audit_status_server_date is not None:
                            self.write_param('last_packages_audit_status_server_date',last_packages_audit_status_server_date)
                        if 'status_hashes' in result.get('result', {}):
                            # known server hashes for next round.
                            self.write_param('last_update_server_hashes', result['result']['status_hashes'])

                        logger.info('Status on server %s updated properly' % self.waptserver.server_url)
                    else:
                        logger.info('Error updating Status on server %s: %s' % (self.waptserver.server_url, result and result['msg'] or 'No message'))
                        if result.get('error_code') in ('ewaptmissingcertificate','ewaptbadserverauthentication'):
                            try_register = True
                            retry = True
                        else:
                            retry = False

                except requests.HTTPError as e:
                    logger.warning('Unable to update server status : %s' % (e,))
                    if e.response.status_code in (400, 401, 403):
                        last_successful_register = self.read_param('last_successful_register')
                        if not last_successful_register or (datetime.datetime.utcnow() - isodate2datetime(last_successful_register) > datetime.timedelta(hours=2)):
                            try_register = True
                        else:
                            retry=False
                    else:
                        retry = False

                except EWaptBadServerAuthentication as e:
                    logger.warning('Unable to update server status : %s' % (e,))
                    try_register = True

                if result and result['success']:
                    if include_wmi:
                        self._last_date_wmi_send = datetime.datetime.utcnow()
                    if include_dmi:
                        self._last_date_dmi_send = datetime.datetime.utcnow()
                    db_data = result.get('result')
                    tasks_logger.info('update_server_status successful (data size:%s, keys:%s)' % (len(data),inv.keys()))
                else:
                    db_data = None

                if try_register or (db_data and db_data.get('computer_fqdn', None).lower() != setuphelpers.get_hostname()):
                    try_register = False
                    tasks_logger.warning('Host on the server is not known or not known under this FQDN name (known as %s). Trying to register the computer...' % (db_data and db_data.get('computer_fqdn', None) or None))
                    result = self.register_computer()
                    if result and result['success']:
                        tasks_logger.info('New registration successful. Retring sending host status.')
                        self.reload_config_if_updated()
                        retry = True
                    else:
                        logger.critical('Unable to register: %s' % result and result['msg'])
                        retry = False

            except Exception as e:
                tasks_logger.warning('Unable to update server status : %s' % e)
                logger.debug(traceback.format_exc())
                break

        return result

    def waptserver_available(self):
        """Test reachability of waptserver.

        If waptserver is defined and available, return True, else False

        Returns:
            boolean: True if server is defined and actually reachable
        """
        return self.waptserver and self.waptserver.available()

    def inc_status_revision(self, inc=1):
        rev = self.read_param('status_revision', 0, ptype='int')+inc
        self.write_param('status_revision', rev)
        return rev

    def merge_installed_softwares_and_wua_list(self):
        soft_inventory = setuphelpers.installed_softwares()
        for s in soft_inventory:
            # append win32 for uniqueness on windows
            s['software_id'] = s['key'] + {False:'##win32',True:'',None:''}.get(s.get('win64'))

        if self.waptwua_enabled and self.is_enterprise():
            dict_kb_name = self.waptdb.get_param('waptwua.simple.list')
            if dict_kb_name:
                for u in dict_kb_name:
                    soft_inventory.append({'software_id':u,
                                           'key': u,
                                           'name': '%s (%s)' % (u, dict_kb_name[u]),
                                           'version': u.replace('KB', ''),
                                           'install_date': '',
                                           'install_location': '',
                                           'uninstall_string': '',
                                           'publisher': 'Microsoft',
                                           'system_component': 1,
                                           'win64': setuphelpers.iswin64() })
        return soft_inventory

    def wapt_status(self):
        """Wapt configuration and version informations

        Returns:
            dict: versions of main main files, waptservice config,
                  repos and waptserver config

        >>> w = Wapt()
        >>> w.wapt_status()
        {
                'setuphelpers-version': '1.1.1',
                'waptserver': {
                        'wapt_server': u'tranquilit.local',
                        'proxies': {
                                'http': None,
                                'https': None
                        },
                        'server_url': 'https: //wapt.tranquilit.local'
                },
                'waptservice_protocol': 'http',
                'repositories': [{
                        'wapt_server': u'tranquilit.local',
                        'proxies': {
                                'http': None,
                                'https': None
                        },
                        'name': 'global',
                        'repo_url': 'http: //wapt.tranquilit.local/wapt'
                },
                {
                        'wapt_server': u'tranquilit.local',
                        'proxies': {
                                'http': None,
                                'https': None
                        },
                        'name': 'wapt-host',
                        'repo_url': 'http: //srvwapt.tranquilit.local/wapt-host'
                }],
                'common-version': '1.1.1',
                'wapt-exe-version': u'1.1.1.0',
                'waptservice_port': 8088,
                'wapt-py-version': '1.1.1'
        }
        """
        result = {}
        if os.name == 'nt':
            waptexe = os.path.join(self.wapt_base_dir, 'wapt-get.exe')
            if os.path.isfile(waptexe):
                result['wapt-get-version'] = setuphelpers.get_file_properties(waptexe)['FileVersion']
        with open(os.path.join(self.wapt_base_dir, 'version-full'), 'r') as wapt_version_full:
            result['wapt-version-full'] = wapt_version_full.readline().rstrip()
        result['waptutils-version'] = __version__
        trusted_certs_sha256 = []
        trusted_certs_cn = []
        invalid_certs_sha256 = []
        result['last_external_ip'] = self.waptdb.get_param('last_external_ip')

        for c in self.authorized_certificates():
            try:
                for c2 in self.cabundle.check_certificates_chain(c):
                    if not c2.fingerprint in trusted_certs_sha256:
                        trusted_certs_sha256.append(c2.fingerprint)
                        trusted_certs_cn.append(c2.cn)
            except Exception as e:
                logger.warning('Certificate %s invalid (fingerprint %s expiration %s): %s' % (c.cn, c.fingerprint, c.not_after, e))
                invalid_certs_sha256.append(c.fingerprint)

        result['authorized_certificates_sha256'] = trusted_certs_sha256
        result['invalid_certificates_sha256'] = invalid_certs_sha256
        result['authorized_certificates_cn'] = trusted_certs_cn
        result['maturities'] = self.maturities
        result['locales'] = self.locales
        result['is_remote_repo'] = self.config.getboolean('repo-sync', 'enable_remote_repo') if (self.config.has_section('repo-sync') and self.config.has_option('repo-sync', 'enable_remote_repo')) else False
        result['remote_reboot_allowed'] = self.config.getboolean('global', 'allow_remote_reboot') if self.config.has_option('global', 'allow_remote_reboot') else False
        result['remote_shutdown_allowed'] = self.config.getboolean('global', 'allow_remote_shutdown') if self.config.has_option('global', 'allow_remote_shutdown') else False
        result['remote_repo_url'] = '' if not(result['is_remote_repo']) else self.config.get('repo-sync', 'remote_repo_url') if (self.config.has_section('repo-sync') and self.config.has_option('repo-sync', 'remote_repo_url')) else 'https://'+setuphelpers.get_fqdn()+'/wapt'
        result['wol_relay'] = self.config.getboolean('global', 'wol_relay') if self.config.has_option('global', 'wol_relay') else result['is_remote_repo']
        result['use_repo_rules'] = self.use_repo_rules

        if sys.platform == 'win32':
            result['pending_reboot_reasons'] = setuphelpers.pending_reboot_reasons()

        # read from config
        if self.config.has_option('global', 'waptservice_sslport'):
            port = self.config.get('global', 'waptservice_sslport')
            if port:
                result['waptservice_protocol'] = 'https'
                result['waptservice_port'] = int(port)
            else:
                result['waptservice_protocol'] = None
                result['waptservice_port'] = None
        elif self.config.has_option('global', 'waptservice_port'):
            port = self.config.get('global', 'waptservice_port')
            if port:
                result['waptservice_protocol'] = 'http'
                result['waptservice_port'] = int(port)
            else:
                # could be better
                result['waptservice_protocol'] = None
                result['waptservice_port'] = None
        else:
            # could be better
            result['waptservice_protocol'] = 'http'
            result['waptservice_port'] = 8088

        result['repositories'] = [r.as_dict() for r in self.repositories]
        if self.waptserver:
            result['waptserver'] = self.waptserver.as_dict()

        result['packages_whitelist'] = self.packages_whitelist
        result['packages_blacklist'] = self.packages_blacklist
        result['is_enterprise'] = self.is_enterprise()

        #if self.is_enterprise():
        #    result['self_service_rules'] = self_service_rules(self)

        return result

    def reachable_ip(self):
        """Return the local IP which is most probably reachable by wapt server

        In case there are several network connections, returns the local IP
          which Windows choose for sending packets to WaptServer.

        This can be the most probable IP which would get packets from WaptServer.

        Returns:
            str: Local IP
        """
        try:
            if self.waptserver and self.waptserver.server_url:
                host = urllib.parse.urlparse(self.waptserver.server_url).hostname
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((host, 0))
                local_ip = s.getsockname()[0]
                s.close()
                return local_ip
            else:
                return None
        except:
            return None

    def inventory(self):
        """Return full inventory of the computer as a dictionary.

        Returns:
            dict: {'host_info','wapt_status','dmi','installed_softwares','installed_packages'}

        ...changed:
            1.4.1: renamed keys
            1.6.2.4: removed setup.py from packages inventory.
        """
        inv = {}
        inv['host_info'] = setuphelpers.host_info()
        inv['host_info']['repositories'] = ";".join([r.as_dict()['repo_url'] for r in self.repositories if not(r.as_dict()['repo_url'].endswith('-host'))])
        # optionally forced dn
        inv['computer_ad_dn'] = self.host_dn

        if self.include_dmi_inventory:
            try:
                inv['dmi'] = setuphelpers.dmi_info()
            except:
                inv['dmi'] = None
                logger.warning('DMI not working')

        if self.include_wmi_inventory:
            if os.name=='nt':
                try:
                    inv['wmi'] = setuphelpers.wmi_info()
                except:
                    inv['wmi'] = None
                    logger.warning('WMI unavailable')

        inv['wapt_status'] = self.wapt_status()

        inv['installed_softwares'] = self.merge_installed_softwares_and_wua_list()
        inv['installed_packages'] = [p.as_dict() for p in self.waptdb.installed(include_errors=True, include_setup=False)]
        inv['host_capabilities'] = self.host_capabilities()
        return inv

    def registration_inventory(self):
        """Minimum inventory for initial registration
        """
        inv = {}
        inv['computer_fqdn'] = ensure_unicode(setuphelpers.get_hostname())
        inv['computer_ad_dn'] = self.host_dn
        inv['wapt_status'] = self.wapt_status()
        inv['host_capabilities'] = self.host_capabilities()
        return inv

    def personal_certificate(self):
        """Returns the personal certificates chain

        Returns:
            list (of SSLCertificate). The first one is the personal certificate. The other are useful if intermediate CA are used.
        """
        cert_chain = SSLCABundle()
        cert_chain.add_certificates_from_pem(pem_filename=self.personal_certificate_path)
        return cert_chain.certificates()

    def private_key(self, private_key_password=None):
        """SSLPrivateKey matching the personal_certificate
        When key has been found, it is kept in memory for later use.

        Args:
            private_key_password : password to use to decrypt key. If None, passwd_callback is called.

        Returns:
            SSLPrivateKey

        Raises:
            EWaptMissingPrivateKey if ket can not be decrypted or found.
        """
        if private_key_password is None:
            password_callback = self.private_key_password_callback
        else:
            password_callback = None

        certs = self.personal_certificate()
        try:
            cert = certs[0]
        except IndexError:
            raise EWaptMissingPrivateKey('No personal certificate could be found ; cannot look for any keys')

        if not self._private_key_cache or not cert.match_key(self._private_key_cache):
            self._private_key_cache = cert.matching_key_in_dirs(password_callback=password_callback, private_key_password=private_key_password)
        if self._private_key_cache is None:
            raise EWaptMissingPrivateKey('The key matching the certificate %s can not be found or decrypted' % (cert.public_cert_filename or cert.subject))
        return self._private_key_cache

    def sign_package(self, zip_or_directoryname, certificate=None, private_key_password=None, private_key=None,
                     set_maturity=None, inc_package_release=False, keep_signature_date=False, excludes=[]):
        """Calc the signature of the WAPT/manifest.sha256 file and put/replace it in ZIP or directory.
            if directory, creates WAPT/manifest.sha256 and add it to the content of package
            create a WAPT/signature file and it to directory or zip file.

            known issue : if zip file already contains a manifest.sha256 file, it is not removed, so there will be
                          2 manifest files in zip / wapt package.

        Args:
            zip_or_directoryname: filename or path for the wapt package's content
            certificate (list): certificates chain of signer.
            private_key (SSLPrivateKey): the private key to use
            private_key_password (str) : passphrase to decrypt the private key. If None provided, use self.private_key_password_callback

        Returns:
            str: base64 encoded signature of manifest.sha256 file (content
        """
        if not isinstance(zip_or_directoryname, str):
            zip_or_directoryname = str(zip_or_directoryname)

        if certificate is None:
            certificate = self.personal_certificate()

        if isinstance(certificate, list):
            signer_cert = certificate[0]
        else:
            signer_cert = certificate

        if private_key_password is None:
            password_callback = self.private_key_password_callback
        else:
            password_callback = None

        if private_key is None:
            private_key = signer_cert.matching_key_in_dirs(password_callback=password_callback, private_key_password=private_key_password)

        if private_key is None:
            raise Exception('No private key provided to sign package')

        logger.info('Using identity : %s' % signer_cert.cn)
        pe = PackageEntry().load_control_from_wapt(zip_or_directoryname)
        if set_maturity is not None and pe.maturity != set_maturity:
            pe.maturity = set_maturity
        if inc_package_release:
            pe.inc_build()
        pe.save_control_to_wapt()
        return pe.sign_package(private_key=private_key,
                               certificate=certificate,
                               keep_signature_date=keep_signature_date,
                               excludes=excludes,
                               excludes_full=DEFAULT_EXCLUDED_PATHS_FOR_BUILD)

    def build_package(self, directoryname, target_directory=None, excludes=[]):
        """Build the WAPT package from a directory

        Args:
            directoryname (str): source root directory of package to build
            inc_package_release (boolean): increment the version of package in control file.
            set_maturity (str): if not None, change package maturity to this. Can be something like DEV, PROD etc..

        Returns:
            str: Filename of built WAPT package
        """
        if not isinstance(directoryname, str):
            directoryname = str(directoryname)
        # some checks
        if not os.path.isdir(os.path.join(directoryname, 'WAPT')):
            raise EWaptNotAPackage('Error building package : There is no WAPT directory in %s' % directoryname)
        if not os.path.isfile(os.path.join(directoryname, 'WAPT', 'control')):
            raise EWaptNotAPackage('Error building package : There is no control file in WAPT directory')

        logger.info('Load control informations from control file')
        entry = PackageEntry(waptfile=directoryname)
        return entry.build_package(excludes=excludes, excludes_full=DEFAULT_EXCLUDED_PATHS_FOR_BUILD, target_directory=target_directory)

    def build_upload(self, sources_directories, private_key_passwd=None, wapt_server_user=None, wapt_server_passwd=None, inc_package_release=False,
                     target_directory=None, set_maturity=None):
        """Build a list of packages and upload the resulting packages to the main repository.
        if section of package is group or host, user specific wapt-host or wapt-group

        Returns
            list: list of filenames of built WAPT package
        """
        sources_directories = ensure_list(sources_directories)
        buildresults = []

        if not self.personal_certificate_path or not os.path.isfile(self.personal_certificate_path):
            raise EWaptMissingPrivateKey('Unable to build %s, personal certificate path %s not provided or not present' % (sources_directories, self.personal_certificate_path))

        for source_dir in [os.path.abspath(p) for p in sources_directories]:
            if os.path.isdir(source_dir):
                logger.info('Signing %s with certificate %s' % (source_dir, self.personal_certificate()))
                signature = self.sign_package(
                    source_dir, private_key_password=private_key_passwd,
                    inc_package_release=inc_package_release,
                    set_maturity=set_maturity
                )
                logger.debug("Package %s signed : signature :\n%s" % (source_dir, signature.decode('utf8')))
                logger.info('Building  %s' % source_dir)
                package_fn = self.build_package(source_dir, target_directory=target_directory)
                if package_fn:
                    logger.info('...done. Package filename %s' % (package_fn,))
                    buildresults.append(package_fn)
                else:
                    logger.critical('package %s not created' % package_fn)
            else:
                logger.critical('Directory %s not found' % source_dir)

        logger.info('Uploading %s files...' % len(buildresults))
        auth = None
        if wapt_server_user and wapt_server_passwd:
            auth = (wapt_server_user, wapt_server_passwd)
        upload_res = self.waptserver.upload_packages(buildresults, auth=auth)

        if not buildresults:
            raise Exception('Packages could not be built')

        if not upload_res:
            raise Exception('Packages built but no packages could be uploaded')

        if upload_res['errors']:
            raise Exception('Packages built but no packages could be uploaded : {}'.format(upload_res['errors'][0]['msg']))

        return buildresults

    def cleanup_session_setup(self):
        """Remove all current user session_setup informations for removed packages
        """
        installed = self.waptdb.installed_package_names(False)
        self.waptsessiondb.remove_obsolete_install_status(installed)

    def session_setup(self, package, force=False):
        """Setup the user session for a specific system wide installed package"
           Source setup.py from database or filename
        """
        install_id = None
        oldpath = sys.path
        try:
            is_dev_mode = False
            if isinstance(package, PackageEntry):
                package_entry = package
            elif os.path.isdir(package):
                package_entry = PackageEntry().load_control_from_wapt(package)
                is_dev_mode = True
            else:
                package_entry = self.is_installed(package)

            if not package_entry:
                raise Exception('Package %s is not installed' % package)

            if package_entry.has_setup_py() and (is_dev_mode or 'def session_setup():' in package_entry.setuppy):
                # initialize a session db for the user
                session_db = WaptSessionDB(self.user)  # WaptSessionDB()
                with session_db:
                    if force or is_dev_mode or not session_db.is_installed(package_entry.package, package_entry.version):
                        print(("Running session_setup for package %s and user %s" % (package_entry.asrequirement(), self.user)))
                        install_id = session_db.add_start_install(package_entry)
                        with WaptPackageSessionSetupLogger(console=sys.stderr, waptsessiondb=session_db, install_id=install_id) as dblog:
                            try:
                                # get value of required parameters from system wide install
                                params = self.get_previous_package_params(package_entry)
                                try:
                                    result = package_entry.call_setup_hook('session_setup', self, params, force=force)
                                except EWaptMissingPackageHook:
                                    result = None

                                if result:
                                    dblog.exit_status = 'RETRY'
                                    session_db.update_install_status(install_id, append_line='session_setup() done\n')
                                else:
                                    dblog.exit_status = 'OK'
                                    session_db.update_install_status(install_id, append_line='session_setup() done\n')
                                return result
                            except Exception:
                                logger.critical("session_setup failed for package %s and user %s" % (package_entry.asrequirement(), self.user))
                                session_db.update_install_status(install_id, append_line=traceback.format_exc())
                                dblog.exit_status = 'ERROR'

                    else:
                        logger.info("session_setup for package %s and user %s already installed" % (package_entry.asrequirement(), self.user))
            else:
                logger.debug('No setup.py, skipping session-setup')
        finally:
            sys.path = oldpath

    def audit(self, package, force=False, audited_by=None) -> str:
        """Run the audit hook for the installed package"
        Source setup.py from database, filename, or packageEntry
        Stores the result and log into "wapt_localstatus" table

        Args:
            package (PackageEntry or directory or package name or {package_uuid} ): package to audit

        Returns:
            str : iso datetime of this audit as stored in packages status table
        """

        def worst(r1, r2):
            states = ['OK', 'WARNING', 'ERROR', 'UNKNOWN']
            try:
                idxr1 = states.index(r1)
            except ValueError:
                idxr1 = states.index('UNKNOWN')
            try:
                idxr2 = states.index(r2)
            except ValueError:
                idxr2 = states.index('UNKNOWN')
            if idxr1 > idxr2:
                return states[idxr1]
            else:
                return states[idxr2]

        install_id = None
        now = datetime2isodate(datetime.datetime.utcnow())

        oldpath = sys.path
        try:
            if isinstance(package, PackageEntry):
                package_entry = package
            elif os.path.isdir(package):
                package_entry = PackageEntry().load_control_from_wapt(package)
            else:
                package_entry = self.is_installed(package)

            if not package_entry:
                raise Exception('Package %s is not installed' % package)

            if hasattr(package_entry, 'install_status') and hasattr(package_entry, 'rowid'):
                install_id = package_entry.rowid
                package_install = package_entry
            else:
                install_id = self._get_package_status_rowid(package_entry)
                if install_id is None:
                    raise Exception('Package %s is not installed' % package)
                package_install = self.waptdb.install_status(install_id)

            if force or not package_install.next_audit_on or now >= package_install.next_audit_on:
                next_audit = None

                if package_install.audit_schedule:
                    audit_period = package_install.audit_schedule
                else:
                    audit_period = self.waptaudit_task_period

                if audit_period is not None:
                    timedelta = get_time_delta(audit_period, 'm')
                    next_audit = datetime.datetime.utcnow()+timedelta

                # skip audit entirely if no uninstall_key and no audit hook
                if not package_install['uninstall_key'] and (not package_entry.has_setup_py() or not 'def audit():' in package_entry.setuppy):
                    self.waptdb.update_audit_status(install_id, set_status='OK', set_last_audit_on=datetime2isodate(datetime.datetime.utcnow()), set_next_audit_on=next_audit and datetime2isodate(next_audit) or None)
                    return 'OK'

                logger.info("Audit run for package %s and user %s" % (package, audited_by or self.user))
                self.waptdb.update_audit_status(install_id, set_status='RUNNING', set_output='',
                                                set_last_audit_on=datetime2isodate(datetime.datetime.utcnow()),
                                                set_next_audit_on=next_audit and datetime2isodate(next_audit) or None)

                with WaptPackageAuditLogger(console=sys.stderr, wapt_context=self, install_id=install_id, user=audited_by or self.user) as dblog:
                    try:
                        # check if registered uninstalley are still there
                        uninstallkeys = self._get_uninstallkeylist(package_install['uninstall_key'])
                        dblog.exit_status = 'OK'

                        print('Auditing %s' % package_entry.package)
                        if sys.platform == 'win32':
                            if uninstallkeys is not None:
                                for key in uninstallkeys:
                                    uninstallkey_exists = setuphelpers.installed_softwares(uninstallkey=key)
                                    if not uninstallkey_exists:
                                        print('ERROR: Uninstall Key %s is not in Windows Registry.' % key)
                                        dblog.exit_status = worst(dblog.exit_status, 'ERROR')
                                    else:
                                        print(' OK: Uninstall Key %s in Windows Registry.' % key)
                                        dblog.exit_status = worst(dblog.exit_status, 'OK')

                        elif sys.platform == 'darwin':
                            if uninstallkeys is not None:
                                for key in uninstallkeys:
                                    if not setuphelpers.uninstall_key_exists(key):
                                        print('ERROR: Uninstall Key %s is not installed.' % key)
                                        dblog.exit_status = worst(dblog.exit_status, 'ERROR')
                                    else:
                                        print(' OK: Uninstall Key %s.' % key)
                                        dblog.exit_status = worst(dblog.exit_status, 'OK')



                        if package_entry.has_setup_py():
                            # get value of required parameters from system wide install
                            params = self.get_previous_package_params(package_entry)
                            # this call return None if not audit hook or if hook has no return value.
                            try:
                                result = package_entry.call_setup_hook('audit', self, params,force=force, user=audited_by)
                            except EWaptMissingPackageHook:
                                result = 'OK'
                            dblog.exit_status = worst(dblog.exit_status, result)
                        else:
                            logger.debug('No setup.py, skipping session-setup')
                            print( 'OK: No setup.py')
                            dblog.exit_status = worst(dblog.exit_status, 'OK')

                        return dblog.exit_status

                    except Exception as e:
                        print('Audit aborted due to exception: %s' % e)
                        dblog.exit_status = 'ERROR'
                        return dblog.exit_status
            else:
                return package_install.last_audit_status

        finally:
            sys.path = oldpath

    def get_previous_package_params(self, package_entry):
        """Return the params used when previous install of package_entry.package
        If no previous install, return {}
        The params are stored as json string in local package status table.

        Args:
            package_entry (PackageEntry): package request to lookup.

        Returns:
            dict
        """
        # get old install params if the package has been already installed
        old_install = self.is_installed(package_entry.package)
        if old_install:
            return ujson.loads(old_install['install_params'])
        else:
            return {}

    def uninstall(self, packagename, params_dict={},force=False):
        """Launch the uninstall script of an installed package"
        Source setup.py from database or filename
        """
        try:
            previous_cwd = os.getcwd()
            if os.path.isdir(packagename):
                entry = PackageEntry().load_control_from_wapt(packagename)
            else:
                logger.debug('Sourcing setup from DB')
                entry = self.is_installed(packagename)

            if not entry:
                raise Exception('no package %s installed on this host' % packagename)

            params = self.get_previous_package_params(entry)
            params.update(params_dict)

            if entry.has_setup_py():
                try:
                    entry.call_setup_hook('uninstall', self, params=params,force=force)
                except EWaptMissingPackageHook:
                    pass
            else:
                logger.info('Uninstall: no setup.py source in database.')

        finally:
            logger.debug('  Change current directory to %s' % previous_cwd)
            os.chdir(previous_cwd)


    def __get_installer_defaults_deb(self, result_format, installer_path):
        """See get_installer_defaults(). Specific to .deb archives"""

        result = result_format
        try:
            with arpy.Archive(installer_path) as ar_file:
                tarball = ar_file.open('control.tar.gz')
                tar_file = tarfile.open(fileobj=tarball)
                control_file = tar_file.extractfile('./control')
                control_lines = control_file.readlines()

            control_dict = {}
            for line in control_lines:
                line_split = line.decode('utf-8').split(': ')
                control_dict[line_split[0]] = line_split[1]

            result.update(dict(filename=control_dict['Package'],
                            version=control_dict['Version'],
                            description=control_dict['Description'],
                            architecture=control_dict['Architecture']))
        except Exception as e:
            logger.info('Couldn\'t extract metadata from deb archive {} : {}'.format(installer_path, e))

        return result

    def __get_installer_defaults_rpm(self, result_format, installer_path):
        """See get_installer_defaults(). Specific to .deb archives"""

        result = result_format
        try:
            with rpmfile.open(installer_path) as rpm:
                rpm_headers = rpm.headers
                result.update(dict(filename=rpm_headers['name'],
                                version=rpm_headers['version'],
                                description=rpm_headers['description'],
                                architecture=rpm_headers['arch']))
        except Exception as e:
            logger.info('Couldn\'t extract metadata from rpm archive {} : {}'.format(installer_path, e))

        return result


    def get_installer_defaults(self, installer_path):
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
        props =  setuphelpers.get_product_props(installer_path)
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

        # the get_installer_defaults_win function is only in setuphelpers_windows
        if sys.platform == 'win32' and (ext in ['.exe', '.msi', '.msu']):
            return setuphelpers.get_installer_defaults_win(installer_path)

        if ext == '.deb':
            result = self.__get_installer_defaults_deb(result, installer_path)
        elif ext == '.rpm':
            result = self.__get_installer_defaults_rpm(result, installer_path)
        else:
            result.update(dict(type=setuphelpers.InstallerTypes.UnknownInstaller, silentflags='/VERYSILENT'))
        return result


    def make_package_template(self, installer_path='', packagename='', directoryname='',
                              section='base', description=None, depends='', version=None, silentflags=None, uninstallkey=None,
                              maturity=None, architecture='all', target_os='all', product_name=None):
        r"""Build a skeleton of WAPT package based on the properties of the supplied installer
           Return the path of the skeleton
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> files = 'c:/tmp/files'
        >>> if not os.path.isdir(files):
        ...    os.makedirs(files)
        >>> tmpdir = 'c:/tmp/dummy'
        >>> devdir = wapt.make_package_template(files,packagename='mydummy',directoryname=tmpdir,depends='tis-firefox')
        >>> os.path.isfile(os.path.join(devdir,'WAPT','control'))
        True
        >>> p = wapt.build_package(devdir)
        >>> 'filename' in p and isinstance(p['files'],list) and isinstance(p['package'],PackageEntry)
        True
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        """
        if installer_path:
            installer_path = os.path.abspath(installer_path)
        if directoryname:
            directoryname = os.path.abspath(directoryname)

        if not installer_path and not packagename:
            raise EWaptException('You must provide at least installer_path or packagename to be able to prepare a package template')

        if installer_path:
            installer = os.path.basename(installer_path)
        else:
            installer = ''

        uninstallkey = uninstallkey or ''
        product_name = product_name or ''

        if os.path.isfile(installer_path):
            # case of an installer
            props = setuphelpers.get_product_props(installer_path)
            silentflags = silentflags or setuphelpers.getsilentflags(installer_path)
            # for MSI, uninstallkey is in properties
            if not uninstallkey and 'ProductCode' in props:
                uninstallkey = '"%s"' % props['ProductCode']
        elif os.path.isdir(installer_path):
            # case of a directory
            props = {
                'product': installer,
                'description': installer,
                'version': '0',
                'publisher': ensure_unicode(setuphelpers.get_current_user()),
                'ProductName' : product_name
            }
            silentflags = silentflags or ''
        else:
            # case of a nothing
            props = {
                'product': packagename,
                'description': packagename,
                'version': '0',
                'publisher': ensure_unicode(setuphelpers.get_current_user()),
                'ProductName' : product_name
            }
            silentflags = ''

        if not packagename:
            simplename = re.sub(r'[\s\(\)\|\,\.\%]+', '_', props['product'].lower())
            packagename = '%s-%s' % (self.config.get('global', 'default_package_prefix'), simplename)

        description = description or 'Package for %s ' % props['description']
        version = version or props['version']
        product_name = product_name or props['ProductName']

        if not directoryname:
            directoryname = self.get_default_development_dir(PackageEntry(package=packagename, version=version, section=section, maturity=maturity, target_os=target_os, architecture=architecture))

        if not os.path.isdir(os.path.join(directoryname, 'WAPT')):
            os.makedirs(os.path.join(directoryname, 'WAPT'))

        if installer_path:
            (installer_name, installer_ext) = os.path.splitext(installer)
            installer_ext = installer_ext.lower()
            if installer_ext in ['.msi', '.msix']:
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_msi.py.tmpl')
            elif installer_ext == '.msu':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_msu.py.tmpl')
            elif installer_ext == '.exe':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_exe.py.tmpl')
            elif installer_ext == '.deb':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_deb.py.tmpl')
            elif installer_ext == '.pkg':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_pkg.py.tmpl')
            elif installer_ext == '.dmg':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_dmg.py.tmpl')
            elif installer_ext == '.rpm':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_rpm.py.tmpl')
            elif installer_ext == '.crt':
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_cert.py.tmpl')
            elif os.path.isdir(installer_path):
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template_dir.py.tmpl')
            else:
                setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_template.py.tmpl')
        else:
            setup_template = os.path.join(self.wapt_base_dir, 'templates', 'setup_package_skel.py.tmpl')

        template = codecs.open(setup_template, encoding='utf8').read() % dict(
            packagename=packagename,
            uninstallkey=uninstallkey,
            silentflags=silentflags,
            installer=installer,
            product=props['product'],
            description=description,
            version=version,
        )
        setuppy_filename = os.path.join(directoryname, 'setup.py')
        if not os.path.isfile(setuppy_filename):
            codecs.open(setuppy_filename, 'w', encoding='utf8').write(template)
        else:
            logger.info('setup.py file already exists, skip create')
        logger.debug('Copy installer %s to target' % installer)
        if os.path.isfile(installer_path):
            shutil.copyfile(installer_path, os.path.join(directoryname, installer))
        elif os.path.isdir(installer_path):
            setuphelpers.copytree2(installer_path, os.path.join(directoryname, installer))

        control_filename = os.path.join(directoryname, 'WAPT', 'control')
        if not os.path.isfile(control_filename):
            entry = PackageEntry()
            entry.package = packagename
            entry.name = product_name
            entry.architecture = architecture
            entry.target_os = target_os
            if maturity is None:
                entry.maturity = self.default_maturity
            else:
                entry.maturity = maturity

            entry.description = description
            try:
                entry.maintainer = ensure_unicode(win32api.GetUserNameEx(3))
            except:
                try:
                    entry.maintainer = ensure_unicode(setuphelpers.get_current_user())
                except:
                    entry.maintainer = os.environ['USERNAME']

            entry.priority = 'optional'
            entry.section = section or 'base'
            entry.version = version+'-0'
            entry.depends = depends
            if self.config.has_option('global', 'default_sources_url'):
                entry.sources = self.config.get('global', 'default_sources_url') % entry.as_dict()
            codecs.open(control_filename, 'w', encoding='utf8').write(entry.ascontrol())
        else:
            logger.info('control file already exists, skip create')

        self.add_pyscripter_project(directoryname)
        self.add_vscode_project(directoryname)
        return directoryname

    def make_host_template(self, packagename='', depends=None, conflicts=None, directoryname=None, description=None):
        if not packagename:
            packagename = self.host_packagename()
        return self.make_group_template(packagename=packagename, depends=depends, conflicts=conflicts, directoryname=directoryname, section='host', description=description)

    def make_group_template(self, packagename='', maturity=None, depends=None, conflicts=None, directoryname=None, section='group', description=None):
        r"""Creates or updates on disk a skeleton of a WAPT group package.
        If the a package skeleton already exists in directoryname, it is updated.

        sourcespath attribute of returned PackageEntry is populated with the developement directory of group package.

        Args:
            packagename (str): group name
            depends :
            conflicts
            directoryname
            section
            description

        Returns:
            PackageEntry

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> if os.path.isdir(tmpdir):
        ...    import shutil
        ...    shutil.rmtree(tmpdir)
        >>> p = wapt.make_group_template(packagename='testgroupe',directoryname=tmpdir,depends='tis-firefox',description=u'Test de groupe')
        >>> print p
        >>> print p['package'].depends
        tis-firefox
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        """
        if directoryname:
            directoryname = os.path.abspath(directoryname)

        if not packagename:
            packagename = self.host_packagename()

        if not directoryname:
            directoryname = self.get_default_development_dir(packagename, section=section)

        if not directoryname:
            directoryname = tempfile.mkdtemp('wapt')

        if not os.path.isdir(os.path.join(directoryname, 'WAPT')):
            os.makedirs(os.path.join(directoryname, 'WAPT'))

        template_fn = os.path.join(self.wapt_base_dir, 'templates', 'setup_%s_template.py' % section)
        if os.path.isfile(template_fn):
            # replacing %(var)s by local values in template
            # so setup template must use other string formating system than % like '{}'.format()
            template = codecs.open(template_fn, encoding='utf8').read() % locals()
            setuppy_filename = os.path.join(directoryname, 'setup.py')
            if not os.path.isfile(setuppy_filename):
                codecs.open(setuppy_filename, 'w', encoding='utf8').write(template)
            else:
                logger.info('setup.py file already exists, skip create')
        else:
            logger.info('No %s template. Package wil lhave no setup.py' % template_fn)

        control_filename = os.path.join(directoryname, 'WAPT', 'control')
        entry = PackageEntry()
        if not os.path.isfile(control_filename):
            entry.priority = 'standard'
            entry.section = section
            entry.version = '0'
            entry.architecture = 'all'
            if maturity is None:
                entry.maturity = maturity
            else:
                entry.maturity = self.default_maturity
            entry.description = description or '%s package for %s ' % (section, packagename)
            try:
                entry.maintainer = ensure_unicode(win32api.GetUserNameEx(3))
            except:
                try:
                    entry.maintainer = ensure_unicode(setuphelpers.get_current_user())
                except:
                    entry.maintainer = os.environ['USERNAME']
        else:
            entry.load_control_from_wapt(directoryname)

        entry.package = packagename

        # Check existing versions and increment it
        older_packages = self.is_available(entry.package)
        if older_packages and entry <= older_packages[-1]:
            entry.version = older_packages[-1].version
            entry.inc_build()

        entry.filename = entry.make_package_filename()

        if self.config.has_option('global', 'default_sources_url'):
            entry.sources = self.config.get('global', 'default_sources_url') % {'packagename': packagename}

        # check if depends should be appended to existing depends
        if (isinstance(depends, str) or isinstance(depends, str)) and depends.startswith('+'):
            append_depends = True
            depends = ensure_list(depends[1:])
            current = ensure_list(entry.depends)
            for d in depends:
                if not d in current:
                    current.append(d)
            depends = current
        else:
            append_depends = False

        depends = ensure_list(depends)
        if depends:
            # use supplied list of packages
            entry.depends = ','.join(['%s' % p for p in depends if p and p != packagename])

        # check if conflicts should be appended to existing conflicts
        if (isinstance(conflicts, str) or isinstance(conflicts, str)) and conflicts.startswith('+'):
            append_conflicts = True
            conflicts = ensure_list(conflicts[1:])
            current = ensure_list(entry.conflicts)
            for d in conflicts:
                if not d in current:
                    current.append(d)
            conflicts = current
        else:
            append_conflicts = False

        conflicts = ensure_list(conflicts)
        if conflicts:
            # use supplied list of packages
            entry.conflicts = ','.join(['%s' % p for p in conflicts if p and p != packagename])

        entry.save_control_to_wapt(directoryname)
        if entry.section != 'host':
            self.add_pyscripter_project(directoryname)
            self.add_vscode_project(directoryname)
        return entry

    def is_installed(self, packagename, include_errors=False):
        """Checks if a package is installed.
        Return package entry and additional local status or None

        Args:
            packagename (str): name / {package_uuid}/ package request to query

        Returns:
            PackageEntry: None en PackageEntry merged with local install_xxx fields
                          * install_date
                          * install_output
                          * install_params
                          * install_status
        """
        if isinstance(packagename, PackageEntry):
            packagename = packagename.asrequirement()
        return self.waptdb.installed_matching(packagename, include_errors=include_errors)

    def installed(self, include_errors=False):
        """Returns all installed packages with their status

        Args:
            include_errors (boolean): include packages wnot installed successfully

        Returns:
            list: list of PackageEntry merged with local install status.
        """
        return self.waptdb.installed(include_errors=include_errors)

    def is_available(self, packagename):
        r"""Check if a package (with optional version condition) is available
        in repositories.

        Args:
            packagename (str) : package name to lookup or package requirement ( packagename(=version) )

        Returns:
            list : of PackageEntry sorted by package version ascending

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> l = wapt.is_available('tis-wapttest')
        >>> l and isinstance(l[0],PackageEntry)
        True
        """
        return self.waptdb.packages_matching(packagename)

    def get_default_development_dir(self, packagecond, section='base'):
        """Returns the default development directory for package named <packagecond>
        based on default_sources_root ini parameter if provided

        Args:
            packagecond (PackageEntry or str): either PackageEntry or a "name(=version)" string

        Returns:
            unicode: path to local proposed development directory
        """
        if not isinstance(packagecond, PackageEntry):
            # assume something like "package(=version)"
            package_and_version = REGEX_PACKAGE_CONDITION.match(packagecond).groupdict()
            pe = PackageEntry(package_and_version['package'], package_and_version['version'] or '0')
        else:
            pe = packagecond

        root = ensure_unicode(self.config.get('global', 'default_sources_root'))
        if not root:
            root = ensure_unicode(tempfile.gettempdir())
        return os.path.join(root, pe.make_package_edit_directory())

    def add_pyscripter_project(self, target_directory):
        """Add a pyscripter project file to package development directory.

        Args:
            target_directory (str): path to location where to create the wapt.psproj file.

        Returns:
            None
        """
        psproj_filename = os.path.join(target_directory, 'WAPT', 'wapt.psproj')
        # if not os.path.isfile(psproj_filename):
        # supply some variables to psproj template
        datas = self.as_dict()
        datas['target_directory'] = target_directory
        proj_template = codecs.open(os.path.join(self.wapt_base_dir, 'templates', 'wapt.psproj'), encoding='utf8').read() % datas
        codecs.open(psproj_filename, 'w', encoding='utf8').write(proj_template)


    def add_vscode_project(self, target_directory):
        r"""Add .vscode folder with project files to the package development directory

        Args:
            target_directory (str): path to the package development directory.

        Returns:
            None

        """
        vscode_dir = os.path.join(target_directory, ".vscode")
        if not (os.path.isdir(vscode_dir)):
            os.mkdir(vscode_dir)
        launch_json = os.path.join(vscode_dir, "launch.json")
        if os.path.isfile(launch_json):
            os.remove(launch_json)
        shutil.copyfile(os.path.join(self.wapt_base_dir, "templates", "vscode_launch.json"), launch_json)
        with open(os.path.join(self.wapt_base_dir, "templates", "vscode_settings.json"), "r") as settings_json_file:
            settings_json = json.load(settings_json_file)
            if not (os.path.isfile(os.path.join(self.wapt_base_dir, "Scripts", "python.exe"))):
                settings_json["python.pythonPath"] = os.path.join(self.wapt_base_dir, "bin", "python")
                settings_json["python.defaultInterpreterPath"] = os.path.join(self.wapt_base_dir, "bin", "python")
            else:
                settings_json["python.pythonPath"] = os.path.join(self.wapt_base_dir,  "Scripts", "python.exe")
                settings_json["python.defaultInterpreterPath"] = os.path.join(self.wapt_base_dir, "Scripts", "python.exe")
            settings_json["python.wapt-get"] = os.path.join(self.wapt_base_dir, "wapt-get.py")
            with open(os.path.join(vscode_dir, "settings.json"), "w") as settings_json_outfile:
                json.dump(settings_json, settings_json_outfile, indent=4)
        with open(os.path.join(target_directory, ".env"), "w") as fenv:
            list_of_env = ["VIRTUAL_ENV=" + self.wapt_base_dir, "PYTHONPATH=" + self.wapt_base_dir]
            fenv.write("\n".join(list_of_env) + "\n")


    def edit_package(self, packagerequest,
                     target_directory='',
                     use_local_sources=True,
                     append_depends=None,
                     remove_depends=None,
                     append_conflicts=None,
                     remove_conflicts=None,
                     auto_inc_version=True,
                     cabundle=None,
                     ):
        r"""Download an existing package from repositories into target_directory for modification
        if use_local_sources is True and no newer package exists on repos, updates current local edited data
        else if target_directory exists and is not empty, raise an exception

        Args:
            packagerequest (str) : path to existing wapt file, or package request
            use_local_sources (boolean) : don't raise an exception if target exist and match package version
            append_depends (list of str) : package requirements to add to depends
            remove_depends (list or str) : package requirements to remove from depends
            auto_inc_version (bool) :
            cabundle  (SSLCABundle) : list of authorized certificate filenames. If None, use default from current wapt.

        Returns:
            PackageEntry : edit local package with sourcespath attribute populated

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> r= wapt.update()
        >>> tmpdir = tempfile.mkdtemp('wapt')
        >>> res = wapt.edit_package('tis-wapttest',target_directory=tmpdir,append_depends='tis-firefox',remove_depends='tis-7zip')
        >>> res['target'] == tmpdir and res['package'].package == 'tis-wapttest' and 'tis-firefox' in res['package'].depends
        True
        >>> import shutil
        >>> shutil.rmtree(tmpdir)

        """
        if cabundle is None:
            cabundle = self.cabundle

        # check before if path exist
        if os.path.isdir(packagerequest):
            entry = PackageEntry(waptfile=packagerequest)
            entry.localpath=packagerequest
            target_directory=packagerequest
        elif os.path.isfile(packagerequest):
            entry = PackageEntry(waptfile=packagerequest)
        else:
            # check if available in repos
            entries = self.is_available(packagerequest)
            if entries:
                entry = entries[-1]
                self.download_packages(entry)
            else:
                raise EWaptException('Package %s does not exist. Either update local status or check filepath.' % (packagerequest))

        packagerequest = entry.asrequirement()

        if target_directory is None:
            target_directory = tempfile.mkdtemp(prefix="wapt")
        elif not target_directory:
            target_directory = self.get_default_development_dir(entry, section=entry.section)

        if entry.localpath:
            local_dev_entry = self.is_wapt_package_development_dir(target_directory)
            if local_dev_entry:
                if use_local_sources and not local_dev_entry.match(packagerequest):
                    raise Exception('Target directory %s contains a different package version %s' % (target_directory, entry.asrequirement()))
                elif not use_local_sources:
                    raise Exception('Target directory %s contains already a developement package %s' % (target_directory, entry.asrequirement()))
                else:
                    logger.info('Using existing development sources %s' % target_directory)
            elif not local_dev_entry:
                entry.unzip_package(target_dir=target_directory, cabundle=cabundle)
                entry.invalidate_signature()
                local_dev_entry = entry

            append_depends = ensure_list(append_depends)
            remove_depends = ensure_list(remove_depends)
            append_conflicts = ensure_list(append_conflicts)
            remove_conflicts = ensure_list(remove_conflicts)

            if append_depends or remove_depends or append_conflicts or remove_conflicts:
                prev_depends = ensure_list(local_dev_entry.depends)
                for d in append_depends:
                    if not d in prev_depends:
                        prev_depends.append(d)

                for d in remove_depends:
                    if d in prev_depends:
                        prev_depends.remove(d)

                prev_conflicts = ensure_list(local_dev_entry.conflicts)
                for d in append_conflicts:
                    if not d in prev_conflicts:
                        prev_conflicts.append(d)

                if remove_conflicts:
                    for d in remove_conflicts:
                        if d in prev_conflicts:
                            prev_conflicts.remove(d)

                local_dev_entry.depends = ','.join(prev_depends)
                local_dev_entry.conflicts = ','.join(prev_conflicts)
                local_dev_entry.save_control_to_wapt(target_directory)

            if entry.section != 'host':
                self.add_pyscripter_project(target_directory)
                self.add_vscode_project(target_directory)
            return local_dev_entry
        else:
            raise Exception('Unable to unzip package in %s' % target_directory)

    def is_wapt_package_development_dir(self, directory):
        """Return PackageEntry if directory is a wapt developement directory (a WAPT/control file exists) or False"""
        return os.path.isfile(os.path.join(directory, 'WAPT', 'control')) and PackageEntry().load_control_from_wapt(directory, calc_md5=False)

    def is_wapt_package_file(self, filename):
        """Return PackageEntry if filename is a wapt package or False
        True if file ends with .wapt and control file can be loaded and decoded from zip file

        Args:
            filename (str): path to a file

        Returns:
            False or PackageEntry

        """
        (root, ext) = os.path.splitext(filename)
        if ext != '.wapt' or not os.path.isfile(filename):
            return False
        try:
            entry = PackageEntry().load_control_from_wapt(filename, calc_md5=False)
            return entry
        except:
            return False

    def edit_host(self,
                  hostname,
                  target_directory=None,
                  append_depends=None,
                  remove_depends=None,
                  append_conflicts=None,
                  remove_conflicts=None,
                  printhook=None,
                  description=None,
                  cabundle=None,
                  ):
        """Download and extract a host package from host repositories into target_directory for modification

        Args:
            hostname       (str)   : fqdn of the host to edit
            target_directory (str)  : where to place the developments files. if empty, use default one from wapt-get.ini configuration
            append_depends (str or list) : list or comma separated list of package requirements
            remove_depends (str or list) : list or comma separated list of package requirements to remove
            cabundle (SSLCA Bundle) : authorized ca certificates. If None, use default from current wapt.

        Returns:
            PackageEntry

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> tmpdir = 'c:/tmp/dummy'
        >>> wapt.edit_host('dummy.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        >>> import shutil
        >>> shutil.rmtree(tmpdir)
        >>> host = wapt.edit_host('htlaptop.tranquilit.local',target_directory=tmpdir,append_depends='tis-firefox')
        >>> 'package' in host
        True
        >>> shutil.rmtree(tmpdir)
        """
        if target_directory is None:
            target_directory = tempfile.mkdtemp('wapt')
        elif not target_directory:
            target_directory = self.get_default_development_dir(hostname, section='host')

        if os.path.isdir(target_directory) and os.listdir(target_directory):
            raise Exception('directory %s is not empty, aborting.' % target_directory)

        #self.use_hostpackages = True

        if cabundle is None:
            cabundle = self.cabundle

        append_depends = ensure_list(append_depends)
        remove_depends = ensure_list(remove_depends)
        append_conflicts = ensure_list(append_conflicts)
        remove_conflicts = ensure_list(remove_conflicts)

        for d in append_depends:
            if not d in remove_conflicts:
                remove_conflicts.append(d)

        for d in append_conflicts:
            if not d in remove_depends:
                remove_depends.append(d)

        # create a temporary repo for this host
        host_repo = WaptHostRepo(name='wapt-host', host_id=hostname, config=self.config, host_key=self._host_key, WAPT=self)
        entry = host_repo.get(hostname)
        if entry:
            host_repo.download_packages(entry)
            entry.unzip_package(target_dir=target_directory, cabundle=cabundle)
            entry.invalidate_signature()

            # update depends list
            prev_depends = ensure_list(entry.depends)
            for d in append_depends:
                if not d in prev_depends:
                    prev_depends.append(d)
            for d in remove_depends:
                if d in prev_depends:
                    prev_depends.remove(d)
            entry.depends = ','.join(prev_depends)

            # update conflicts list
            prev_conflicts = ensure_list(entry.conflicts)
            for d in append_conflicts:
                if not d in prev_conflicts:
                    prev_conflicts.append(d)
            if remove_conflicts:
                for d in remove_conflicts:
                    if d in prev_conflicts:
                        prev_conflicts.remove(d)
            entry.conflicts = ','.join(prev_conflicts)
            if description is not None:
                entry.description = description

            entry.save_control_to_wapt(target_directory)
            return entry
        else:
            # create a new version of the existing package in repository
            return self.make_host_template(packagename=hostname, directoryname=target_directory, depends=append_depends, description=description)

    def forget_packages(self, packages_list):
        """Remove install status for packages from local database
        without actually uninstalling the packages

        Args:
            packages_list (list): list of installed package names to forget

        Returns:
            list: list of package names actually forgotten

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> res = wapt.install('tis-test')
        ???
        >>> res = wapt.is_installed('tis-test')
        >>> isinstance(res,PackageEntry)
        True
        >>> wapt.forget_packages('tis-test')
        ['tis-test']
        >>> wapt.is_installed('tis-test')
        >>> print wapt.is_installed('tis-test')
        None
        """
        result = []
        packages_list = ensure_list(packages_list)
        for package in packages_list:
            q = self.waptdb.query("""\
               select * from wapt_localstatus
                where package=?
               """, (package,))
            for pe in q:
                if pe['persistent_dir'] and os.path.isdir(os.path.abspath(pe['persistent_dir'])):
                    shutil.rmtree(os.path.abspath(pe['persistent_dir']))

            rowid = self.waptdb.remove_install_status(package)
            if rowid:
                result.append(package)

        self.store_upgrade_status()
        return result

    def duplicate_package(self,
                          packagename,
                          newname=None,
                          newversion=None,
                          newmaturity=None,
                          target_directory=None,
                          append_depends=None,
                          remove_depends=None,
                          append_conflicts=None,
                          remove_conflicts=None,
                          auto_inc_version=True,
                          usecache=True,
                          printhook=None,
                          cabundle=None,
                          ):
        """Duplicate an existing package.
        Duplicate an existing package from declared repostory or file into targetdirectory with
          optional newname and version.

        Args:
            packagename (str) :      packagename to duplicate, or filepath to a local package or package development directory.
            newname (str):           name of target package
            newversion (str):        version of target package. if None, use source package version
            target_directory (str):  path where to put development files. If None, use temporary. If empty, use default development dir
            append_depends (list):   comma str or list of depends to append.
            remove_depends (list):   comma str or list of depends to remove.
            auto_inc_version (bool): if version is less than existing package in repo, set version to repo version+1
            usecache (bool):         If True, allow to use cached package in local repo instead of downloading it.
            printhook (func):        hook for download progress
            cabundle (SSLCABundle):         list of authorized ca certificate (SSLPublicCertificate) to check authenticity of source packages. If None, no check is performed.

        Returns:
            PackageEntry : new packageEntry with sourcespath = target_directory

        >>> wapt = Wapt(config_filename='c:/tranquilit/wapt/tests/wapt-get.ini')
        >>> wapt.dbpath = ':memory:'
        >>> r= wapt.update()
        >>> def nullhook(*args):
        ...     pass
        >>> tmpdir = 'c:/tmp/testdup-wapt'
        >>> if os.path.isdir(tmpdir):
        ...     import shutil
        ...     shutil.rmtree(tmpdir)
        >>> p = wapt.duplicate_package('tis-wapttest',
        ...     newname='testdup',
        ...     newversion='20.0-0',
        ...     target_directory=tmpdir,
        ...     excludes=['.svn','.git','.gitignore','*.pyc','src'],
        ...     append_depends=None,
        ...     auto_inc_version=True,
        ...     usecache=False,
        ...     printhook=nullhook)
        >>> print repr(p['package'])
        PackageEntry('testdup','20.0-0')
        >>> if os.path.isdir(tmpdir):
        ...     import shutil
        ...     shutil.rmtree(tmpdir)
        >>> p = wapt.duplicate_package('tis-wapttest',
        ...    target_directory=tempfile.mkdtemp('wapt'),
        ...    auto_inc_version=True,
        ...    append_depends=['tis-firefox','tis-irfanview'],
        ...    remove_depends=['tis-wapttestsub'],
        ...    )
        >>> print repr(p['package'])
        PackageEntry('tis-wapttest','120')
        """
        if target_directory:
            target_directory = os.path.abspath(target_directory)

        if newname:
            while newname.endswith('.wapt'):
                dot_wapt = newname.rfind('.wapt')
                newname = newname[0:dot_wapt]
                logger.warning("Target ends with '.wapt', stripping.  New name: %s", newname)


        append_depends = ensure_list(append_depends)
        remove_depends = ensure_list(remove_depends)
        append_conflicts = ensure_list(append_conflicts)
        remove_conflicts = ensure_list(remove_conflicts)

        def check_target_directory(target_directory, source_control):
            if os.path.isdir(target_directory) and os.listdir(target_directory):
                pe = PackageEntry().load_control_from_wapt(target_directory)
                if pe.package != source_control.package or pe > source_control:
                    raise Exception('Target directory "%s" is not empty and contains either another package or a newer version, aborting.' % target_directory)

        # duplicate a development directory tree
        if os.path.isdir(packagename):
            source_control = PackageEntry().load_control_from_wapt(packagename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname, section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory, source_control)
            if packagename != target_directory:
                shutil.copytree(packagename, target_directory)
        # duplicate a wapt file
        elif os.path.isfile(packagename):
            source_filename = packagename
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname, section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory, source_control)
            source_control.unzip_package(target_dir=target_directory, cabundle=cabundle)

        else:
            source_package = self.is_available(packagename)
            if not source_package:
                raise Exception('Package %s is not available in current repositories.' % (packagename,))
            # duplicate package from a repository
            filenames = self.download_packages([packagename], usecache=usecache, printhook=printhook)
            package_paths = filenames['downloaded'] or filenames['skipped']
            if not package_paths:
                raise Exception('Unable to download package %s' % (packagename,))
            source_filename = package_paths[0]
            source_control = PackageEntry().load_control_from_wapt(source_filename)
            if not newname:
                newname = source_control.package
            if target_directory == '':
                target_directory = self.get_default_development_dir(newname, section=source_control.section)
            if target_directory is None:
                target_directory = tempfile.mkdtemp('wapt')
            # check if we will not overwrite newer package or different package
            check_target_directory(target_directory, source_control)
            source_control.unzip_package(target_dir=target_directory, cabundle=cabundle)

        # duplicate package informations
        dest_control = PackageEntry()
        for a in source_control.required_attributes + source_control.optional_attributes:
            dest_control[a] = source_control[a]

        if newmaturity is not None:
            dest_control.maturity = newmaturity
        else:
            dest_control.maturity = self.default_maturity

        # add / remove dependencies from copy
        prev_depends = ensure_list(dest_control.depends)
        for d in append_depends:
            if not d in prev_depends:
                prev_depends.append(d)
        for d in remove_depends:
            if d in prev_depends:
                prev_depends.remove(d)
        dest_control.depends = ','.join(prev_depends)

        # add / remove conflicts from copy
        prev_conflicts = ensure_list(dest_control.conflicts)
        for d in append_conflicts:
            if not d in prev_conflicts:
                prev_conflicts.append(d)

        for d in remove_conflicts:
            if d in prev_conflicts:
                prev_conflicts.remove(d)
        dest_control.conflicts = ','.join(prev_conflicts)

        # change package name
        dest_control.package = newname
        if newversion:
            dest_control.version = newversion

        # Check existing versions of newname and increment it
        if auto_inc_version:
            older_packages = self.is_available(newname)
            if older_packages and dest_control <= older_packages[-1]:
                dest_control.version = older_packages[-1].version
                dest_control.inc_build()

        dest_control.filename = dest_control.make_package_filename()
        dest_control.save_control_to_wapt(target_directory)

        if dest_control.section != 'host':
            self.add_pyscripter_project(target_directory)
            self.add_vscode_project(target_directory)
        dest_control.invalidate_signature()
        return dest_control

    def write_param(self, name, value):
        """Store in local db a key/value pair for later use"""
        self.waptdb.set_param(name, value)

    def set_package_attribute(self, package, key, value):
        """Store in local db a key/value pair for later use"""
        self.waptdb.set_param(package+'.'+key, value)

    def get_package_attribute(self, package, key, default_value=None):
        """Store in local db a key/value pair for later use"""
        return self.waptdb.get_param(package+'.'+key, default_value)

    def read_param(self, name, default=None, ptype=None):
        """read a param value from local db
        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> wapt.read_param('db_version')
        u'20140410'
        """
        return self.waptdb.get_param(name, default, ptype)

    def delete_param(self, name):
        """Remove a key from local db"""
        self.waptdb.delete_param(name)

    def dependencies(self, packagename, expand=False):
        """Return all dependecies of a given package
        >>> w = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> dep = w.dependencies('tis-waptdev')
        >>> isinstance(dep,list) and isinstance(dep[0],PackageEntry)
        True
        """
        packages = self.is_available(packagename)
        result = []
        errors = []
        if packages:
            depends = ensure_list(packages[-1].depends)
            for dep in depends:
                subpackages = self.is_available(dep)
                if subpackages:
                    if expand:
                        result.extend(self.dependencies(dep))
                    if not subpackages[-1] in result:
                        result.append(subpackages[-1])
                else:
                    errors.append(dep)

        return result

    def get_package_entries(self, packages_names):
        r"""Return most up to date packages entries for packages_names
        packages_names is either a list or a string.

        'missing' key lists the package requirements which are not available in the
        package index.

        Args;
            packages_names (list or str): list of package requirements

        Returns:
            dict : {'packages':[PackageEntries,],'missing':[str,]}

        >>> wapt = Wapt(config_filename='c:/wapt/wapt-get.ini')
        >>> res = wapt.get_package_entries(['tis-firefox','tis-putty'])
        >>> isinstance(res['missing'],list) and isinstance(res['packages'][0],PackageEntry)
        True
        """
        result = {'packages': [], 'missing': []}
        if isinstance(packages_names, str) or isinstance(packages_names, str):
            packages_names = [p.strip() for p in packages_names.split(",")]
        for package_name in packages_names:
            matches = self.waptdb.packages_matching(package_name)
            if matches:
                result['packages'].append(matches[-1])
            else:
                result['missing'].append(package_name)
        return result

    def network_reconfigure(self):
        """Called whenever the network configuration has changed
        """
        try:
            if self._repositories:
                for repo in self._repositories:
                    repo.reset_network()
            if not self.disable_update_server_status:
                self.update_server_status()
        except Exception as e:
            logger.warning('WAPT was unable to reconfigure properly after network changes : %s' % ensure_unicode(e))

    def add_upgrade_shutdown_policy(self):
        """Add a local shitdown policy to upgrade system"""
        waptexit_path = setuphelpers.makepath(self.wapt_base_dir, 'waptexit.exe')
        if not os.path.isfile(waptexit_path):
            raise Exception('Can not find %s' % waptexit_path)
        setuphelpers.shutdown_scripts_ui_visible(state=True)
        return setuphelpers.add_shutdown_script(waptexit_path, '')

    def remove_upgrade_shutdown_policy(self):
        """Add a local shitdown policy to upgrade system"""
        waptexit_path = setuphelpers.makepath(self.wapt_base_dir, 'waptexit.exe')
        if not os.path.isfile(waptexit_path):
            raise Exception('Can not find %s' % waptexit_path)
        return setuphelpers.remove_shutdown_script(waptexit_path, '')

    def show_progress(self, show_box=False, msg='Loading...', progress=None, progress_max=None):
        """Global hook to report progress feedback to the user

        Args:
            show_box (bool): indicate to display or hide the notification
            msg (str): A status message to display. If None, nothing is changed.
            progress (float): Completion
            progress_max (float): Target of completion.

        """
        if self.progress_hook:
            return self.progress_hook(show_box, msg, progress, progress_max)  # pylint: disable=not-callable
        else:
            print(('%s : %s / %s' % (msg, progress, progress_max)))
            return False

    def get_secured_token_generator(self,token_secret_key):
        return URLSafeTimedSerializer(token_secret_key)

    def is_authorized_package_action(self, action, package, user_groups=[], rules=None):
        package_request = PackageRequest(package=package)
        if package_request.package in self.waptdb.installed_package_names() and action in ('install', 'upgrade'):
            return True

        upgrades_and_pending = [PackageRequest(pr).package for pr in self.get_last_update_status().get('upgrades', [])]
        if package_request.package in upgrades_and_pending and action in ('install', 'upgrade'):
            return True

        if not user_groups:
            return False

        if self.is_enterprise():
            if rules is None:
                rules = self_service_rules(self)

            for group in user_groups:
                if package_request.package in rules.get(group, []):
                    return True

        if 'waptselfservice' in user_groups:
            return True
            # return package_request.section not in ('restricted','wsus','unit','profile')

        return False

    def available_categories(self):
        return list(set([k.get('keywords').capitalize().split(',')[0] for k in self.waptdb.query('select distinct keywords from wapt_package where keywords is not null')]))

    def self_service_auth(self, login, password, host_uuid, groups):
        """ Sends login and password to server, who then checks if it's a valid user

        Returns:
            list: groups the user belongs to.
        """
        result = None

        if not self.waptserver_available():
            raise Exception("Waptserver is not available ; cannot send credentials to server")

        try:
            data = {"user": login,
                    "password": password,
                    "uuid": host_uuid,
                    "groups": list(groups)
                    }
            signature = self.sign_host_content(str.encode(jsondump(data)))

            result = self.waptserver.post('login_self_service',
                                            data=jsondump(data),
                                            signature=signature,
                                            signer=self.get_host_certificate().cn
                                            )

            if result and result['success']:
                logger.info('User successfully authenticated %s updated properly' % self.waptserver.server_url)
                return result
            else:
                raise Exception('Error authenticating on server %s: %s' % (self.waptserver.server_url, result and result['msg'] or 'No message'))
        except requests.HTTPError as e:
            logger.debug('Unable to authenticate on server : %s' % traceback.format_exc())
            logger.warning('Unable to authenticate on server : %s' % e)
            raise e

    ### audit / metrics related dara
    def _audit_data_to_db(self,value):
        if value is None:
            return None
        if isinstance(value, datetime.datetime):
            value = datetime2isodate(value)
        value = jsondump(value)
        return value

    def _audit_data_from_db(self, value, ptype=None):
        if value is None:
            return None
        else:
            # stored always in json format
            try:
                value = ujson.loads(value)
            except ValueError:
                # tolerant for old data
                pass
            # specific output conversion
            if ptype == 'datetime':
                return isodate2datetime(value)
            return value

    def audit_data_expired(self, section, key, value):
        """Check if the latest value associated with section/key is expired

        Returns:
            bool: True is data exists and has expires or if data does not exists.

        """
        q = self.waptdb.execute('select expiration_date from wapt_audit_data where value_section=? and value_key=? order by value_date desc limit 1', (section,key,)).fetchone()
        if q:
            (expiration_date, ) = q
            return not expiration_date or expiration_date < datetime2isodate(datetime.datetime.utcnow())
        else:
            return True

    def write_audit_data_if_changed(self, section, key, value, ptype=None, value_date=None, expiration_date=None, max_count=2, keep_days=None):
        """Write data only if different from last one

        Returns:
            previous value
        """
        previous = self.read_audit_data(section, key, include_expired_data=False)
        if previous != value:
            self.write_audit_data(section=section, key=key, value=value, value_date=value_date, expiration_date=expiration_date, max_count=max_count, keep_days=keep_days)
        return previous

    def write_audit_data(self, section, key, value, ptype=None, value_date=None, expiration_date=None, max_count=2, keep_days=None):
        """Stores in database a metrics, removes expired ones

        Args:
            section (str)
            key (str)
            value (any)
            value_date (str or datetime): value date (utc). By default datetime.datetime.utcnow()
            expiration_date (str) : expiration date of the new value
            max_count (int) : keep at most max_count value. remove oldest one.
            keep_days (int) : set the expiration date to now + keep_days days. override expiration_date arg if not None

        Returns:
            None

        """
        with self.waptdb:
            value = self._audit_data_to_db(value)
            # if value_date is not provided, use current timestamp
            if value_date is None:
                value_date = datetime2isodate(datetime.datetime.utcnow())

            if isinstance(value_date, datetime.datetime):
                value_date = datetime2isodate(value_date)

            if keep_days:
                expiration_date = datetime2isodate(datetime.datetime.utcnow() + datetime.timedelta(days=keep_days))

            self.waptdb.execute('insert or replace into wapt_audit_data(value_date,value_section,value_key,value,expiration_date) values (?,?,?,?,?)',
                (value_date,section,key,value,expiration_date))
            # removes expired values
            # current count of metric
            if max_count is not None:
                cur = self.waptdb.execute("""select min(value_date) from (select value_date from wapt_audit_data where value_section=? and value_key=? order by value_date desc limit ?)""",(section,key,max_count))
                if cur:
                    (min_value_date,) = cur.fetchone()
                    # delete oldest in order to keep at least max_count
                    self.waptdb.execute("""delete from wapt_audit_data where value_date<? and value_section=? and value_key=?""",
                        (min_value_date,section,key))

            self.waptdb.execute("""delete from wapt_audit_data where value_date<? and value_section=? and value_key=? and (expiration_date is null or expiration_date<?)""",
                (value_date,section,key,datetime2isodate(datetime.datetime.utcnow())))


    def read_audit_data(self, section, key, default=None, ptype=None, include_expired_data=True):
        """Retrieve the latest value associated with section/key from database"""
        if include_expired_data:
            expiration_date = '0000-00-00'
        else:
            expiration_date = datetime2isodate(datetime.datetime.utcnow())

        q = self.waptdb.execute('select value from wapt_audit_data where value_section=? and value_key=? and (expiration_date is null or expiration_date >= ?) order by value_date desc limit 1', (section,key,expiration_date)).fetchone()
        if q:
            (value, ) = q
            value = self._audit_data_from_db(value,ptype)
            if value is None:
                value = default
            return value
        else:
            return default

    def read_audit_data_set(self, section, key, as_dict=False, raw_data=False, descending=True):
        """Retrieve all the values associated with section/key from database"""
        if descending:
            desc='desc'
        else:
            desc=''
        for (value, value_date, expiration_date) in self.waptdb.execute("""\
            select value,value_date,expiration_date from wapt_audit_data
            where value_section=? and value_key=?
            order by value_date %s
            """ % desc, (section,key)).fetchall():
            if raw_data:
                if as_dict:
                    yield dict(value=value, value_date=value_date, expiration_date=expiration_date)
                else:
                    yield (value, value_date, expiration_date)
            else:
                if as_dict:
                    yield dict(value=self._audit_data_from_db(value), value_date=value_date, expiration_date=expiration_date)
                else:
                    yield (self._audit_data_from_db(value), value_date, expiration_date)

    def delete_audit_data(self, section, key):
        with self:
            row = self.waptdb.execute('select value from wapt_audit_data where value_section=? and value_key like ? limit 1', (section,key,)).fetchone()
            if row:
                self.waptdb.execute('delete from wapt_audit_data where value_section=? and value_key like ?', (section,key,))

    def read_audit_data_since(self, last_query_date=None,raw_data=False):
        """Retrieve all the values associated with section/key from database"""
        if last_query_date is None:
            last_query_date=''
        yield ('id','value_section', 'value_key', 'value_date', 'value', 'expiration_date')
        for (id,value_section, value_key, value_date, value, expiration_date) in self.waptdb.execute("""\
            select id,value_section, value_key, value_date, value, expiration_date from wapt_audit_data
            where value_date > ?
            order by value_date
            """, (last_query_date,)).fetchall():
            if raw_data:
                yield (
                    id,
                    value_section,
                    value_key,
                    value_date,
                    value,
                    expiration_date)
            else:
                yield (
                    id,
                    value_section,
                    value_key,
                    value_date,
                    self._audit_data_from_db(value),
                    expiration_date)

    def get_next_audit_datetime(self):
        """Return next datetime for next audit loop
        = minimum(next_audit_date)
        """
        with self.waptdb:
            query = self.waptdb.query("select min(next_audit_on) as next_audit from wapt_localstatus l where l.install_status <> 'ERROR' and (next_audit_on is not null and next_audit_on<>'') and (next_audit_on > last_audit_on)")
            if query:
                isots = query[0]['next_audit']
                if isots:
                    d = isodate2datetime(isots)
                    d_stripseconds = datetime.datetime(d.year,d.month,d.day,d.hour,d.minute) # strip the seconds
                    return d_stripseconds
                else:
                    return None
            else:
                return None

    def call_python_code(self, python_filename, func_name, package_entry=None, force = None, params=None, working_dir = None, import_modules = []):
        """Calls a function in python_filename.
        Set basedir, control, and run context within the function context.

        Args:
            python_filename : python filename mith module to load.
            func_name (str): name of function to call in setuppy
            package_entry (PackageEntry): if not None, use it to set environment
        Returns:
            output of hook.

        """

        if not os.path.isfile(python_filename):
            raise Exception('Python file not found: %s, aborting.' % ensure_unicode(python_filename))

        if working_dir is None:
            working_dir = os.path.abspath(os.path.dirname(python_filename))

        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        try:
            previous_cwd = os.getcwd()
            os.chdir(working_dir)

            # import the setup module from package file
            logger.info("  sourcing py file %s " % ensure_unicode(python_filename))
            # import code as file to allow debugging.
            setup = import_setup(python_filename)

            hook_func = getattr(setup, func_name, None)
            if hook_func is None:
                raise EWaptMissingPackageHook('No %s function found in %s module' % (func_name, python_filename))

            try:
                # import all names from modules.
                for module_name in import_modules:
                    try:
                        module_info =  imp.find_module(module_name)
                        code = module_info[0].read()
                        exec(code, setup.__dict__)
                    except ImportError as e:
                        logger.critical('Unable to import implicit module %s : %s' % (module_name,e))

                if package_entry:
                    package_entry._set_hook_module_environment(setup, wapt_context=self, params=params, force=force, user=self.user)

                logger.info("  executing %s" % (func_name, ))
                with _disable_file_system_redirection():
                    hookdata = hook_func()
                return hookdata
            except Exception as e:
                logger.critical('Fatal error in %s  %s:\n%s' % (func_name, ensure_unicode(e), ensure_unicode(traceback.format_exc())))
                raise e

        finally:
            os.chdir(previous_cwd)
            gc.collect()
            if 'setup' in dir() and setup is not None:
                setup_name = setup.__name__[:]
                logger.debug('Removing module: %s, refcnt: %s' % (setup_name, sys.getrefcount(setup)))
                del setup
                if setup_name in sys.modules:
                    del sys.modules[setup_name]
            sys.path = oldpath

    def get_json_config_filename(self,config_name):
        """Returns the filename for a json config named <config_name>
        """
        return setuphelpers.makepath(self.configs_dir, config_name + ".json")

    def install_json_config(self, conf, config_name=None, priority=None):
        """Add a dynamic configuration from dict conf with name  config_name
        and priority
        """
        try:
            if not type(conf) == dict:
                raise EWaptException('JSON Config object must be a dict not a %s' % (type(conf)))
            if config_name is None:
                config_name = conf.get('name')
            if not config_name:
                raise EWaptException('Unable to install json config, no config_name')

            # awful hack, as repo-sync is not a valid identifier, we store 'reposync' key in json
            # but keep  [repo-sync] section name in ini file for compat.
            if 'reposync' in conf:
                conf['repo-sync'] = conf['reposync']
                del conf['reposync']

            if not type(conf) is dict:
                raise Exception('Json configuration is not a dict')

            if priority:
                conf['priority'] = int(priority)

            # first remove previous files
            self.remove_json_config(config_name)

            # extract packages signer certificates
            crts = conf.get('certificates', {})
            for key in crts:
                crt_dest = setuphelpers.makepath(self.public_certs_dir, "%s-%s.crt" % (config_name, key))
                with open(crt_dest, "w") as f:
                    f.write(crts[key])

            for section in conf:
                # these are managed specifically
                if section in ('priority','name','certificates','server_certificates'):
                    continue
                if not isinstance(conf[section],dict):
                    continue
                # change verify_cert fileid into a filename
                if conf[section].get('verify_cert', None):
                    if conf[section]['verify_cert'].lower().strip() in ['0','1','true','false']:
                        conf[section]['verify_cert'] = conf[section]['verify_cert']
                    else:
                        # extract TLS server certificates
                        cert_server = setuphelpers.makepath(self.public_certs_dir,'server',config_name + '-' + conf[section]['verify_cert'] + '.crt')
                        with open(cert_server, "w") as f:
                            f.write(conf['server_certificates'][conf[section]['verify_cert']])
                        conf[section]['verify_cert'] = cert_server

            # Copy the json config as a josn file to <wapt>/conf.d
            config_filename = self.get_json_config_filename(config_name)
            with open(config_filename, "w") as config_file:
                config_file.write(json.dumps(conf))

            return (os.path.isfile(config_filename), config_filename)

        except Exception as e:
            raise Exception("Invalid json configuration %s:\n%s" % (config_name, str(e)))

    def install_json_configb64(self,json_config_b64, config_name=None, priority=None):
        """Install a json config encoded as a base64 string"""
        try:
            json_config = json.loads(base64.b64decode(json_config_b64.encode('utf-8')).decode('utf-8'))
            return self.install_json_config(json_config, config_name, priority)
        except:
            raise Exception("Invalid base64 json configuration : \n%s" % json_config_b64)

    def install_json_config_from_url(self,url=None, config_hash=None, config_name='default_config', priority=None):
        """Load a json config from the remote wapt server (default location is /var/www/wapt/conf.d/<config_name>-<config_hash>.json)
        given its name and hash.
        """
        if url is None and self.waptserver:
            url = "wapt/conf.d/%s_%s.json" % (config_name, config_hash)
            json_config = self.waptserver.get(url,decode_json=False)
        elif url is None and self.repositories:
            url = "%s/conf.d/%s_%s.json" % (self.repositories[0].repo_url, config_name, config_hash)
            with self.repositories[0].get_requests_session as session:
                json_config = session.get(url).content
            return self.install_json_config(json_config, config_name, priority)
        else:
            json_config = wgets(url,verify_cert = not config_hash)

        if sha256_for_data(json_config) != config_hash:
            raise EWaptException('Bad sha256 checksum for config from url %s' % url)

        res = self.install_json_config(json.loads(json_config), config_name, priority=priority)

        return res

    def install_json_config_file(self,json_config_file, config_name=None, priority=None):
        """Install a json config stored in a file"""
        if not os.path.isfile(json_config_file):
            raise Exception("%s configuration file not found" % json_config_file)
        with open(json_config_file, "r") as file:
            json_config = json.load(file)
        return self.install_json_config(json_config, config_name, priority)

    def get_json_config_certificates_filenames(self,config_name):
        # get the list of filenames of signers certificates provided by this configuration
        config_filename = self.get_json_config_filename(config_name)
        result = []
        if os.path.isfile(config_filename):
            with open(config_filename, "r") as config_file:
                json_config = json.load(config_file)
                crts = json_config.get('certificates', [])
                for key in crts:
                    crt_filename = setuphelpers.makepath(self.public_certs_dir, "%s-%s.crt" % (config_name, key))
                    result.append(crt_filename)
        return result

    def remove_json_config(self,config_name):
        """Remove a json config given its name"""
        previous_json = None
        filename = self.get_json_config_filename(config_name)
        if os.path.isfile(filename):
            # load the config as a dict from json file.
            with open(filename, "r") as file:
                json_config = json.load(file)
                previous_json = file.read()

            os.remove(filename)

            # remove the package signers certificates
            crts = json_config.get('certificates', [])
            for key in crts:
                crt_filename = setuphelpers.makepath(self.public_certs_dir, "%s-%s.crt" % (config_name, key))
                if os.path.isfile(crt_filename):
                    os.unlink(crt_filename)

            # loop over the sections to remove the TLS certificates
            for section in json_config:
                # these are managed specifically
                if section in ('priority','name','certificates','server_certificates'):
                    continue

                if not isinstance(json_config[section],dict):
                    continue

                if json_config[section].get('verify_cert'):
                    verify_cert = json_config[section]['verify_cert']
                    if not verify_cert.lower().strip() in ['0','1','true','false']:
                        verify_cert_filename = setuphelpers.makepath(self.public_certs_dir,'server','%s-%s.crt' % (config_name,verify_cert))
                        if os.path.isfile(verify_cert_filename):
                            os.unlink(verify_cert_filename)

        return previous_json

def wapt_sources_edit(wapt_sources_dir: str, editor_for_packages: str = None) -> str:
    r"""Utility to open PyScripter or the configured editor with package sources if it is installed
        else open the wapt package development directory in System Shell Explorer.

    Args
        wapt_sources_dir (str): directory path of the wapt package sources

    Returns:
        str: sources path

    """
    wapt_sources_dir = ensure_unicode(wapt_sources_dir)
    if waptlicences:
        print(waptlicences.edit_wapt_sources(wapt_sources_dir, editor_for_packages=editor_for_packages or ''))
    else:
        params = {
            "wapt_base_dir": os.path.dirname(__file__),
            "wapt_sources_dir": wapt_sources_dir,
            "setup_filename": os.path.join(wapt_sources_dir, "setup.py"),
            "control_filename": os.path.join(wapt_sources_dir, "WAPT", "control"),
            "changelog_filename": os.path.join(wapt_sources_dir, "WAPT", "changelog.txt"),
            "update_package_filename": os.path.join(wapt_sources_dir, "update_package.py"),
        }
        params_vscod_list = [params["wapt_sources_dir"], params["setup_filename"], params["control_filename"], params["update_package_filename"], params["changelog_filename"]]

        # in edit_for_packages you can specify {key_params} to replace for launch the editor

        env = os.environ
        env.update(dict(PYTHONPATH=params["wapt_base_dir"], VIRTUAL_ENV=params["wapt_base_dir"]))

        if os.name == "nt":
            if not (editor_for_packages) or editor_for_packages == "pyscripter":
                pyscripter_filename = os.path.join(setuphelpers.programfiles32, "PyScripter", "PyScripter.exe")
                if sys.platform == "win32" and os.path.isfile(pyscripter_filename):
                    params["psproj_filename"] = os.path.join(wapt_sources_dir, "WAPT", "wapt.psproj")
                    setuphelpers.run_as_administrator(
                        pyscripter_filename,
                        '--PYTHONDLLPATH="{wapt_base_dir}" --python38 -N --project="{psproj_filename}" "{setup_filename}" "{control_filename}" "{update_package_filename}" "{changelog_filename}"'.format(
                            **params
                        ),
                    )
                elif shutil.which("code"):
                    command = [shutil.which("code"), *params_vscod_list]
                    run(command)
                elif shutil.which("codium"):
                    command = [shutil.which("codium"), *params_vscod_list]
                    run(command)
                else:
                    os.startfile(params["wapt_sources_dir"])
            else:
                try:
                    exe_file = ""
                    if editor_for_packages.strip("vs") in ["code", "codium", "vscode", "vscodium"] and os.path.isfile(
                        shutil.which(editor_for_packages.strip("vs"))
                    ):
                        exe_file = shutil.which(editor_for_packages.strip("vs"))
                    elif editor_for_packages.find(".exe") != -1 and os.path.isfile(editor_for_packages[: editor_for_packages.find(".exe") + 4]):
                        exe_position = editor_for_packages.find(".exe")
                        exe_file = editor_for_packages[: exe_position + 4]
                    if exe_file:
                        command = [exe_file, *params_vscod_list]
                        run(command)
                    else:
                        os.startfile(params["wapt_sources_dir"])
                except:
                    os.startfile(params["wapt_sources_dir"])
        else:
            command = []
            list_supported_editor = ["codium", "vscodium", "vscode", "code", "nano", "vim", "vi"]
            if (editor_for_packages is not None) and (editor_for_packages not in list_supported_editor):
                space_sep = editor_for_packages.find(" ")
                params_string = editor_for_packages[space_sep + 1 :].format(**params)
                command = [editor_for_packages, params_string]
            elif shutil.which("codium") and ((editor_for_packages is None) or (editor_for_packages in ["codium", "vscodium"])):
                command = ["codium", *params_vscod_list]
            elif shutil.which("code") and ((editor_for_packages is None) or (editor_for_packages in ["code", "vscode"])):
                command = ["code", *params_vscod_list]
            elif shutil.which("nano") and ((editor_for_packages is None) or (editor_for_packages == "nano")):
                command = ["nano", params["setup_filename"]]
            elif shutil.which("vim") and ((editor_for_packages is None) or (editor_for_packages == "vim")):
                command = ["vim", params["setup_filename"]]
            elif shutil.which("vi") and ((editor_for_packages is None) or (editor_for_packages == "vi")):
                command = ["vi", params["setup_filename"]]
            if command:
                subprocess.call(command)
        return wapt_sources_dir


def sid_from_rid(domain_controller, rid):
    """Return SID structure based on supplied domain controller's domain and supplied rid
    rid can be for example DOMAIN_GROUP_RID_ADMINS, DOMAIN_GROUP_RID_USERS
    """
    umi2 = win32net.NetUserModalsGet(domain_controller, 2)
    domain_sid = umi2['domain_id']

    sub_authority_count = domain_sid.GetSubAuthorityCount()

    # create and init new sid with acct domain Sid + acct rid
    sid = pywintypes.SID()
    sid.Initialize(domain_sid.GetSidIdentifierAuthority(),
                   sub_authority_count+1)

    # copy existing subauthorities from account domain Sid into
    # new Sid
    for i in range(sub_authority_count):
        sid.SetSubAuthority(i, domain_sid.GetSubAuthority(i))

    # append Rid to new Sid
    sid.SetSubAuthority(sub_authority_count, rid)
    return sid


def lookup_name_from_rid(domain_controller, rid):
    """ return username or group name from RID (with localization if applicable)
        from https://mail.python.org/pipermail/python-win32/2006-May/004655.html
        domain_controller : should be a DC
        rid : integer number (512 for domain admins, 513 for domain users, etc.)
    >>> lookup_name_from_rid('srvads', DOMAIN_GROUP_RID_ADMINS)
    u'Domain Admins'

    """
    sid = sid_from_rid(domain_controller, rid)
    name, domain, typ = win32security.LookupAccountSid(domain_controller, sid)
    return name


def get_domain_admins_group_name():
    r"""Return localized version of domain admin group (ie "domain admins" or
                 "administrateurs du domaine" with RID -512)

    >>> get_domain_admins_group_name()
    u'Domain Admins'
    """
    try:
        target_computer = win32net.NetGetAnyDCName()
        name = lookup_name_from_rid(target_computer, DOMAIN_GROUP_RID_ADMINS)
        return name
    except Exception as e:
        logger.debug('Error getting Domain Admins group name : %s' % e)
        return 'Domain Admins'


def get_local_admins_group_name():
    sid = win32security.GetBinarySid('S-1-5-32-544')
    name, domain, typ = win32security.LookupAccountSid(setuphelpers.wincomputername(), sid)
    return name


def check_is_member_of(huser, group_name):
    """Check if a user is a member of a group

    Args:
        huser (handle) : pywin32
        group_name (str) : group

    >>> from win32security import LogonUser
    >>> hUser = win32security.LogonUser ('technique','tranquilit','xxxxxxx',win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    >>> check_is_member_of(hUser,'domain admins')
    False
    """
    try:
        sid, system, type = win32security.LookupAccountName(None, group_name)
    except:
        logger.debug('"%s" is not a valid group name' % group_name)
        return False
    return win32security.CheckTokenMembership(huser, sid)


def check_user_membership(user_name, password, domain_name, group_name):
    """Check if a user is a member of a group

    Args:
        user_name (str): user
        password (str):
        domain_name (str) : If empty, check local then domain
        group_name (str): group

    >>> from win32security import LogonUser
    >>> hUser = win32security.LogonUser ('technique','tranquilit','xxxxxxx',win32security.LOGON32_LOGON_NETWORK,win32security.LOGON32_PROVIDER_DEFAULT)
    >>> check_is_member_of(hUser,'domain admins')
    False
    """
    try:
        sid, system, type = win32security.LookupAccountName(None, group_name)
    except pywintypes.error as e:
        if e.args[0] == 1332:
            logger.warning('"%s" is not a valid group name' % group_name)
            return False
        else:
            raise
    huser = win32security.LogonUser(user_name, domain_name, password, win32security.LOGON32_LOGON_NETWORK, win32security.LOGON32_PROVIDER_DEFAULT)
    return win32security.CheckTokenMembership(huser, sid)

def self_service_rules(wapt):
    """Returns dict of allowed packages for users and groups
    """
    cur = wapt.waptdb.execute("""select package,persistent_dir from wapt_localstatus s where s.section='selfservice' and s.persistent_dir is not null""")
    result = {}
    for (package, persistent_dir) in cur.fetchall():
        if persistent_dir:
            rules_fn = setuphelpers.makepath(persistent_dir, 'selfservice.json')
            if os.path.isfile(rules_fn):
                with open(rules_fn, 'r') as f:
                    rules = json.load(f)
                for group, packages in rules.items():
                    if not group.lower() in result:
                        result[group.lower()] = packages
                    else:
                        group_packages = result[group.lower()]
                        for package in packages:
                            if not package in group_packages:
                                group_packages.append(package)
    return result


def authorized_packages_for_token(wapt, token, secret_key, package_requests=None):
    token_gen = wapt.get_secured_token_generator(secret_key)

    max_age = wapt.token_lifetime
    user_pac = token_gen.loads(token, max_age=max_age)
    user_groups = user_pac.get('groups', [])

    rules = self_service_rules(wapt)

    result = []
    if package_requests is None:
        for group in user_groups:
            for package in rules.get(group, []):
                if not package in result:
                    result.append(package)
    else:
        for package_request in package_requests:
            if isinstance(package_request, PackageRequest):
                pr = package_request
            elif isinstance(package_request, str):
                pr = PackageRequest(pr)
            elif isinstance(package_request, PackageEntry):
                pr = package_request.as_package_request()
            else:
                continue

            for group in user_groups:
                if pr.package in rules.get(group, []):
                    result.append(pr)
                    break

    return result


# for backward compatibility
Version = setuphelpers.Version  # obsolete

if __name__ == '__main__':
    sys.exit(0)
