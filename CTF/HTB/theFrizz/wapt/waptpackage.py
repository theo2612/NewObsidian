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

#from waptutils import __version__

__all__ = [
    'control_to_dict',
    'parse_major_minor_patch_build',
    'make_version',
    'PackageVersion',
    'PackageVersionStr',
    'PackageRequest',
    'PackageEntry',
    'HostCapabilities',
    'WaptBaseRepo',
    'WaptLocalRepo',
    'WaptRemoteRepo',
    'update_packages',
    'REGEX_PACKAGE_VERSION',
    'REGEX_PACKAGE_CONDITION',
    'ArchitecturesList',
    'EWaptException',
    'EWaptBadSignature',
    'EWaptCorruptedFiles',
    'EWaptNotSigned',
    'EWaptBadControl',
    'EWaptBadSetup',
    'EWaptNeedsNewerAgent',
    'EWaptDiskSpace',
    'EWaptBadPackageAttribute',
    'EWaptNotAPackage',
    'EWaptDownloadError',
    'EWaptMissingLocalWaptFile',
    'EWaptNeedsNewerAgent',
    'EWaptConfigurationError',
    'EWaptUnavailablePackage',
    'EWaptNotSourcesDirPackage',
    'EWaptPackageSignError',
    'EWaptConflictingPackage',
    'EWaptInstallPostponed',
    'EWaptInstallError',
]


import os
import zipfile
import io
import hashlib
import logging
import glob
import codecs
import re
import time
import json
try:
    import ujson
except ImportError:
    import json as ujson

import sys
import requests
import datetime
import tempfile
import shutil
import base64
import copy
import gc
import uuid

from iniparse import RawConfigParser
import traceback

from typing import Sequence,Union,List,Tuple

from waptutils import BaseObjectClass, Version, ensure_unicode, CustomZipFile
from waptutils import create_recursive_zip, ensure_list, all_files, all_empty_dirs, list_intersection
from waptutils import datetime2isodate, httpdatetime2isodate, httpdatetime2datetime, fileutcdate, fileisoutcdate, isodate2datetime
from waptutils import wget, get_language, import_setup, import_code
from waptutils import _disable_file_system_redirection
from waptutils import get_requests_client_cert_session
from waptutils import safe_cmp_tuples,safe_cmp
from waptutils import _hash_file, sanitize_filename,is_unsafe_filename

from waptcrypto import EWaptMissingCertificate, EWaptBadCertificate
from waptcrypto import SSLCABundle, SSLCertificate, SSLCRL, EWaptCryptoException
from waptcrypto import SSLVerifyException, serialize_content_for_signature
from waptutils import is_pem_key_encrypted, makepath, hexdigest_for_data
from waptutils import get_verify_cert

logger = logging.getLogger('waptcore')

# From Semantic Versioning : http://semver.org/ by Tom Preston-Werner,
# valid : 0.0-0  0.0.0-0 0.0.0.0-0
REGEX_PACKAGE_VERSION = re.compile(r'^(?P<major>[0-9]+)'
                                   '(\.(?P<minor>[0-9]+))?'
                                   '(\.(?P<patch>[0-9]+))?'
                                   '(\.(?P<subpatch>[0-9]+))?'
                                   '(\-(?P<packaging>[0-9A-Za-z]+(\.[0-9A-Za-z]+)*))?$')

# tis-exodus(>2.3.4-10)
# changed in 1.6.2.4
REGEX_PACKAGE_CONDITION = re.compile(r'(?P<package>[^()]+)\s*(\(\s*(?P<operator>[<=>]*)\s*(?P<version>\S+)\s*\))?')

REGEX_VERSION_CONDITION = re.compile(r'(?P<operator>[<=>]*)\s*(?P<version>\S+)')

DEFAULT_EXCLUDED_PATHS_FOR_BUILD = ['.svn', '.git', 'setup.pyc', 'update_package.pyc', '__pycache__/setup.cpython-38.pyc', '__pycache__/update_package.cpython-38.pyc']

def parse_major_minor_patch_build(version):
    """Parse version to major, minor, patch, pre-release, build parts.
    """
    match = REGEX_PACKAGE_VERSION.match(version)
    if match is None:
        raise ValueError('%s is not valid SemVer string' % version)

    verinfo = match.groupdict()

    def int_or_none(name):
        if name in verinfo and verinfo[name] != None:
            return int(verinfo[name])
        else:
            return None
    verinfo['major'] = int_or_none('major')
    verinfo['minor'] = int_or_none('minor')
    verinfo['patch'] = int_or_none('patch')
    verinfo['subpatch'] = int_or_none('subpatch')

    return verinfo


def make_version(major_minor_patch_build):
    p1 = '.'.join(["%s" % major_minor_patch_build[p] for p in ('major', 'minor', 'patch', 'subpatch') if major_minor_patch_build[p] != None])
    if major_minor_patch_build['packaging'] != None:
        return '-'.join([p1, major_minor_patch_build['packaging']])
    else:
        return p1


ArchitecturesList = ('all', 'x86', 'x64', 'arm', 'arm64', 'armhf')


class EWaptException(Exception):
    pass


class EWaptBadSignature(EWaptException):
    pass


class EWaptDownloadError(EWaptException):
    pass


class EWaptCorruptedFiles(EWaptException):
    pass


class EWaptNotSigned(EWaptException):
    pass


class EWaptBadControl(EWaptException):
    pass


class EWaptBadSetup(EWaptException):
    pass


class EWaptNeedsNewerAgent(EWaptException):
    pass


class EWaptDiskSpace(EWaptException):
    pass

class EWaptNotAPackage(EWaptException):
    pass

class EWaptBadPackageAttribute(EWaptException):
    pass

class EWaptNotSourcesDirPackage(EWaptException):
    pass


class EWaptMissingPackageHook(EWaptException):
    pass


class EWaptPackageSignError(EWaptException):
    pass


class EWaptInstallError(EWaptException):
    """Exception raised during installation of package
    msg is logged in local install database
    if retry_count is None, install will be retried indefinitely until success
    else install is retried at most retry_count times.
    """

    def __init__(self, msg, install_status='ERROR', retry_count=None):
        Exception.__init__(self, msg)
        self.install_status = install_status
        self.retry_count = retry_count


class EWaptInstallPostponed(EWaptInstallError):
    def __init__(self, msg, install_status='POSTPONED', retry_count=5, grace_delay=3600):
        EWaptInstallError.__init__(self, msg, install_status, retry_count)
        self.grace_delay = grace_delay


class EWaptUnavailablePackage(EWaptInstallError):
    pass


class EWaptConflictingPackage(EWaptInstallError):
    pass


class EWaptRemoveError(EWaptException):
    pass


class EWaptConfigurationError(EWaptException):
    pass


class EWaptMissingLocalWaptFile(EWaptException):
    pass


class HostCapabilities(BaseObjectClass):
    __all_attributes = ['uuid', 'language', 'os', 'tags', 'os_version', 'kernel_version', 'architecture', 'dn', 'fqdn',
                        'site', 'wapt_version', 'wapt_edition', 'packages_trusted_ca_fingerprints',
                        'packages_blacklist', 'packages_whitelist', 'packages_locales',
                        'packages_maturities', 'use_hostpackages', 'host_packages_names',
                        'host_profiles', 'host_certificate_fingerprint', 'host_certificate_authority_key_identifier', 'on_date']

    def __init__(self, from_dict=None, from_string_filter=None,  **kwargs):
        self.uuid = None
        self.language = None
        self.os = None
        self.tags = []
        self.os_version = None
        self.kernel_version = None
        self.architecture = None
        self.dn = None
        self.fqdn = None
        self.site = None
        self.wapt_version = None
        self.wapt_edition = None
        self.packages_trusted_ca_fingerprints = None
        self.packages_blacklist = None
        self.packages_whitelist = None
        self.packages_locales = None
        self.packages_maturities = None
        self.use_hostpackages = None
        self.host_profiles = None
        self.host_packages_names = None
        self.host_certificate_fingerprint = None
        self.host_certificate_authority_key_identifier = None
        self.on_date = None

        # for fpc init
        if from_dict is not None:
            for (k, v) in from_dict.items():
                if hasattr(self, k):
                    setattr(self, k, v)
                else:
                    #raise Exception('HostCapabilities has no attribute %s' % k)
                    logger.critical('HostCapabilities has no attribute %s : ignored' % k)

        if from_string_filter is not None:
            # ex: :'windows~10.0.18363~x64~windows-19H2|windows-1909~fr|en~PREPROD|PROD'
            (self.os, self.os_version, self.architecture, tags, locales, maturities) = from_string_filter.split('~')[0:6]
            self.tags = tags.split('|')
            self.packages_locales = locales.split('|')
            self.packages_maturities = maturities.split('|')


        for (k, v) in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                #raise Exception('HostCapabilities has no attribute %s' % k)
                logger.critical('HostCapabilities has no attribute %s : ignored' % k)

    def __getitem__(self, name):
        if name is str:
            name = name.lower()
        if hasattr(self, name):
            return getattr(self, name)
        else:
            raise Exception('%s : No such attribute : %s' % (self.__class__.__name__, name))

    def __iter__(self):
        for key in self.__all_attributes:
            yield (key, getattr(self, key))

    def as_dict(self):
        return dict(self)

    def fingerprint(self):
        return hashlib.sha256(serialize_content_for_signature(self.as_dict())).hexdigest()

    def get_package_request_filter(self):
        """Returns a filter for package search in repositories

        Returns:
            PackageRequest
        """
        return PackageRequest(
            architectures=ensure_list(self.architecture),
            locales=ensure_list(self.packages_locales),
            maturities=self.packages_maturities,
            tags=self.tags[:] if self.tags else None,  # be sure to not share list, get it by value
            min_os_version=self.os_version,
            max_os_version=self.os_version,
        )

    def has_matching_target(self,package_entry):

        def evaluate_condition_target(acond, avalue):
            version_avalue=Version(avalue)
            version_acond=Version(acond[1])

            def eq(): return version_avalue == version_acond
            def ne(): return version_avalue != version_acond
            def ge(): return version_avalue >= version_acond
            def gt(): return version_avalue > version_acond
            def le(): return version_avalue <= version_acond
            def lt(): return version_avalue < version_acond

            return {
                '==': eq,
                '<=': le,
                '>=': ge,
                '<>': ne,
                '!=': ne,
                '<': lt,
                '>': gt,
                '=': eq,
            }[acond[0]]()

        def target_is_matching(atarget):
            return atarget[0] in self.tags and (not atarget[1] or atarget[0] in ['all', 'unix'] or \
                (atarget[0] in ['linux', 'darwin'] and all(evaluate_condition_target(acond, self.kernel_version) for acond in atarget[1])) or \
                (atarget[0]==self.os and all(evaluate_condition_target(acond, self.os_version) for acond in atarget[1])))

        return not self.tags or not package_entry.target_os or 'all' in package_entry.tags or any(target_is_matching(atarget) for atarget in package_entry.target_os_list)


    def is_matching_package(self, package_entry, for_datetime=None, errors_list=None):
        """Check if package_entry is matching the current capabilities and restrictions

        """
        def error(msg):
            if errors_list is not None:
                errors_list.append(msg)
            return False

        if for_datetime is not None:
            if package_entry.valid_from and package_entry.valid_from > for_datetime:
                return error("Attribute valid_from (%s) doesn't allow the current date (%s)" % (package_entry.valid_from, for_datetime))

            if package_entry.valid_until and for_datetime >= package_entry.valid_until:
                return error("Attribute valid_until (%s) doesn't allow the current date (%s)" % (package_entry.valid_until, for_datetime))

        if self.packages_blacklist is not None:
            for bl in self.packages_blacklist:  # pylint: disable=not-an-iterable
                if glob.fnmatch.fnmatch(package_entry.package, bl):
                    return error("This package (%s) is blacklisted on this agent (blacklist entry: %s)" % (package_entry.package, bl))

        if self.packages_whitelist is not None:
            allowed = False
            for wl in self.packages_whitelist:  # pylint: disable=not-an-iterable
                if glob.fnmatch.fnmatch(package_entry.package, wl):
                    allowed = True
                    break
            if not allowed:
                return error("This package (%s) is not in the agent whitelist (%s)" % (package_entry.package, ",".join(self.packages_whitelist)))

        if self.wapt_version is not None and package_entry.min_wapt_version and Version(package_entry.min_wapt_version) > Version(self.wapt_version):
            return error("This package needs a wapt version %s but the agent is on wapt %s" % (package_entry.min_wapt_version, self.wapt_version))

        if not self.has_matching_target(package_entry):
            return error("Package target doesn't match this agent" )

        package_request = self.get_package_request_filter()
        return package_request.is_matched_by(package_entry, errors_list=errors_list)

    def __repr__(self):
        return repr(self.as_dict())


class PackageKey(object):
    def __init__(self, package_uuid=None, package=None, version=None, architecture=None, locale=None, maturity=None, **kwargs):
        self.package_uuid = package_uuid
        self.package = package
        self.version = version
        self.architecture = architecture
        self.locale = locale
        self.maturity = maturity
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

    def __str__(self):
        def and_list(v):
            if isinstance(v, list) or isinstance(v, tuple):
                return ','.join(ensure_list(v))
            else:
                return v
        attribs = []
        attribs.extend(["%s" % (ensure_unicode(and_list(getattr(self, a)))) for a in ['architecture', 'locale', 'maturity']
                        if getattr(self, a) is not None and getattr(self, a) != '' and getattr(self, a) != 'all'])
        if attribs:
            attribs = ' [%s]' % '_'.join(attribs)
        else:
            attribs = ''
        return "%s (=%s)%s" % (self.package, self.version, attribs)

    def __iter__(self):
        return iter((self.package, self.version, self.architecture, self.locale, self.maturity))

    def as_dict(self):
        return dict(
            package=self.package,
            version=self.version,
            architecture=self.architecture,
            locale=self.locale,
            maturity=self.maturity,
        )

    def __repr__(self):
        return repr(self.as_dict())

    def __cmp__(self, other):
        if self.package_uuid and other.package_uuid and self.package_uuid == other.package_uuid:
            return 0
        return safe_cmp_tuples((self.package, self.version, self.architecture, self.locale, self.maturity), (other.package, other.version, other.architecture, other.locale, other.maturity))

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return self.__cmp__(other) != 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __ge__(self, other):
        return self.__cmp__(other) >= 0

    def __le__(self, other):
        return self.__cmp__(other) <= 0


def PackageVersion(package_or_versionstr) -> Tuple:
    """Splits a version string 1.2.3.4-567
    software version is clipped to 4 members
    if '-packaging' is not provided, the second member will be 0 for safe comparison

    Args:
        package_or_versionstr (str): package version string

    Returns:
        tuple: (Version,int) : soft version on 4 members / packaging as an int

    """
    if isinstance(package_or_versionstr, PackageEntry):
        package_or_versionstr = package_or_versionstr.version
    if isinstance(package_or_versionstr, Version):
        return (Version(package_or_versionstr, 4), 0)
    version_build = package_or_versionstr.split('-', 1)
    if len(version_build) > 1:
        return (Version(version_build[0], 4), int(version_build[1]))
    else:
        return (Version(version_build[0], 4), 0)

def PackageVersionStr(package_or_versionstr) -> Tuple:
    """Splits a version string 1.2.3.4-567
    software version is clipped to 4 members
    if '-packaging' is not provided, the second member will be 0 for safe comparison

    Args:
        package_or_versionstr (str): package version string

    Returns:
        tuple: (Version,int) : soft version on 4 members / packaging as an int

    """
    if isinstance(package_or_versionstr, PackageEntry):
        package_or_versionstr = package_or_versionstr.version
    if isinstance(package_or_versionstr, Version):
        return (Version(package_or_versionstr, 4), 0)
    version_build = package_or_versionstr.split('-', 1)
    if len(version_build) > 1:
        return Version(version_build[0], 4).sortable_str()+'-%08d'%int(version_build[1])
    else:
        return Version(version_build[0], 4).sortable_str()+'-%08d' % 0



class PackageRequest(BaseObjectClass):
    """Package and version request / condition
    The request is the basic packagename(=version) request
    Additional filters can be specified as arguments
    The list filters are ordered from most preferred to least preferred options

    Args:
        request (str): packagename(<=>version)
        architectures (list) : list of x64, x86, arm, arm64, armhf
        locales (list) : list of 2 letters lki

    """
    _attributes = ['package_uuid','package', 'version', 'architectures', 'locales', 'maturities', 'tags', 'min_os_version', 'max_os_version']

    def __init__(self, request=None, copy_from=None, **kwargs):
        self.package_uuid = None
        self.package = None
        self.version = None
        self.architectures = None
        self.locales = None
        self.maturities = None
        self.tags = None
        self.min_os_version = None
        self.max_os_version = None

        self._request = None
        self._package = None
        self._version_operator = None
        self._version = None
        self._architectures = None
        self._locales = None
        self._maturities = None
        self._tags = None
        self._min_os_version = None
        self._max_os_version = None

        if copy_from is not None:
            for k in self._attributes:
                setattr(self, k, getattr(copy_from, k))

        self.request = request

        for (k, v) in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise Exception('PackageRequest has no attribute %s' % k)

    @property
    def request(self):
        return self._request

    @request.setter
    def request(self, value):
        self._request = value
        if value:
            if value.startswith('{') and value.endswith('}'):
                self.package_uuid = value[1:-1]
                self._package = None
                self._version = None
                self._version_operator = None
            else:
                self.package_uuid = None
                package_version = REGEX_PACKAGE_CONDITION.match(value).groupdict()
                self._package = package_version['package']
                if package_version['operator'] is not None:
                    self._version_operator = package_version['operator']
                else:
                    self._version_operator = '='

                if package_version['version'] is not None:
                    self._version = PackageVersion(package_version['version'])
                else:
                    self._version = None
        else:
            self._package = None
            self._version = None
            self._version_operator = None
            self.package_uuid = None

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        if value is None:
            self._version_operator = None
            self._version = None
        else:
            package_version = REGEX_VERSION_CONDITION.match(value).groupdict()
            if package_version['operator'] is not None:
                self._version_operator = package_version['operator']
            else:
                self._version_operator = '='
            if package_version['version'] is not None:
                self._version = PackageVersion(package_version['version'])
            else:
                self._version = None

    @property
    def min_os_version(self):
        return self._min_os_version

    @min_os_version.setter
    def min_os_version(self, value):
        if value is not None and value != '':
            if isinstance(value,Version):
                self._min_os_version = value
            else:
                self._min_os_version = Version(value)
        else:
            self._min_os_version = None

    @property
    def max_os_version(self):
        return self._max_os_version

    @max_os_version.setter
    def max_os_version(self, value):
        if value is not None and value != '':
            if isinstance(value,Version):
                self._max_os_version = value
            else:
                self._max_os_version = Version(value)
        else:
            self._max_os_version = None

    def _is_matched_version(self, version):
        """Return True if this request is verified by the provided version

        Args:
            version (str or Version): version to check against this request

        Returns:
            bool : True if version is verified by this request
        """

        if self._version is None:
            return True
        else:
            possibilities_dict = {
                '>': (1,),
                '<': (-1,),
                '=': (0,),
                '==': (0,),
                '>=': (0, 1),
                '<=': (-1, 0)
            }
            possibilities = possibilities_dict[self._version_operator]
            if not isinstance(version, tuple):
                version = PackageVersion(version)
            if self._version[1] is None:
                # omit packaging in comparison
                cmp_res = safe_cmp(version[0], self._version[0])
            else:
                cmp_res = safe_cmp(version, self._version)
            return cmp_res in possibilities

    @property
    def package(self):
        return self._package or None

    @package.setter
    def package(self, value):
        if value:
            self._package = value
        else:
            self._package = None

    @property
    def architectures(self):
        """List of accepted architecturs"""
        return self._architectures

    @architectures.setter
    def architectures(self, value):
        if value in ('all', '', None):
            self._architectures = None
        else:
            self._architectures = ensure_list(value)

    @property
    def maturities(self) -> List:
        """List of accepted maturities"""
        return self._maturities

    @maturities.setter
    def maturities(self, value: List):
        """List of accepted maturities"""
        if value in ('all', '', None):
            self._maturities = None
        else:
            self._maturities = ensure_list(value, allow_none=True)

    @property
    def tags(self) -> list:
        """List of accepted tags for OS"""
        return self._tags

    @tags.setter
    def tags(self, value: List):
        """List of accepted tags for OS"""
        if not value:
            self._tags = None
        else:
            self._tags = ensure_list(value, allow_none=True)
            if 'linux' in self._tags:
                self._tags += ['ubuntu', 'debian', 'linuxmint', 'raspbian', 'rhel', 'centos', 'fedora', 'debian_based', 'rhel_based']
            elif 'unix' in self._tags:
                self._tags += ['ubuntu', 'debian', 'linuxmint', 'raspbian', 'rhel', 'centos', 'fedora', 'macos', 'darwin', 'linux']

    @property
    def locales(self) -> List:
        return self._locales

    @locales.setter
    def locales(self, value: List):
        if value in ('all', '', None):
            self._locales = None
        else:
            self._locales = ensure_list(value)

    def is_matched_by(self, package_entry: 'PackageEntry', errors_list=None):
        """Check if package_entry is matching this request"""
        def error(msg):
            errors_list.append(msg)
            return False

        if not (self.package_uuid is None or package_entry.package_uuid == self.package_uuid):
            if errors_list is None:
                return False
            return error("Package uuid (%s) doesn't match request uuid (%s)" % (package_entry.package_uuid, self.package_uuid))
        if not (self.package is None or package_entry.package == self.package):
            if errors_list is None:
                return False
            return error("Package (%s) doesn't match request (%s)" % (package_entry.package, self.package))
        if not (self.version is None or self._is_matched_version(package_entry.version)):
            if errors_list is None:
                return False
            return error("Package version (%s) doesn't match request version (%s)" % (package_entry.version, self.version))
        if not (not self.tags or ('all' in self.tags) or not package_entry.target_os or bool(set([acapa[0] for acapa in package_entry.target_os_list]).intersection(set(self.tags+['all'])))):
            if errors_list is None:
                return False
            return error("Package target_os (%s) doesn't match request tags (%s)" % (package_entry.target_os, ','.join(self.tags)))
        if not (self.min_os_version is None or not package_entry.max_os_version or Version(package_entry.max_os_version) >= self.min_os_version):
            if errors_list is None:
                return False
            return error("Package max_os_version (%s) doesn't include request min_os_version (%s)" % (package_entry.max_os_version, self.min_os_version))
        if not (self.max_os_version is None or not package_entry.min_os_version or Version(package_entry.min_os_version) <= self.max_os_version):
            if errors_list is None:
                return False
            return error("Package min_os_version (%s) doesn't include request max_os_version (%s)" % (package_entry.min_os_version, self.max_os_version))
        if not (self.architectures is None or package_entry.architecture in ('', 'all') or len(list_intersection(ensure_list(package_entry.architecture), self.architectures)) > 0):
            if errors_list is None:
                return False
            return error("Package architecture (%s) doesn't match request architectures (%s)" % (package_entry.architecture, self.architectures))
        if not (self.locales is None or package_entry.locale in ('', 'all') or len(list_intersection(ensure_list(package_entry.locale), self.locales)) > 0):
            if errors_list is None:
                return False
            return error("Package locale (%s) doesn't match request locales (%s)" % (package_entry.locale, self.locales))
        if not (self.maturities is None or (package_entry.maturity == '' and (self.maturities is None or 'PROD' in self.maturities)) or package_entry.maturity in self.maturities):
            if errors_list is None:
                return False
            return error("Package maturity (%s) doesn't match request maturities (%s)" % (package_entry.maturity, self.maturities))

        return True

    def __cmp__(self, other):
        if isinstance(other, str):
            other = PackageRequest(request=other)

        if isinstance(other, PackageRequest):
            return safe_cmp_tuples((self.package, self.version, self.tags, self.architectures, self.locales, self.maturities), (other.package, other.version, other.tags, other.architectures, other.locales, other.maturities))
        elif isinstance(other, PackageEntry):
            if self.is_matched_by(other):
                return 0
            else:
                return safe_cmp_tuples((self.package, self.tags, self.version, self.architectures, self.locales, self.maturities), (other.package, other.version, other.tags, other.architecture, other.locale, other.maturity))
        else:
            raise Exception('Unsupported comparison between PackageRequest and %s' % other)

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return self.__cmp__(other) != 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __ge__(self, other):
        return self.__cmp__(other) >= 0

    def __le__(self, other):
        return self.__cmp__(other) <= 0

    def __repr__(self):
        def or_list(v):
            if isinstance(v, list) or isinstance(v, tuple):
                return '|'.join(ensure_list(v))
            else:
                return v
        attribs = []
        attribs.extend(["%s=%s" % (a, repr(getattr(self, a))) for a in self._attributes if getattr(self, a) is not None and getattr(self, a) != '' and getattr(self, a) != 'all'])
        attribs = ','.join(attribs)
        return "PackageRequest(%s)" % attribs

    def __str__(self):
        def or_list(v):
            if isinstance(v, list) or isinstance(v, tuple):
                return ','.join(ensure_list(v))
            else:
                return v
        attribs = []
        attribs.extend(["%s" % (ensure_unicode(or_list(getattr(self, a)))) for a in ['architectures', 'locales', 'maturities']
                        if getattr(self, a) is not None and getattr(self, a) != '' and getattr(self, a) != 'all'])
        if attribs:
            attribs = ' [%s]' % '_'.join(attribs)
        else:
            attribs = ''
        return "%s%s" % (self.request, attribs)

    def get_package_compare_key(self, pe1: 'PackageEntry') -> Tuple:
        """Compute a key for a package to compare it with other in the context of this request.
        This takes in account the preferences from filter like order of locale, architecture, or maturities
        which define preferences.

        Args:
            pe1 (PackageEntry)

        Returns:
            tuple
        """
        def _safe_rev_index(alist, avalue):
            if avalue in ('', 'all'):
                return -1000
            elif alist and avalue in alist:
                return -alist.index(avalue)
            elif alist is None:
                return -ord(avalue[0])
            else:
                return -10000

        def _safe_rev_index_list(l1, l2):
            if l2 is None:
                return -1000
            if l1:
                for e1 in l1:
                    if e1 in l2:
                        return -l1.index(e1)
                return -10000
            return -10000

        return (
            pe1.package,
            (self.version is None and '') or PackageVersion(pe1.version),
            _safe_rev_index_list(self.tags, pe1.tags),
            _safe_rev_index(self.architectures, pe1.architecture),
            _safe_rev_index(self.locales, pe1.locale),
            _safe_rev_index(self.maturities, pe1.maturity),
        )

    def __iter__(self):
        for key in self._attributes:
            yield (key, getattr(self, key))

    def as_dict(self):
        return dict(self)

    def fingerprint(self):
        return hashlib.sha256(serialize_content_for_signature(self.as_dict())).hexdigest()


def control_to_dict(control, int_params=('size', 'installed_size'), out_excluded_control_keys=['filename', 'size', 'md5sum', 'repo_url', 'repo'], out_control_lines=None):
    """Convert a control file like object
    key1: value1
    key2: value2
    ...
    list of lines into a dict

    Multilines strings begins with a space

    Breaks when an empty line is reached (limit between 2 package in Packages indexes)

    Args:
        control (file,str or list): file like object to read control from (until an empty line is reached)
        int_params (list): attributes which must be converted to int
        out_control_lines (list): if not None, decoded raw control lines are appended to this list.

    Returns:
        dict
    """
    result = {}
    (key, value) = ('', '')
    linenr = 0

    if isinstance(control, str):
        control = control.splitlines()

    while 1:
        if isinstance(control, list):
            if linenr >= len(control):
                line = None
            else:
                line = control[linenr]
            if not line or not line.strip():
                break
        else:
            line = control.readline()
            if not line or not line.strip():
                break

        if line.startswith(' '):
            # additional lines begin with a space!
            value = result[key]
            value += '\n'
            value += line.strip()
            result[key] = value
        else:
            sc = line.find(':')
            if sc < 0:
                raise EWaptBadControl('Invalid line (no ":" found) : %s' % line)
            (key, value) = (line[:sc].strip(), line[sc+1:].strip())
            key = key.lower()
            if key in int_params:
                try:
                    value = int(value)
                except:
                    pass
            result[key] = value
        linenr += 1
        # output line in out_control_lines if its key is not excluded
        if out_control_lines is not None and (not key or (not key in out_excluded_control_keys)):
            out_control_lines.append(line)

    return result


def is_valid_package_for_filename(name):
    """Return True if the package name can be used as this for package filename
    If not, the name has to be hashed to build a filename

    Args:
        name (unicode): package name to test

    Returns:
        bool
    """
    for c in name:
        if not c.isalnum() and not c in ['-', '_', '.']:
            return False
    return True


def make_valid_package_name(name):
    """Return a valid package name from a proposed name.

    """
    result = ''
    for c in name:
        if c.isalnum() or c in ['-', '_', '=', '~', '.']:
            result += c
        elif c == ',':
            result += '_'
        elif c == ' ':
            result += '~'

    return result


class PackageEntry(BaseObjectClass):
    """Manage package attributes coming from either control files in WAPT package, local DB, or developement dir.

    Methods to build, unzip, sign or check a package.
    Methods to sign the control attributes and check them.

    >>> pe = PackageEntry('testgroup','0')
    >>> pe.depends = 'tis-7zip'
    >>> pe.section = 'group'
    >>> pe.description = 'A test package'
    >>> print(pe.ascontrol())
    package           : testgroup
    version           : 0
    architecture      : all
    section           : group
    priority          : optional
    maintainer        :
    description       : A test package
    depends           : tis-7zip
    conflicts         :
    maturity          :
    locale            :
    min_wapt_version  :
    sources           :
    installed_size    :
    signer            :
    signer_fingerprint:
    signature_date    :
    signed_attributes :

    >>>
    """
    # minim attributes for a valid control file
    required_attributes = ['package', 'version', 'architecture', 'section', 'priority']
    optional_attributes = ['name', 'categories', 'maintainer', 'description', 'depends', 'conflicts', 'maturity',
                           'locale', 'target_os', 'min_wapt_version',
                           'sources', 'installed_size', 'impacted_process', 'description_fr',
                           'description_pl', 'description_de', 'description_es', 'description_pt',
                           'description_it', 'description_nl', 'description_ru', 'audit_schedule',
                           'editor', 'keywords', 'licence', 'homepage', 'package_uuid', 'valid_from',
                           'valid_until', 'forced_install_on', 'changelog', 'min_os_version', 'max_os_version',
                           'icon_sha256sum']
    # attributes which are added by _sign_control
    signature_attributes = ['signer', 'signer_fingerprint', 'signature', 'signature_date', 'signed_attributes']

    # these attrbutes are not written to Package control file, but only in Packages repository index
    repo_attributes = ['filename','size','md5sum']

    # attribute valid only for local copy of packages
    local_attributes = ['sourcespath','repo','localpath','repo_url']

    # these attributes are not kept when duplicating / editing a package
    not_duplicated_attributes = signature_attributes

    # there files are not included in manifest file
    manifest_filename_excludes = ['WAPT/signature', 'WAPT/signature.sha256', 'WAPT/manifest.sha256']

    _calculated_attributes = []

    @property
    def all_attributes(self):
        return self.required_attributes + self.optional_attributes + self.signature_attributes + self.repo_attributes + self.local_attributes + self._calculated_attributes

    def get_default_signed_attributes(self):
        all = self.required_attributes+self.optional_attributes+self.signature_attributes
        all.remove('signature')
        return all

    def __init__(self, package='', version='0', repo='', waptfile=None, section='base', **kwargs):
        """Initialize a Package entry with either attributes or an existing package file or directory.

        Args:
            waptfile (str): path to wapt zipped file or wapt development directory.

            package (str) : package name
            version (str) : package version
            section (str): Type of package
                                base : any standard software install or configuration package with setup.py python code
                                restricted : same as base but is hidden by default in self service
                                group : group of packages, without setup.py. Only WAPT/control file.
                                host : host package without setup.py. Only WAPT/control file.
                                unit : AD Organizational unit package. Only WAPT/control file
                                profile : AD Group package. Only WAPT/control file
                                wsus : WAPT WUA Windows updates rules package with WAPT/control and WAPT/waptwua_rules.json file.
            any control attribute (str): initialize matching attribute

        Returns:
            None
        """
        # temporary attributes added by join queries from local Wapt database
        self._calculated_attributes = []
        self._package_content = None
        self._control_updated = None

        # init package attributes
        for key in self.required_attributes:
            setattr(self, key, '')

        for key in self.optional_attributes:
            setattr(self, key, '')

        self.package = package
        self.version = version
        self.architecture = 'all'
        self.section = section
        self.priority = 'optional'

        self.name = ''
        self.categories = ''
        self.maintainer = ''
        self.description = ''
        self.depends = ''
        self.conflicts = ''
        self.sources = ''
        self.filename = ''
        self.size = None
        self.maturity = ''

        self.signer = None
        self.signer_fingerprint = None
        self.signature = None
        self.signature_date = None
        self.signed_attributes = None

        self.locale = ''
        self.target_os = ''
        self.min_os_version = ''
        self.max_os_version = ''
        self.min_wapt_version = ''
        self.installed_size = ''

        self.audit_schedule = ''
        self.impacted_process = ''
        self.keywords = ''
        self.editor = ''
        self.licence = ''

        self.valid_from = ''
        self.valid_until = ''
        self.forced_install_on = ''

        self.homepage = ''
        self.changelog = ''
        self.package_uuid = ''

        self.icon_sha256sum = ''

        # non control attributes
        self.md5sum = ''
        self.repo_url = ''
        self.repo = repo

        # directory if unzipped package files
        self.sourcespath = None

        # full filename of package if built
        self.localpath = None
        self._control_updated = False

        self.persistent_dir = None

        self._tags = None
        self._target_os_list = None

        self._control_lines = None

        if waptfile:
            if os.path.isfile(waptfile):
                self.load_control_from_wapt(waptfile)
            elif os.path.isdir(waptfile):
                self.load_control_from_wapt(waptfile)
            else:
                raise EWaptBadControl('Package filename or directory %s does not exist' % waptfile)

        if kwargs:
            for key, value in kwargs.items():
                if key in self.required_attributes + self.optional_attributes + self.repo_attributes + self.local_attributes:
                    setattr(self, key, value)

    def as_key(self):
        return PackageKey(
            package=self.package,
            version=self.version,
            architecture=self.architecture if (self.architecture is not None and self.architecture != '' and self.architecture != 'all') else '',
            locale=self.locale if (self.locale is not None and self.locale != '' and self.locale != 'all') else '',
            maturity=self.maturity if (self.maturity is not None and self.maturity != '' and self.maturity != 'all') else '',
        )

    def package_ident(self):
        """Version independent package key

        Returns:
            tuple
        """
        return (self.package,self.target_os or 'all',self.architecture or 'all',self.locale or 'all',self.maturity or 'PROD')


    def make_fallback_uuid(self):
        return 'fb-%s' % (hashlib.sha256(('-'.join([str(self.package or ''), str(self.version or ''), str(self.architecture or ''), str(self.locale or ''), str(self.maturity or '')])).encode('utf8')).hexdigest(),)

    def make_uuid(self):
        self.package_uuid = str(uuid.uuid4())
        return self.package_uuid

    def _calc_md5sum(self):
        """Return md5sum of package file on disk if it exists"""
        if self.localpath and os.path.isfile(self.localpath):
            return _hash_file(self.localpath, hash_func=hashlib.md5)
        else:
            return ''

    def _md5sum_from_filename(self,filename):
        """Returns the md5sum from a filename.
        It is the last part of the basename, name parts are separated with '_'

        >>> pe = PackageEntry(waptfile='c:/tranquilit/tis-disable-telemetry_6.wapt')
        >>> pe.md5sum = pe._calc_md5sum()
        >>> pe.make_package_filename()
        u'tis-disable-telemetry_6_3519b9e9b1d116dccd9514c209bb84ab.wapt'
        >>> pe._md5sum_from_filename(pe.make_package_filename())
        u'3519b9e9b1d116dccd9514c209bb84ab'
        """
        if not isinstance(filename,str):
            return ''
        filename = os.path.basename(filename)
        if filename and filename.endswith('.wapt') and len(filename) > 37 and filename[-38] == '_':
            md5sum = filename[-37:-5]  # remove ending .wapt
            return md5sum
        else:
            return ''

    def as_package_request(self):
        return PackageRequest(
            package=self.package,
            version=self.version,
            architectures=[self.architecture] if self.architecture else None,
            locales=[self.locale] if self.locale else None,
            maturities=[self.maturity] if self.maturity else None,
            tags=self.tags[:] if self.tags else None,
        )

    def parse_version(self):
        """Parse version to major, minor, patch, pre-release, build parts.

        """
        return parse_major_minor_patch_build(self.version)

    def check_package_attributes(self, remove_min_max_os=False):
        self.target_os=self.target_os.lower()
        if remove_min_max_os and (self.get('min_os_version') or self.get('max_os_version')):
            left_cond = ''
            right_cond = ''
            if self.get('min_os_version'):
                left_cond = '>=%s' % (self.min_os_version)
                self.min_os_version = None
            if self.get('max_os_version'):
                right_cond = '<=%s' % (self.max_os_version)
                self.max_os_version = None
            cond ='(%s)' % ' '.join([left_cond, right_cond]).strip()

            list_target_os = ensure_list(self.target_os)
            if list_target_os:
                if not 'windows' in list_target_os:
                    if 'all' in list_target_os:
                        list_target_os.remove('all')
                    list_target_os.append('windows')
                self.target_os = ','.join([atarget if atarget!='windows' else 'windows%s' % (cond) for atarget in list_target_os])
            else:
                self.target_os = 'windows%s' % (cond)

        if self.target_os:
            list_target_os = ensure_list(self.target_os)
            if len(list_target_os)>1 and any(t.startswith('all') for t in list_target_os):
                self.target_os = 'all'
        self.parse_capabilities_target_os(check=True)

        # be sure filename is ok
        if self.filename  and self.filename != sanitize_filename(self.filename):
            raise EWaptBadControl('filename %s is invalid for a package' % self.filename)


    def parse_capabilities_target_os(self, check=False):

        comparison_operators = ['==', '<=', '>=', '<>', '!=', '<', '>', '=']

        def match_regex_condition_capabilities(astr):
            return bool(re.match(r'^(%s)[a-zA-Z0-9.]+$' % '|'.join(comparison_operators), astr))

        def match_regex_tags(astr):
            return bool(re.match(r'^[\w-]+$', astr))

        def parse_comparison_operators(acond):
            for anope in comparison_operators:
                if acond.startswith(anope):
                    operator = anope
                    break
            return (operator, acond[acond.find(operator)+len(operator):])

        def raise_or_log(target):
            if check:
                raise Exception('Malformed target OS for %s with target : %s' % (repr(self),target))
            else:
                logger.debug('Exception for package %s, with target %s' % (repr(self), target))


        capabilities = []

        if not self.target_os:
            capabilities.append(('all', []))
        else:
            for target in ensure_list(self.target_os):
                try:
                    opening_parenthesis_pos = target.find('(')
                    closing_parenthesis_pos = target.rfind(')')
                    conds = []
                    if opening_parenthesis_pos!=-1 and closing_parenthesis_pos!=-1:
                        os_versions = [t for t in target[opening_parenthesis_pos+1:closing_parenthesis_pos].split(' ')]
                        extracted_tag = target[0:opening_parenthesis_pos].strip().lower()
                        if all([match_regex_condition_capabilities(t) for t in os_versions]):
                            conds = [parse_comparison_operators(acond) for acond in os_versions]
                        else:
                            raise_or_log(target)
                    else:
                        extracted_tag = target.strip().lower()
                    if match_regex_tags(extracted_tag):
                        capabilities.append((extracted_tag,conds))
                    else:
                        raise_or_log(target)
                except:
                    raise_or_log(target)

        return capabilities


    @property
    def tags(self):
        if self._tags is None:
            self._tags = [atarget[0] for atarget in self.target_os_list]
        return self._tags


    @property
    def target_os_list(self):
        if self._target_os_list is None:
            self._target_os_list = self.parse_capabilities_target_os()
        return self._target_os_list


    def set_icon_sha256sum(self):
        self.icon_sha256sum = ''
        if self.localpath:
             with CustomZipFile(self.localpath, 'r', allowZip64=True, compression=zipfile.ZIP_DEFLATED) as waptzip:
                if 'WAPT/icon.png' in waptzip.namelist():
                    self.icon_sha256sum = _hash_file(waptzip.open('WAPT/icon.png'), hash_func=hashlib.sha256)
        elif os.path.isfile(os.path.join(self.sourcespath, 'WAPT/icon.png')):
            self.icon_sha256sum = _hash_file(os.path.join(self.sourcespath, 'WAPT/icon.png'), hash_func=hashlib.sha256)


    def __getitem__(self, name):
        if isinstance(name, str):
            name = name.lower()
        if hasattr(self, name):
            return getattr(self, name)
        else:
            raise Exception('No such attribute : %s' % name)

    def __iter__(self):
        for key in self.all_attributes:
            if not key.startswith('_') or key == '_localized_description':
                yield (key, getattr(self, key))

    def as_dict(self):
        return dict(self)

    def fingerprint(self):
        return hashlib.sha256(serialize_content_for_signature(self.as_dict())).hexdigest()

    def __str__(self):
        return self.ascontrol(with_repo_attributes=True)

    def __repr__(self):
        return "PackageEntry(%s,%s %s)" % (repr(self.package), repr(self.version),
                                           ','.join(["%s=%s" % (key, repr(getattr(self, key))) for key in ('architecture', 'maturity', 'locale','target_os') if (getattr(self, key) is not None and getattr(self, key) != '' and getattr(self, key) != 'all')]))

    def get(self, name, default=None):
        """Get PackageEntry property.

        Args:
            name (str): property to get. name is forced to lowercase.
            default (any) : value to return in case the property doesn't not exist.

        Returns:
            any : property value
        """
        if isinstance(name, str):
            name = name.lower()
        return getattr(self, name, default)

    def get_localized_description(self, locale_code=None):
        """locale_code is a 2 chars code like fr or en or de"""
        if locale_code is None:
            return self.description
        else:
            if hasattr(self, 'description_%s' % locale_code):
                desc = getattr(self, 'description_%s' % locale_code)
                if desc:
                    return desc
                else:
                    return self.description
            else:
                return self.description

    def __setitem__(self, name, value):
        """attribute which are not member of all_attributes list are considered _calculated

        >>> p = PackageEntry('test')
        >>> print p._calculated_attributes
        []
        >>> p.install_date = u'2017-06-09 12:00:00'
        >>> print(p._calculated_attributes)
        []
        """
        setattr(self, name, value)

    def __setattr__(self, name, value):
        if isinstance(name, str):
            name = name.lower()
        if name not in self.all_attributes:
            self._calculated_attributes.append(name)
        if name == 'target_os':
            self._tags = None
            self._target_os_list = None
        if name in self.required_attributes+self.optional_attributes and self._control_updated is not None and value != getattr(self, name):
            self._control_updated = True
        super().__setattr__(name, value)

    def __len__(self):
        return len(self.all_attributes)

    def __cmp__(self, entry_or_version):
        try:
            if isinstance(entry_or_version,PackageEntry):
                return safe_cmp_tuples(PackageVersion(self.version)+(self.maturity,self.signature_date) ,PackageVersion(entry_or_version.version)+(entry_or_version.maturity,entry_or_version.signature_date))
            else:
                return safe_cmp_tuples(PackageVersion(self.version),PackageVersion(entry_or_version))
        except ValueError as e:
            logger.warning("%s" % e)
            if isinstance(entry_or_version, PackageEntry):
                return safe_cmp_tuples((self.package, self.version), (entry_or_version.package, entry_or_version.version))
            else:
                return safe_cmp(self.version, entry_or_version)

    def __eq__(self, entry_or_version):
        return self.__cmp__(entry_or_version) == 0

    def __ne__(self, entry_or_version):
        return self.__cmp__(entry_or_version) != 0

    def __gt__(self, entry_or_version):
        return self.__cmp__(entry_or_version) > 0

    def __lt__(self, entry_or_version):
        return self.__cmp__(entry_or_version) < 0

    def __ge__(self, entry_or_version):
        return self.__cmp__(entry_or_version) >= 0

    def __le__(self, entry_or_version):
        return self.__cmp__(entry_or_version) <= 0

    def match(self, match_expr):
        """Return True if package entry match a package string like 'tis-package (>=1.0.1-00)

        """
        if isinstance(match_expr, PackageRequest):
            return match_expr.is_matched_by(self)
        elif isinstance(match_expr, str):
            pcv = REGEX_PACKAGE_CONDITION.match(match_expr).groupdict()
            if pcv['package'] != self.package:
                return False
            else:
                if 'operator' in pcv and pcv['operator']:
                    return self.match_version(pcv['operator']+pcv['version'])
                else:
                    return True
        else:
            raise Exception('Unsupported match operand %s' % match_expr)

    def sortable_version(self):
        return PackageVersionStr(self)

    def match_version(self, version_expr):
        """Return True if package entry match a version string condition like '>=1.0.1-00'

        """
        prefix = version_expr[:2]
        if prefix in ('>=', '<=', '=='):
            match_version = version_expr[2:]
        elif prefix and prefix[0] in ('>', '<', '='):
            prefix = prefix[0]
            match_version = version_expr[1:]
        else:
            raise ValueError("version_expr parameter should be in format <op><ver>, "
                             "where <op> is one of ['<', '>', '==', '<=', '>=']. "
                             "You provided: %r" % version_expr)

        possibilities_dict = {
            '>': (1,),
            '<': (-1,),
            '=': (0,),
            '==': (0,),
            '>=': (0, 1),
            '<=': (-1, 0)
        }

        possibilities = possibilities_dict[prefix]
        cmp_res = self.__cmp__(match_version)

        return cmp_res in possibilities

    def match_search(self, search):
        """Check if entry match search words

        Args:
            search (str): words to search for separated by spaces

        Returns:
            boolean: True if entry contains the words in search in correct order and at word boundaries
        """
        if not search:
            return True
        else:
            found = re.search(r'\b{}'.format(search.replace(' ', r'.*\b')), '%s %s' % (self.package, self.description), re.IGNORECASE)
            return found is not None

    def load_control_from_dict(self, adict):
        """Fill in members of entry with keys from supplied dict

        adict members which are not a registered control attribute are set too
        and attribute name is put in list of "calculated" attributes.

        Args:
            adict (dict): key,value to put in this entry

        Returns:
            PackageEntry: self
        """
        for k in adict:
            setattr(self, k, adict[k])
        return self

    def _load_control(self, control_text, keep_control_lines=False):
        if not keep_control_lines:
            self._control_lines = None
            self.load_control_from_dict(control_to_dict(control_text))
        else:
            self._control_lines = []
            self.load_control_from_dict(control_to_dict(control_text,out_excluded_control_keys=self.repo_attributes+self.local_attributes,out_control_lines=self._control_lines))
        self._control_updated = False

    def load_control_from_wapt(self, fname=None, calc_md5=False, keep_control_lines=False):
        """Load package attributes from the control file (utf8 encoded) included in WAPT zipfile fname

        Args:
            fname (str or unicode): Package file/directory path
                                    If None, try to load entry attributes from self.sourcespath or self.localpath
                                    If fname is a file path, it must be Wapt zipped file, and try to load control data from it
                                    If fname is a directory path, it must be root dir of unzipped package file and load control from <fname>/WAPT/control

            calc_md5 (boolean): if True and fname is a zipped file, initialize md5sum attribute with md5 part of filename or calc from Zipped file

        Returns:
            PackageEntry: self

        """
        if fname is None:
            if self.sourcespath and os.path.isdir(self.sourcespath):
                fname = self.sourcespath
            elif self.localpath and os.path.isfile(self.localpath):
                fname = self.localpath

        if fname and os.path.isfile(fname):
            with CustomZipFile(fname, 'r', allowZip64=True) as waptzip:
                control = waptzip.open('WAPT/control').read().decode('utf8')
        elif fname and os.path.isdir(fname) and os.path.isfile(os.path.join(fname, 'WAPT', 'control')):
            with open(os.path.join(fname, 'WAPT', 'control'), 'r', encoding='utf8') as f:
                control = f.read()
        else:
            raise EWaptBadControl('Bad or no control found for %s' % (fname,))

        self._load_control(control,keep_control_lines=keep_control_lines)

        if os.path.isfile(fname):
            self.size = os.path.getsize(fname)
            self.filename = os.path.basename(fname)
            self.localpath = os.path.abspath(fname)
            if calc_md5:
                self.md5sum = self._calc_md5sum()
        else: # Can only be directory otherwise a EWaptBadControl would have been raised before
            self.filename = None
            self.localpath = None
            self.size = None
            self.sourcespath = os.path.abspath(fname)
        return self

    def save_control_to_wapt(self, fname=None, force=True):
        """Save package attributes to the control file (utf8 encoded)

        Update self.locapath or self.sourcespath if not already set.

        Args:
            fname (str) : base directoy of waptpackage or filepath of Zipped Packges.
                          If None, use self.sourcespath if exists, or self.localpath if exists

            force (bool) : write control in wapt zip file even if it already exist
        Returns:
            PackageEntry : None if nothing written, or previous PackageEntry if new data written

        Raises:
            Exception: if fname is None and no sourcespath and no localpath
            Exception: if control exists and force is False

        """
        if fname is None:
            if self.sourcespath and os.path.isdir(self.sourcespath):
                fname = self.sourcespath
            elif self.localpath and os.path.isfile(self.localpath):
                fname = self.localpath

        if fname is None:
            raise Exception('Needs a wapt package directory root or WaptPackage filename to save control to')

        fname = os.path.abspath(fname)

        try:
            old_control = PackageEntry(waptfile=fname)
        except EWaptBadControl:
            old_control = None

        # wether data is different
        write_needed = not old_control or (old_control.ascontrol() != self.ascontrol())

        if not force and old_control and write_needed:
            raise Exception('control file already exist in WAPT file %s' % fname)

        if write_needed:
            self._control_updated = False
            if os.path.isdir(fname):
                if not os.path.isdir(os.path.join(fname, 'WAPT')):
                    os.makedirs(os.path.join(fname, 'WAPT'))
                with codecs.open(os.path.join(fname, 'WAPT', 'control'), 'w', encoding='utf8') as control_file:
                    control_file.write(self.ascontrol())
                if not self.sourcespath:
                    self.sourcespath = fname
                return old_control
            else:
                waptzip = CustomZipFile(fname, 'a', allowZip64=True, compression=zipfile.ZIP_DEFLATED)
                try:
                    try:
                        waptzip.remove('WAPT/control')
                    except Exception as e:
                        logger.debug("OK %s" % repr(e))
                    waptzip.writestr('WAPT/control', self.as_control_bytes())
                    if not self.localpath:
                        self.localpath = fname
                    return old_control
                finally:
                    waptzip.close()
        else:
            self._control_updated = False
            return None

    def ascontrol(self,with_repo_attributes = False,with_empty_attributes=False):
        """Return control attributes and values as stored in control packages file

        Each attribute on a line with key : value
        If value is multiline, new line begin with a space.

        Args:
            with_repo_attributes (bool) : if True, include md5sum and filename (for Packages index only)
            with_empty_attributes (bool) : weither to include attribute with empty value too or only
                                           non empty and/or signed attributes
        Returns:
            str: lines of attr: value
        """
        val = []

        def escape_cr(s):
            # format multi-lines description with a space at each line start
            # format list as csv
            if s and (isinstance(s, str) or isinstance(s, str)):
                return re.sub(r'$(\n)(?=^\S)', r'\n ', s, flags=re.MULTILINE)
            elif isinstance(s, list):
                return ','.join([ensure_unicode(item) for item in s])
            else:
                if s is None:
                    return ''
                else:
                    return s

        for att in self.required_attributes+self.optional_attributes+self.signature_attributes:
            # we add to the control file all signed attributes, the non empty ones, and all the other if required
            if att in self.get_default_signed_attributes() or with_empty_attributes or getattr(self, att):
                val.append("%-18s: %s" % (att, escape_cr(getattr(self, att))))

        if with_repo_attributes:
            for att in self.repo_attributes :
                if getattr(self,att):
                    val.append("%-18s: %s" % (att, escape_cr(getattr(self, att))))
        return '\n'.join(val)

    def make_package_filename(self,with_md5sum = False):
        """Return the standard package filename based on current attributes
        parts of control which are either 'all' or empty are not included in filename

        Returns:
            str:  standard package filename
                  - packagename.wapt for host
                  - packagename_arch_maturity_locale.wapt for group
                  - packagename_version_arch_maturity_locale.wapt for others
        """
        if self.section not in ['host', 'group', 'unit'] and not (self.package and self.version and self.architecture):
            raise Exception('Not enough information to build the package filename for %s (%s)' % (self.package, self.version))

        if not is_valid_package_for_filename(self.package):
            package_name = hashlib.md5(self.package.encode('utf8')).hexdigest()
        else:
            package_name = self.package

        if with_md5sum:
            _md5sum = self.md5sum
        else:
            _md5sum = None

        if self.section == 'host':
            att = [package_name]
        else:
            att = [package_name,self.version]
            if package_name.lower().endswith('-waptupgrade') and self.target_os == 'windows':
                att.extend([f for f in (self.target_os,
                                        self.maturity,
                                        '-'.join(ensure_list(self.locale)),
                                        _md5sum) if f])
            else:
                if not self.target_os or self.target_os in self.tags:
                    target_os = None
                elif self.target_os.isalnum():
                    target_os = self.target_os
                else:
                    target_os = hashlib.md5(self.target_os.encode('utf8')).hexdigest()

                # includes only non empty fields
                att.extend([f for f in (
                    '-'.join(ensure_list(self.architecture)),
                    '-'.join(self.tags),
                    target_os,
                    self.min_os_version,
                    self.max_os_version,
                    self.maturity,
                    '-'.join(ensure_list(self.locale)),
                    _md5sum) if (f and f != 'all')])

        result = '_'.join(att)+'.wapt'
        return sanitize_filename(result)

    def make_package_edit_directory(self):
        """Return the standard package directory to edit the package based on current attributes

        Returns:
            str:  standard package filename
                  - {package}_{version}_{architecture}_{OS}_{Min-OS-Version}_{Max-OS-Version}_{maturity}_{locale}-wapt
        """
        if not (self.package):
            raise Exception('Not enough information to build the package directory for %s' % (self.package))
            # includes only non empty fields
        return '_'.join([f for f in (
            self.package,
            self.version,
            (self.architecture  or '').replace(',', '-'),
            self.target_os,
            self.min_os_version,
            self.max_os_version,
            (self.maturity or 'PROD').replace(',', '-'),
            (self.locale or '').replace(',', '-'))
            if (f and f != 'all')]) + '-wapt'

    def asrequirement(self):
        """Return package and version for designing this package in depends or install actions

        Returns:
            str: "packagename (=version)"
        """
        return "%s(=%s)" % (self.package, self.version)

    def get_software_version(self):
        """Return the software version only (without the build number of the package)

        Returns:
            str: "software_version"
        """
        version_parsed = self.parse_version()
        return '.'.join([str(version_parsed[elem]) for elem in version_parsed.keys() if elem != 'packaging' and version_parsed[elem] is not None])

    def set_software_version(self, version, inc_build=False):
        """Set the software version only
           inc_build will increment the buildnumber
        """
        version = parse_major_minor_patch_build(version)
        version['packaging'] = self.parse_version()['packaging']
        self.version = make_version(version)
        if inc_build:
            self.inc_build()

    def get_impacted_process_list(self):
        """Return a list containing the impacted process

        Returns:
            List[str] impacted process list
        """
        return [p for p in self.impacted_process.split(',') if p]

    def inc_build(self):
        """Increment last number part of version in memory"""
        # Raise value error if version is invalid
        version_parts = self.parse_version()
        for part in ('packaging', 'subpatch', 'patch', 'minor', 'major'):
            if part in version_parts and version_parts[part] != None and\
                    (isinstance(version_parts[part], int) or version_parts[part].isdigit()):
                version_parts[part] = "%i" % (int(version_parts[part])+1,)
                self.version = make_version(version_parts)
                return

    def build_management_package(self, target_directory=None):
        """Build the WAPT package from attributes only, without setup.py
        stores the result in target_directory.

        self.sourcespath must be None.
        Package will contain only a control file.

        Args:
            target_directory (str): where to create Zip wapt file.
                                    if None, temp dir will be used.

        Returns:
            str: path to zipped Wapt file. It is unsigned.

        >>> pe = PackageEntry('testgroup','0',description='Test package',maintainer='Hubert',sources='https://dev/svn/testgroup',architecture='x86')
        >>> waptfn = pe.build_management_package()
        >>> key = SSLPrivateKey('c:/private/htouvet.pem',password='monmotdepasse')
        >>> crt = SSLCertificate('c:/private/htouvet.crt')
        >>> pe.sign_package(crt,key)
        >>> pe.unzip_package()
        'c:\\users\\htouvet\\appdata\\local\\temp\\waptob4gcd'
        >>> ca = SSLCABundle('c:/wapt/ssl')
        >>> pe.check_control_signature(ca)
        <SSLCertificate cn=u'htouvet' issuer=u'tranquilit-ca-test' validity=2017-06-28 - 2027-06-26 Code-Signing=True CA=True>
        """

        result_filename = ''
        # some checks
        if self.sourcespath:
            raise Exception('Package must not have local sources')

        # check version syntax
        parse_major_minor_patch_build(self.version)

        # check architecture
        for arch in ensure_list(self.architecture):
            if not arch in ArchitecturesList:
                raise EWaptBadControl('Bad architecture %s, should one of %s' % (arch, ArchitecturesList,))

        self.filename = self.make_package_filename()

        control_data = self.ascontrol()

        if target_directory is None:
            target_directory = tempfile.gettempdir()

        if not os.path.isdir(target_directory):
            raise Exception('Bad target directory %s for package build' % target_directory)

        result_filename = os.path.abspath(os.path.join(target_directory, self.filename))

        if os.path.isfile(result_filename):
            logger.warning('Target package already exists, removing %s' % result_filename)
            os.unlink(result_filename)

        self.localpath = result_filename
        with CustomZipFile(result_filename, 'w', allowZip64=True, compression=zipfile.ZIP_DEFLATED) as wapt_zip:
            wapt_zip.writestr('WAPT/control', control_data.encode('utf8'))
        return result_filename

    def build_package(self, excludes=[], target_directory=None, excludes_full=DEFAULT_EXCLUDED_PATHS_FOR_BUILD):
        """Build the WAPT package, stores the result in target_directory
        Zip the content of self.sourcespath directory into a zipfile
        named with default package filename based on control attributes.

        Update filename attribute.
        Update localpath attribute with result filepath.

        Args:
            excludes (list) : list of patterns for source files to exclude from built package.
            target_directory (str): target directory where to store built package.
                                    If None, use parent directory of package sources dircetory.
            excludes_full (list) : list of exact (relative to package root) filepathes to exclude from Zip.

        Returns:
            str: full filepath to built wapt package
        """

        self.localpath = ''

        # some checks
        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Error building package : There is no sourcespath %s' % self)

        if not os.path.isdir(os.path.join(self.sourcespath, 'WAPT')):
            raise EWaptNotSourcesDirPackage('Error building package : There is no WAPT directory in %s' % self.sourcespath)

        control_filename = os.path.join(self.sourcespath, 'WAPT', 'control')
        if not os.path.isfile(control_filename):
            raise EWaptNotSourcesDirPackage('Error building package : There is no control file in WAPT directory')

        # check version syntax
        parse_major_minor_patch_build(self.version)

        # check architecture
        for arch in ensure_list(self.architecture):
            if not arch in ArchitecturesList:
                raise EWaptBadControl('Bad architecture %s, should one of %s' % (arch, ArchitecturesList,))

        self.filename = self.make_package_filename()

        logger.debug('Control data : \n%s' % self.ascontrol())
        if target_directory is None:
            target_directory = os.path.abspath(os.path.join(self.sourcespath, '..'))

        if not os.path.isdir(target_directory):
            raise Exception('Bad target directory %s for package build' % target_directory)

        self.localpath = os.path.abspath(os.path.join(target_directory, self.filename))
        if os.path.isfile(self.localpath):
            logger.warning('Target package already exists, removing %s' % self.localpath)
            os.unlink(self.localpath)

        create_recursive_zip(
            zipfn=self.localpath,
            source_root=ensure_unicode(self.sourcespath),
            target_root='',
            excludes=excludes,
            excludes_full=excludes_full)
        self._invalidate_package_content()
        self.md5sum = self._calc_md5sum()
        self.size = os.path.getsize(self.localpath)
        return self.localpath

    def _invalidate_package_content(self):
        """Remove the _package_content for host packages

        """
        if hasattr(self, '_package_content'):
            self._package_content = None
        if hasattr(self, '_control_lines'):
            self._control_lines = None

    def _signed_content(self):
        """Return the signed control informations

        Returns:
            dict of att:values of control data which must be signed
        """
        # workaround for migration
        if not self.signed_attributes and self.signature_date and self.signature_date  < '20170609':
            logger.warning('Package %s has old control signature style, some attributes are not checked. Please re-sign package' % (self.localpath or self.sourcespath or self.asrequirement()))
            effective_signed_attributes = ['package', 'version', 'architecture', 'section', 'priority', 'depends', 'conflicts', 'maturity']
        else:
            effective_signed_attributes = self.signed_attributes
        return {att: getattr(self, att, None) for att in ensure_list(effective_signed_attributes)}

    def _sign_control(self, private_key, certificate, keep_signature_date=False):
        """Sign the contractual attributes of the control file using
        the provided key, add certificate Fingerprint and CN too

        Args:
            private_key (SSLPrivateKey)
            certificate (SSLCertificate)

        Returns:
            str: signature
        """
        self.make_uuid()
        self.signed_attributes = ','.join(self.get_default_signed_attributes())
        if not keep_signature_date or not self.signature_date:
            self.signature_date = datetime2isodate(datetime.datetime.utcnow())
        self.signer = certificate.cn
        self.signer_fingerprint = certificate.fingerprint
        self.signature = base64.b64encode(private_key.sign_content(self._signed_content(), md='sha256')).decode('utf8')
        return self.signature

    def check_control_signature(self, trusted_bundle, signers_bundle=None):
        """Check in memory control signature against a list of public certificates

        Args:
            trusted_bundle (SSLCABundle): Trusted certificates. : packages certificates must be signed by one of this bundle.
            signers_bundle : Optional. List of potential packages signers certificates chains.
                             When checking Packages index, actual
                             packages are not available, only certificates embedded in Packages index.
                             Package signature are checked against these certificates
                             looking here for potential intermediate CA too.
                             and matching certificate is checked against trusted_bundle.

        Returns:
            SSLCertificate : matching trusted package's signers SSLCertificate

        >>> from waptpackage import *
        >>> from common import SSLPrivateKey,SSLCertificate
        >>> k = SSLPrivateKey('c:/private/test.pem')
        >>> c = SSLCertificate('c:/private/test.crt')

        >>> p = PackageEntry('test',version='1.0-0')
        >>> p.depends = 'test'
        >>> p._sign_control(k,c)
        >>> p.check_control_signature(c)

        >>> p.check_control_signature(SSLCABundle('c:/wapt/ssl'))

        """
        if not self.signature:
            raise EWaptNotSigned('Package control %s on repo %s is not signed' % (self.asrequirement(), self.repo))
        if not isinstance(trusted_bundle, SSLCABundle):
            raise EWaptMissingCertificate('Trusted bundle must be a SSLCABundle and cannot be None')

        certs = self.package_certificates()
        if certs is None and signers_bundle is not None:
            certs = signers_bundle.certificate_chain(fingerprint=self.signer_fingerprint)
        if not certs:
            # raise EWaptCryptoException instead of returning None because we use a fingerprint
            try:
                certs = trusted_bundle.certificate_chain(fingerprint=self.signer_fingerprint)
            except EWaptCryptoException:
                raise EWaptMissingCertificate('Control %s data has no matching certificate in Packages index or Package, please rescan your Packages index.' % self.asrequirement())

        # append trusted to ca
        #issued_by = \
        trusted_bundle.check_certificates_chain(certs)[-1]
        #logger.debug('Certificate %s is trusted by root CA %s' % (cert.subject,issued_by.subject))

        signed_content = self._signed_content()
        signature_raw = base64.b64decode(self.signature)
        try:
            certs[0].verify_content(signed_content, signature_raw, md='sha256')
            return certs[0]
        except Exception as e:
            raise SSLVerifyException('SSL signature verification failed for control %s against embedded certificate %s (%s)' % (self.asrequirement(), certs[0].cn, e))

    def has_file(self, fname):
        """Return None if fname is not in package, else return file datetime

        Args:
            fname (unicode): file path like WAPT/signature

        Returns:
            datetime : last modification datetime of file in Wapt archive if zipped or local sources if unzipped
        """
        if self.localpath or self._package_content is not None:
            try:
                with self.as_zipfile() as waptzip:
                    return datetime.datetime(*waptzip.getinfo(fname).date_time)
            except KeyError:
                return None
        elif self.sourcespath and os.path.isdir(self.sourcespath) and os.path.isfile(os.path.join(self.sourcespath, fname)):
            # unzipped sources
            fpath = os.path.abspath(os.path.join(self.sourcespath, fname))
            return datetime.datetime.fromtimestamp(os.stat(fpath).st_mtime)
        else:
            # package is not yet built/signed.
            return None

    def package_certificates(self):
        """Return certificates from package. If package is built, take it from Zip
        else take the certificates from unzipped directory

        Returns:
            list: list of embedded certificates when package was signed or None if not provided or signed.
                    First one of the list is the signer, the others are optional intermediate CA
        """
        if self.localpath and os.path.isfile(self.localpath):
            try:
                with CustomZipFile(self.localpath, allowZip64=True) as zip:
                    cert_pem = zip.read('WAPT/certificate.crt')
                certs = SSLCABundle()
                certs.add_certificates_from_pem(cert_pem)
                return certs.certificates()
            except Exception as e:
                logger.warning('No certificate found in %s : %s' % (self.localpath, repr(e)))
                return None
        elif self.sourcespath and os.path.isdir(self.sourcespath) and os.path.isfile(os.path.join(self.sourcespath, 'WAPT', 'certificate.crt')):
            # unzipped sources
            certs = SSLCABundle(os.path.join(self.sourcespath, 'WAPT', 'certificate.crt'))
            return certs.certificates()
        else:
            # package is not yet built/signed.
            return None

    def build_manifest(self, exclude_filenames=None, block_size=2**20, forbidden_files=[], waptzip=None, excludes=[]):
        """Calc the manifest of a wapt package

        Args:
            forbidden_files (list): list of relative files which must not be present for the manifest to be built
                                    (if one is found, build fails)
            exclude_filenames (list) : list of exact (relative to package root with forward slashes) filepathes to exclude from manifest.
            excludes (list) : list of file / dir patterns to exclude, whatever level they are in the file hierarchy

        Returns:
            dict: {filepath:shasum,}
        """
        if not self.localpath and not self.sourcespath:
            raise EWaptMissingLocalWaptFile('%s has no localpath or sourcespath' % self.asrequirement())
        if self.localpath and not os.path.isfile(self.localpath):
            raise EWaptMissingLocalWaptFile('%s is not a Wapt package' % self.localpath)

        if self.sourcespath and not os.path.isdir(self.sourcespath):
            raise EWaptMissingLocalWaptFile('%s is not a Wapt package source directory' % self.sourcespath)

        if exclude_filenames is None:
            exclude_filenames = self.manifest_filename_excludes

        if waptzip is None and self.localpath:
            waptzip = CustomZipFile(self.localpath, 'r', allowZip64=True)
            _close_zip = True
        else:
            _close_zip = False

        try:
            manifest = {}
            if waptzip:
                for fn in waptzip.filelist:
                    if not fn.filename in exclude_filenames:
                        if fn.filename in forbidden_files:
                            raise EWaptPackageSignError('File %s is not allowed.' % fn.filename)

                        excluded = False
                        for exclude_glob in excludes:
                            if glob.fnmatch.fnmatch(fn.filename, exclude_glob):
                                excluded = True
                                break
                        if excluded:
                            continue

                        # not hash for directories
                        if not fn.filename.endswith('/'):
                            shasum = hashlib.new('sha256')
                            file_data = waptzip.open(fn)
                            while True:
                                data = file_data.read(block_size)
                                if not data:
                                    break
                                shasum.update(data)
                            shasum.update(data)
                            manifest[fn.filename] = shasum.hexdigest()
                            # remove hash for empty dir
                            adir = os.path.dirname(fn.filename)+'/'
                            if adir in manifest:
                                del manifest[adir]
                        else:
                            manifest[fn.filename] = ''

            else:
                def _process(rootdir):
                    is_empty = True
                    for fn in os.listdir(rootdir):
                        absolute_filename = os.path.abspath(os.path.join(rootdir, fn))
                        relative_filename = os.path.relpath(absolute_filename, self.sourcespath).replace('\\', '/')
                        if not relative_filename in exclude_filenames:
                            if fn in forbidden_files:
                                raise EWaptPackageSignError('File %s is not allowed.' % fn)

                            excluded = False
                            for exclude_glob in excludes:
                                if glob.fnmatch.fnmatch(fn, exclude_glob):
                                    excluded = True
                                    break
                            if excluded:
                                continue

                            if os.path.isdir(absolute_filename):
                                if not _process(absolute_filename):
                                    manifest[relative_filename] = ''
                            else:
                                is_empty = False
                                shasum = hashlib.new('sha256')
                                with open(absolute_filename, 'rb') as file_data:
                                    while True:
                                        data = file_data.read(block_size)
                                        if not data:
                                            break
                                        shasum.update(data)
                                shasum.update(data)
                                manifest[relative_filename] = shasum.hexdigest()
                    return not is_empty
                _process(self.sourcespath)
            return manifest
        finally:
            if _close_zip:
                waptzip.close()

    def sign_package(self, certificate, private_key,
                     keep_signature_date=False, excludes_full=DEFAULT_EXCLUDED_PATHS_FOR_BUILD, excludes=[]):
        """Sign a package source directory or an already built (zipped) package.
        Should follow immediately the build_package step.

        Append signed control, manifest.sha256 and signature to zip wapt package
        If these files are already in the package, they are first removed.

        Use the self.localpath attribute to get location of waptfile build file.

        Args:
            certificate (SSLCertificate or list): signer certificate chain
            private_key (SSLPrivateKey): signer private key
            keep_signature_date (bool): If true, previous date fo signature is kept (useful when resigning is needed, but no meaningful change has been done)
            excludes_full (list) : list of exact (relative to package root) filepathes to exclude from manifest.
            excludes (list) : list of file / dir patterns to exclude, whatever level they are in the file hierarchy

        Returns:
            str: signature

        """
        self.check_package_attributes()

        self.set_icon_sha256sum()

        if not (
                (self.localpath and os.path.isfile(self.localpath)) or
                (self.sourcespath and os.path.isdir(self.sourcespath))
                ):
            raise Exception("Path %s is not a Wapt package or Wapt source dir" % (self.localpath or self.sourcespath))

        if isinstance(certificate, list):
            signer_cert = certificate[0]
            certificate_chain = certificate
        else:
            signer_cert = certificate
            certificate_chain = [certificate]

        cert_chain_str = None

        if private_key is None:
            raise EWaptPackageSignError('No matching private key found for signing using certificate %s' % signer_cert)

        package_fn = self.localpath or self.sourcespath
        logger.debug('Signing %s with key %s, and certificate CN "%s"' % (package_fn, private_key, signer_cert.cn))
        self._sign_control(certificate=signer_cert, private_key=private_key, keep_signature_date=keep_signature_date)

        # control file is appended to manifest file separately.
        control = self.as_control_bytes()
        exclude_filenames = self.manifest_filename_excludes
        exclude_filenames.append('WAPT/control')
        # files to ignore as they will not be zipped into final package
        exclude_filenames.extend(excludes_full)

        forbidden_files = []
        # removes setup.py
        # if file is in forbidden_files, raise an exception.
        if not signer_cert.is_code_signing:
            forbidden_files.append('setup.py')

        self._invalidate_package_content()

        # clear existing signatures
        # case for already build packages. We sign inline the content of zip package
        # does not always works well for big packages (not fixed yet...)
        if self.localpath:
            with CustomZipFile(self.localpath, 'a', allowZip64=True, compression=zipfile.ZIP_DEFLATED) as waptzip:
                filenames = waptzip.namelist()
                if self.get_signature_filename() in filenames:
                    waptzip.remove(self.get_signature_filename())
                if self.get_manifest_filename() in filenames:
                    waptzip.remove(self.get_manifest_filename())

                if 'WAPT/control' in filenames:
                    waptzip.remove('WAPT/control')
                waptzip.writestr('WAPT/control', control)

                # replace or append signer certificate
                if 'WAPT/certificate.crt' in filenames:
                    waptzip.remove('WAPT/certificate.crt')
                cert_chain_str = b'\n'.join([cert.as_pem() for cert in certificate_chain])
                waptzip.writestr('WAPT/certificate.crt', cert_chain_str)

                try:
                    # need read access to ZIP file.
                    manifest_data = self.build_manifest(exclude_filenames=exclude_filenames, forbidden_files=forbidden_files, waptzip=waptzip, excludes=excludes)
                except EWaptPackageSignError:
                    raise EWaptBadCertificate('Certificate %s doesn''t allow to sign packages with setup.py file.' % signer_cert.cn)

                manifest_data['WAPT/control'] = hexdigest_for_data(control, md='sha256')

                new_cert_hash = hexdigest_for_data(cert_chain_str, md='sha256')
                if manifest_data.get('WAPT/certificate.crt', None) != new_cert_hash:
                    # need to replace certificate in Wapt package
                    manifest_data['WAPT/certificate.crt'] = new_cert_hash
                else:
                    new_cert_hash = None

                # convert to list of list...
                wapt_manifest = serialize_content_for_signature(list(manifest_data.items()))

                signature = private_key.sign_content(wapt_manifest, md='sha256')

                waptzip.writestr(self.get_manifest_filename(), wapt_manifest)
                waptzip.writestr(self.get_signature_filename(), base64.b64encode(signature))

            mtime = time.mktime(isodate2datetime(self.signature_date).timetuple())
            self.md5sum = self._calc_md5sum()
            self.size = os.path.getsize(self.localpath)

            # be sure that filename does not keep a bad checksum
            md5_from_fn = self._md5sum_from_filename(self.localpath)
            if md5_from_fn:
                new_fn = self.make_package_filename()
                # Always true because we don't set back the md5sum in the filename...
                if new_fn != self.filename:
                    logger.warning("Renaming entry filename from %s to %s" % (self.filename,new_fn))
                    self.filename = new_fn
                    new_localpath = os.path.join(os.path.dirname(self.localpath),self.filename)
                    os.rename(self.localpath,new_localpath)
                    self.localpath = new_localpath
            os.utime(self.localpath, (mtime, mtime))
        else:
            # common case for base packages. We sign the content of unzipped package
            self.save_control_to_wapt(self.sourcespath)
            cert_chain_str = b'\n'.join([cert.as_pem() for cert in certificate_chain])
            with open(os.path.join(self.sourcespath, 'WAPT', 'certificate.crt'), 'wb') as f:
                f.write(cert_chain_str)

            manifest_data = self.build_manifest(exclude_filenames=exclude_filenames, forbidden_files=forbidden_files, excludes=excludes)
            manifest_data['WAPT/control'] = hexdigest_for_data(control, md='sha256')
            manifest_data['WAPT/certificate.crt'] = hexdigest_for_data(cert_chain_str, md='sha256')
            # convert to list of list...
            wapt_manifest = serialize_content_for_signature(list(manifest_data.items()))
            signature = private_key.sign_content(wapt_manifest, md='sha256')
            with open(os.path.join(self.sourcespath, self.get_manifest_filename()), 'wb') as f:
                f.write(wapt_manifest)
            with open(os.path.join(self.sourcespath, self.get_signature_filename()), 'wb') as f:
                f.write(base64.b64encode(signature))

        return base64.b64encode(signature)

    def get_manifest_filename(self):
        return 'WAPT/manifest.sha256'

    def get_signature_filename(self):
        return 'WAPT/signature.sha256'

    def _get_package_zip_entry(self, filename):
        """Open wapt zipfile and return one package zipfile entry
        could fail if zip file is already opened elsewhere...

        Returns
            zip
        """
        with CustomZipFile(self.localpath, 'r', allowZip64=True) as waptzip:
            try:
                return waptzip.getinfo(filename)
            except:
                return None

    def change_prefix(self, new_prefix):
        """Change prefix of package name to new_prefix and return True if
        it was really changed.
        """
        if '-' in self.package:
            (old_prefix, name) = self.package.split('-', 1)
            if old_prefix != new_prefix:
                self.package = '%s-%s' % (new_prefix, name)
                return True
            else:
                return False
        else:
            return False

    def change_depends_conflicts_prefix(self, new_prefix):
        """Change prefix of package name to new_prefix
        in depends and conflicts csv lists and return True if
        it was really changed.

        Args:
            new_prefix (str): new prefix to put in package names

        Returns:
            bool
        """
        result = False

        def rename_package(package, new_prefix):
            if '-' in package:
                (old_prefix, name) = package.split('-', 1)
                if old_prefix != new_prefix:
                    package = '%s-%s' % (new_prefix, name)
            return package

        # renames dependencies
        if self.depends:
            newdepends = []
            depends = ensure_list(self.depends)
            for dependname in depends:
                newname = rename_package(dependname, new_prefix)
                newdepends.append(newname)
            if self.depends != ','.join(newdepends):
                self.depends = ','.join(newdepends)
                result = True

        # renames conflicts
        if self.conflicts:
            newconflicts = []
            conflicts = ensure_list(self.conflicts)
            for dependname in conflicts:
                newname = rename_package(dependname, new_prefix)
                newconflicts.append(newname)
            if self.conflicts != ','.join(newconflicts):
                self.conflicts = ','.join(newconflicts)
                result = True

        return result

    def invalidate_signature(self):
        """Remove all signature informations from control and unzipped package directory
        Package must be in unzipped state.
        """
        # remove control signature
        for att in self.signature_attributes:
            if hasattr(self, att):
                setattr(self, att, None)

        # remove package / files signature if sources entry.
        if self.sourcespath and os.path.isdir(self.sourcespath):
            manifest_filename = os.path.abspath(os.path.join(self.sourcespath, self.get_manifest_filename()))
            if os.path.isfile(manifest_filename):
                os.remove(manifest_filename)

            signature_filename = os.path.abspath(os.path.join(self.sourcespath, self.get_signature_filename()))
            if os.path.isfile(signature_filename):
                os.remove(signature_filename)

            certificate_filename = os.path.join(self.sourcespath, 'WAPT', 'certificate.crt')
            if os.path.isfile(certificate_filename):
                os.remove(certificate_filename)

        self._invalidate_package_content()

    def list_corrupted_files(self,ignore_missing_files=False,remove_extra_files=False):
        """Check hexdigest sha for the files in manifest.
        Package must be already unzipped.

        Returns:
            list: non matching files (corrupted files)
        """

        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Package %s (path %s) is not unzipped, checking corrupted files is not supported.' % (self.asrequirement(), self.localpath))

        if not os.path.isdir(self.sourcespath):
            raise EWaptNotSourcesDirPackage('%s is not a valid package directory.' % self.sourcespath)

        manifest_filename = os.path.join(self.sourcespath, self.get_manifest_filename())
        if not os.path.isfile(manifest_filename):
            raise EWaptBadSignature('no manifest file in %s directory.' % self.sourcespath)

        with open(manifest_filename, 'r') as manifest_file:
            manifest = ujson.loads(manifest_file.read())
            if not isinstance(manifest, list):
                raise EWaptBadSignature('manifest file in %s is invalid.' % self.sourcespath)

        errors = []
        expected = []
        expected_empty_dirs = []

        for (filename, hexdigest) in manifest:
            fullpath = os.path.abspath(os.path.join(self.sourcespath, filename))
            # an empty directory
            if hexdigest=='':
                if not ignore_missing_files and not os.path.isdir(fullpath):
                    errors.append(filename)
                expected_empty_dirs.append(fullpath)
            else:
                expected.append(fullpath)
                # file was expected but has disapeared...
                if not os.path.isfile(fullpath):
                    if not ignore_missing_files:
                        errors.append(filename)
                elif hexdigest != _hash_file(fullpath, hash_func=hashlib.sha256):
                    errors.append(filename)

        files = all_files(ensure_unicode(self.sourcespath))
        # removes files which are not in manifest by design
        for fn in self.manifest_filename_excludes:
            full_fn = os.path.abspath(os.path.join(self.sourcespath, fn))
            if full_fn in files:
                files.remove(full_fn)

        extra_files = [fn for fn in files if fn not in expected]
        if remove_extra_files:
            # remove not expected files...
            for fn in extra_files:
                # useless check ?
                if os.path.isfile(fn):
                    os.unlink(fn)
        else:
            # add in errors list files found but not expected...
            errors.extend(extra_files)

        # add in errors list dirs found but not expected...
        extra_empty_dirs = [fn for fn in all_empty_dirs(ensure_unicode(self.sourcespath)) if fn not in expected_empty_dirs]
        if remove_extra_files:
            # remove not expected files...
            for fn in extra_empty_dirs:
                # useless check ?
                if os.path.isdir(fn):
                    os.rmdir(fn)
        else:
            # add in errors list files found but not expected...
            errors.extend(extra_empty_dirs)

        return errors

    def has_setup_py(self):
        if not self.sourcespath and not self.localpath and hasattr(self, 'setuppy'):
            return self.get('setuppy', None) is not None
        elif self.sourcespath or self.localpath:
            return self.has_file('setup.py')
        raise EWaptBadSetup('Unable to determine if this package has a setup.py file. No sources, no local package and no setuppy attribute')

    def check_package_signature(self, trusted_bundle, ignore_missing_files=False):
        """Check
        - hash of files in unzipped package_dir with list in package's manifest file
        - try to decrypt manifest signature with package's certificate
        - check that the package certificate is issued by a know CA or the same as one the authorized certitificates.

        Args:
            trusted_bundle (SSLCABundle) : Local certificates store. Certificates in trusted_bundle.trusted_certificates are trusted.
            ignore_missing_files  (bool): whether to raise exception for missing files. Useful to check stripped down packages when remote resigning

        Returns:
            SSLCertificate : matching certificate

        Raises:
            Exception if no certificate match is found.
        """
        if not trusted_bundle:
            raise EWaptBadCertificate('No supplied trusted_bundle to check package signature')

        if isinstance(trusted_bundle, SSLCertificate):
            cert = trusted_bundle
            trusted_bundle = SSLCABundle()
            trusted_bundle.add_certificates_from_pem(cert.as_pem(), trusted=True)

        assert(isinstance(trusted_bundle, SSLCABundle))

        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Package entry is not an unzipped sources package directory.')

        if not os.path.isdir(self.sourcespath):
            raise EWaptNotAPackage('%s is not a valid package directory.' % self.sourcespath)

        manifest_filename = os.path.join(self.sourcespath, self.get_manifest_filename())
        if not os.path.isfile(manifest_filename):
            raise EWaptNotSigned('The package %s in %s does not contain the %s file with content fingerprints' % (self.asrequirement(), self.sourcespath, self.get_manifest_filename()))

        verified_by = None

        with open(manifest_filename, 'rb') as f:
            manifest_data = f.read()

        if self.has_setup_py():
            logger.info('Package has a setup.py, code signing certificate is required.')

        signature_filename = os.path.abspath(os.path.join(self.sourcespath, self.get_signature_filename()))
        if not os.path.isfile(signature_filename):
            raise EWaptNotSigned('The package %s in %s does not contain a signature' % (self.asrequirement(), self.sourcespath))

        # first check if signature can be decrypted by any of the public keys
        with open(signature_filename, 'rb') as signature_file:
            signature = base64.b64decode(signature_file.read())
        try:
            certs = self.package_certificates()
            if not certs:
                # certificates is not embedded, use the fingerprint to get it from machine cert store
                # raise EWaptCryptoException instead of returning None because we use a fingerprint
                certs = trusted_bundle.certificate_chain(fingerprint=self.signer_fingerprint)

            issued_by = ', '.join('%s' % ca.cn for ca in trusted_bundle.check_certificates_chain(certs))
            logger.debug('Certificate %s is trusted by root CA %s' % (certs[0].subject, issued_by))

            signer_cert = certs[0]
            logger.debug('Checking signature with %s' % signer_cert)
            signer_cert.verify_content(manifest_data, signature, md='sha256')
            if self.has_setup_py() and not signer_cert.is_code_signing:
                raise SSLVerifyException('Signature OK but not a code signing certificate: %s' % signer_cert)

            verified_by = signer_cert
            logger.info('Package issued by %s, trusted issuer %s' % (signer_cert.subject,verified_by.subject))

        except Exception as e:
            logger.debug(traceback.format_exc())
            raise EWaptBadSignature('Check_package_signature failed for %s. Signer:%s :  %s' % (
                self.asrequirement(),self.signer,e))


        # now check the integrity of files
        errors = self.list_corrupted_files(ignore_missing_files=ignore_missing_files)
        if errors:
            raise EWaptCorruptedFiles('Error in package %s in %s, files corrupted, SHA not matching for %s' % (self.asrequirement(), self.sourcespath, errors,))
        return verified_by

    def unzip_package(self, target_dir=None, cabundle=None, ignore_missing_files=False):
        """Unzip package and optionnally check content

        Args:
            target_dir (str): where to unzip package content. If None, a temp dir is created
            cabundle (list) : list of Certificates to check content. If None, no check is done

        Returns:
            str : path to unzipped packages files

        Raises:
            EWaptNotAPackage, EWaptBadSignature,EWaptCorruptedFiles
            if check is not successful, unzipped files are deleted.
        """
        if not self.localpath:
            raise EWaptNotAPackage('unzip_package : Package %s is not downloaded' % ensure_unicode(self))

        if not os.path.isfile(self.localpath):
            raise EWaptNotAPackage('unzip_package : Package %s does not exists' % ensure_unicode(self.localpath))

        if target_dir is not None and not isinstance(target_dir, str):
            raise Exception('Provide a valid directory name to unzip package to')

        if not target_dir:
            target_dir = tempfile.mkdtemp(prefix="wapt")
        else:
            target_dir = os.path.abspath(target_dir)

        logger.info('Unzipping package %s to directory %s' % (self.localpath, ensure_unicode(target_dir)))
        with CustomZipFile(self.localpath, allowZip64=True) as zip:
            # check if there are unsafe filenames
            for fn in zip.namelist():
                if is_unsafe_filename(fn):
                    raise EWaptCorruptedFiles('Unzip: Unsafe filename %s in zip package file %s' % (fn,self.localpath))
            #
            try:
                zip.extractall(path=target_dir)
                self.sourcespath = target_dir
                # remove legacy signature files
                for fn in (makepath(target_dir,'WAPT','signature'), makepath(target_dir,'WAPT','manifest.sha1')):
                    if os.path.isfile(fn):
                        os.remove(fn)

                if cabundle is not None:
                    verified_by = self.check_package_signature(cabundle,ignore_missing_files=ignore_missing_files)
                    logger.info('Unzipped files verified by certificate %s' % verified_by)
            except Exception as e:
                if os.path.isdir(target_dir):
                    try:
                        shutil.rmtree(target_dir)
                    except Exception:
                        logger.critical('Unable to remove temporary files %s' % repr(target_dir))
                raise e
        return self.sourcespath


    def get_stripped_package(self):
        """Build a package keeping only Wapt stuff...
        Keeps only WAPT directory and setup.py

        Returns:
            bytes: zipped data
        """
        if not self.localpath:
            raise EWaptNotAPackage('get_stripped_package : Package %s is not downloaded' % ensure_unicode(self))

        if not os.path.isfile(self.localpath):
            raise EWaptNotAPackage('get_stripped_package : Package %s does not exists' % ensure_unicode(self.localpath))

        target_zipped_data = io.BytesIO()
        with CustomZipFile(target_zipped_data, 'w', compression=zipfile.ZIP_DEFLATED) as target_zip:
            with CustomZipFile(self.localpath, allowZip64=True) as zip:
                for fn in ('setup.py','update_package.py','WAPT/control',self.get_manifest_filename(),self.get_signature_filename(),'WAPT/certificate.crt', 'WAPT/icon.png'):
                    if zip.NameToInfo.get(fn):
                        target_zip.writestr(fn, zip.read(fn))

        return target_zipped_data.getvalue()

    def merge_stripped_package(self,stripped_package_zip_data=None,stripped_package_filename=None):
        """Use the files from stripped_package_zip_data and include it in current unzipped
        package, remove files not in manifest, and recheck file hashes.

        """
        # be sure package is in unzipped form
        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Package entry is not an unzipped sources package directory.')

        if not os.path.isdir(self.sourcespath):
            raise EWaptNotAPackage('%s is not a valid package directory.' % self.sourcespath)

        if stripped_package_zip_data is not None:
            stripped_package_file = io.BytesIO(stripped_package_zip_data)
        elif stripped_package_filename is not None:
            stripped_package_file = open(stripped_package_filename,'rb')
        else:
            raise Exception('No filename nor zip data to merge')

        try:
            with CustomZipFile(stripped_package_file, 'r') as stripped_package_zip:
                for fn in ('setup.py','update_package.py','WAPT/control',self.get_manifest_filename(),self.get_signature_filename(),'WAPT/certificate.crt'):
                    if stripped_package_zip.NameToInfo.get(fn):
                        stripped_package_zip.extract(fn,self.sourcespath)
        finally:
            stripped_package_file.close()

        # remove all files not referenced in manifest
        errors = self.list_corrupted_files(ignore_missing_files=False, remove_extra_files=True)
        if errors:
            raise EWaptCorruptedFiles('Errors in files when merging back stripped package: %s',(errors,))

        # reload replaced control data
        self.load_control_from_wapt(calc_md5=False)
        self.md5sum = None

        # invalidate local build
        self.localpath=None
        self._invalidate_package_content()

        # after whe should...
        # self.check_package_signature(ca)
        # self.build_package()

    def as_control_bytes(self):
        """Return this package entry metadata as bytes as saved in package control file

        Return:
            bytes: lines with key: value
        """
        return self.ascontrol().encode('utf8')

    def sign_stripped_package(self,certificate, private_key,
            excludes_full=DEFAULT_EXCLUDED_PATHS_FOR_BUILD, excludes=[], sign_setuppy=False):
        """Sign an unzipped source package assuming digests in manifest file are OK except for control and certificate.crt
        * remove signature files -> WAPT/certificate.crt, WAPT/signature.sha256,
        * resign WAPT/control
        * update control hash in WAPT/manifest.sha256
        * resign WAPT/manifest.sha256 and put in WAPT/signature.sha256

        Args:
            certificate (list of SSLCertificate) : certificates chain of the signer. First certificate is the signer's one. other are intermediate CA
            private_key (SSLPrivateKey) : key to sign the control and manifest files.
            excludes_full
            excludes

        Returns:
            str: signature of manifest.sha256

        """

        if not self.sourcespath:
            raise EWaptNotSourcesDirPackage('Package entry is not an unzipped sources package directory.')

        if not os.path.isdir(self.sourcespath):
            raise EWaptNotAPackage('%s is not a valid package directory.' % self.sourcespath)

        self.set_icon_sha256sum()

        if isinstance(certificate, list):
            signer_cert = certificate[0]
            certificate_chain = certificate
        else:
            signer_cert = certificate
            certificate_chain = [certificate]

        cert_chain_str = None
        if private_key is None:
            raise EWaptPackageSignError('No private key provided for signing for certificate %s' % signer_cert)
        if not private_key.match_cert(signer_cert) :
            raise EWaptPackageSignError('Private key does not match public key in certificate %s' % signer_cert)

        package_fn = self.localpath or self.sourcespath
        logger.debug('Signing stripped down package %s with key %s, and certificate CN "%s"' % (package_fn, private_key, signer_cert.cn))
        self._sign_control(certificate=signer_cert, private_key=private_key)

        # control file is appended to manifest file separately.
        control_data = self.as_control_bytes()
        with open(os.path.join(self.sourcespath, 'WAPT', 'control'), 'wb') as f:
            f.write(control_data)

        # be sure not to keep in memory zipped content
        self._invalidate_package_content()

        # replace certificate.crt
        cert_chain_str = b'\n'.join([cert.as_pem() for cert in certificate_chain])
        with open(os.path.join(self.sourcespath, 'WAPT', 'certificate.crt'), 'wb') as f:
            f.write(cert_chain_str)

        # update manifest.sha256
        manifest_filename = os.path.join(self.sourcespath, self.get_manifest_filename())
        if not os.path.isfile(manifest_filename):
            raise EWaptNotSigned('The package %s in %s does not contain the %s file with content fingerprints' % (self.asrequirement(), self.sourcespath, self.get_manifest_filename()))
        with open(manifest_filename, 'rb') as f:
            manifest_data = f.read()
        manifest_filelist = ujson.loads(manifest_data)
        new_manifest_filelist = []
        for fn_digest in manifest_filelist:
            # replace digest for resigned files
            if fn_digest[0] == 'WAPT/control':
                fn_digest[1] = hexdigest_for_data(control_data)
            elif fn_digest[0] == 'WAPT/certificate.crt':
                fn_digest[1] = hexdigest_for_data(cert_chain_str)
            elif sign_setuppy and fn_digest[0] == 'setup.py':
                with open(os.path.join(self.sourcespath, 'setup.py'), 'rb') as f:
                    new_setup_hash = hexdigest_for_data(f.read())
                if new_setup_hash != fn_digest[1]:
                    if not signer_cert.is_code_signing:
                        raise EWaptPackageSignError('Certificate is not a code signing. Updating setup.py is not allowed.')
                    fn_digest[1] = new_setup_hash

            # excludes unwanted files from manifest
            if not fn_digest[0] in excludes_full:

                excluded = False
                for exclude_glob in excludes:
                    if glob.fnmatch.fnmatch(fn_digest[0], exclude_glob):
                        excluded = True
                        break

                if not excluded:
                    new_manifest_filelist.append(fn_digest)

        # convert to list of list...
        wapt_manifest = serialize_content_for_signature(new_manifest_filelist)
        # sign with default md
        signature = private_key.sign_content(wapt_manifest)
        with open(os.path.join(self.sourcespath, self.get_manifest_filename()), 'wb') as f:
            f.write(wapt_manifest)
        with open(os.path.join(self.sourcespath, self.get_signature_filename()), 'wb') as f:
            f.write(base64.b64encode(signature))

        return base64.b64encode(signature)


    def delete_localsources(self):
        """Remove the unzipped local directory
        """
        if self.sourcespath and os.path.isdir(self.sourcespath):
            try:
                shutil.rmtree(self.sourcespath)
                self.sourcespath = None
            except Exception:
                pass

    def as_zipfile(self, mode='r'):
        """Return a CustomZipFile for this package for read only operations"""
        if self.localpath and os.path.isfile(self.localpath):
            return CustomZipFile(self.localpath, compression=zipfile.ZIP_DEFLATED, allowZip64=True, mode=mode)
        elif self._package_content is not None:
            return CustomZipFile(io.BytesIO(self._package_content), mode=mode, compression=zipfile.ZIP_DEFLATED, allowZip64=True)
        else:
            raise EWaptMissingLocalWaptFile('This PackageEntry has no local content for zip operations %s' % self.asrequirement())


    def _set_hook_module_environment(self,module, wapt_context=None, params=None, force=None, user=None):
            # get definitions of required parameters from setup module
            if hasattr(module, 'required_params'):
                required_params = module.required_params
                if not isinstance(required_params, dict):
                    required_params = {k: None for k in required_params}
                else:
                    required_params = copy.deepcopy(required_params)
            else:
                required_params = {}

            # be sure some minimal functions are available in module module at install step
            setattr(module, 'basedir', self.sourcespath)
            setattr(module, 'control', self)
            setattr(module, 'force', force)

            if not hasattr(module, 'uninstallkey'):
                module.uninstallkey = []

            persistent_source_dir = None
            persistent_dir = None

            if self.sourcespath and os.path.isdir(self.sourcespath):
                persistent_source_dir = os.path.join(self.sourcespath, 'WAPT', 'persistent')

            setattr(module, 'persistent_source_dir', persistent_source_dir)

            if wapt_context:
                # run and run_notfatal are replaced by pids aware versions
                setattr(module, 'run', wapt_context.run)
                setattr(module, 'run_notfatal', wapt_context.run_notfatal)
                setattr(module, 'WAPT', wapt_context)
                setattr(module, 'language', wapt_context.language)
                setattr(module, 'user', user or wapt_context.user)
                setattr(module, 'usergroups', wapt_context.usergroups)

            else:
                setattr(module, 'WAPT', None)
                setattr(module, 'language', get_language())
                # todo
                setattr(module, 'user', None)
                setattr(module, 'usergroups', [])

            if hasattr(self, 'persistent_dir') and self.persistent_dir:
                persistent_dir = self.persistent_dir
            elif self.package_uuid and wapt_context:
                persistent_dir = os.path.join(wapt_context.persistent_root_dir, self.package_uuid)
            else:
                # dev mode
                persistent_dir = persistent_source_dir

            setattr(module, 'persistent_dir', persistent_dir)

            # set params dictionary
            if not hasattr(module, 'params'):
                # create a params variable for the module.install func call
                setattr(module, 'params', required_params)
            else:
                # update the already created params with additional params from command line
                module.params.update(required_params)

            # add specific hook call arguments
            if params is not None:
                module.params.update(params)


    def call_setup_hook(self, hook_name='session_setup', wapt_context=None, params=None, force=None, user=None):
        """Calls a hook in setuppy given a wapt_context

        Set basedir, control, and run context within the function context.

        Args:
            hook_name (str): name of function to call in setuppy
            wapt_context (Wapt) : run context

        Returns:
            output of hook.

        Changes:

            1.6.2.1: the called hook is run with Disabled win6432 FileSystem redirection
        """
        setuppy = None

        if self.sourcespath:
            setup_filename = os.path.join(self.sourcespath, 'setup.py')
            # PackageEntry from developement or temporary directory with setup.py in a file
            if not os.path.isfile(setup_filename):
                raise EWaptNotAPackage('There is no setup.py file in %s, aborting.' % ensure_unicode(self.sourcespath))
            else:
                setuppy = codecs.open(setup_filename, 'r', encoding='utf8').read()
        else:
            # PackageEntry from database with stored setup.py as a field
            setuppy = getattr(self, 'setuppy', None)
            setup_filename = None

        if setuppy is None:
            if self.localpath:
                # we have a zipped package file, but it is not unzipped in a temporary directory
                raise EWaptBadSetup('Package %s has not been unzipped yet, unable to call %s' % (self.asrequirement(), hook_name))
            else:
                # we have a PackageEntry without setuppy
                raise EWaptBadSetup('No setup.py source for package %s, unable to call %s' % (self.asrequirement(), hook_name))

        # we  record old sys.path as we will include current setup.py
        oldpath = sys.path

        try:
            previous_cwd = os.getcwd()
            if self.sourcespath:
                os.chdir(self.sourcespath)

            # import the setup module from package file
            logger.info("  sourcing setuppy file %s " % ensure_unicode(setup_filename))
            if setup_filename:
                # import code as file to allow debugging.
                setup = import_setup(setup_filename)
            else:
                setup = import_code(setuppy)

            hook_func = getattr(setup, hook_name, None)
            if hook_func is None:
                raise EWaptMissingPackageHook('No %s function found in setup module for %s' % (hook_name, setup_filename or self.asrequirement()))

            try:
                self._set_hook_module_environment(setup, wapt_context=wapt_context, params=params, force=force, user=user)
                logger.info("  executing setup.%s(%s) " % (hook_name, repr(setup.params)))
                with _disable_file_system_redirection():
                    hookdata = hook_func()
                return hookdata
            except Exception as e:
                logger.critical('Fatal error in %s function: %s:\n%s' % (hook_name, ensure_unicode(e), ensure_unicode(traceback.format_exc())))
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

    def get_values_for_db(self, locale_code):
        return (self.package_uuid,
                self.package,
                self.categories,
                self.version,
                self.architecture,
                self.section,
                self.priority,
                self.maintainer,
                self.get_localized_description(locale_code),
                self.filename,
                self.size,
                self.md5sum,
                self.depends,
                self.conflicts,
                self.sources,
                self.repo_url,
                self.repo,
                self.signer,
                self.signer_fingerprint,
                self.signature,
                self.signature_date,
                self.signed_attributes,
                self.min_wapt_version,
                self.maturity,
                self.locale,
                self.installed_size,
                self.target_os,
                self.max_os_version,
                self.min_os_version,
                self.impacted_process,
                self.audit_schedule,
                self.name,
                self.editor,
                self.keywords,
                self.licence,
                self.homepage,
                self.changelog,
                self.valid_from,
                self.valid_until,
                self.forced_install_on,
                self.icon_sha256sum,
                )

    def add_depends(self,to_add):
        to_add = ensure_list(to_add)
        if self.depends == '':
            new_depends = []
        else:
            new_depends = self.depends.split(',')
        updated = False
        for depend in to_add:
            if not depend in new_depends:
                new_depends.append(depend)
                updated = True
        if updated:
            self.depends = ','.join(new_depends)

    def remove_depends(self,to_remove):
        to_remove = ensure_list(to_remove)
        if self.depends == '':
            depends = []
        else:
            depends = self.depends.split(',')
        new_depends = []
        updated = False
        for depend in depends:
            if not depend in to_remove:
                new_depends.append(depend)
                updated = True
        if updated:
            self.depends = ','.join(new_depends)

    def add_conflicts(self,to_add):
        to_add = ensure_list(to_add)
        if self.conflicts == '':
            new_conflicts = []
        else:
            new_conflicts = self.conflicts.split(',')
        updated = False
        for conflict in to_add:
            if not conflict in new_conflicts:
                new_conflicts.append(conflict)
                updated = True
        if updated:
            self.conflicts = ','.join(new_conflicts)

    def remove_conflicts(self,to_remove):
        to_remove = ensure_list(to_remove)
        if self.conflicts == '':
            conflicts = []
        else:
            conflicts = self.conflicts.split(',')
        new_conflicts = []
        updated = False
        for conflict in conflicts:
            if not conflict in to_remove:
                new_conflicts.append(conflict)
                updated = True
        if updated:
            self.conflicts = ','.join(new_conflicts)

    def matches_host_capabilities_string(self,capabilities):
        """Return True if package is matching the host package raw capability string

        """
        (os_name, os_version, architecture, locales, maturities) = capabilities.split(',')[0:5]
        locales = locales.split('|')
        maturities = maturities.split('|')
        capa = HostCapabilities(from_string_filter = capabilities)
        return capa.is_matching_package(self)


class WaptPackageDev(PackageEntry):
    """Source package directory"""

    def build_package(self, directoryname, inc_package_release=False, excludes=[],
                      target_directory=None):
        raise NotImplementedError()


class WaptPackage(PackageEntry):
    """Built Wapt package zip file"""

    def __init__(self, package_filename):
        PackageEntry.__init__(self)
        self.package_filename = package_filename


def extract_iconpng_from_wapt(fname):
    """Return the content of WAPT/icon.png if it exists, a unknown.png file content if not

    """
    iconpng = None
    if os.path.isfile(fname):
        with CustomZipFile(fname, 'r', allowZip64=True) as waptzip:
            try:
                iconpng = waptzip.open('WAPT/icon.png').read()
            except:
                pass
    elif os.path.isdir(fname):
        png_path = os.path.join(fname, 'WAPT', 'icon.png')
        if os.path.isfile(png_path):
            with open('WAPT/icon.png', 'rb') as f:
                iconpng = f.read()

    if not iconpng:
        raise Exception('no icon.png found in package name {}'.format(fname))

    return iconpng


class WaptBaseRepo(BaseObjectClass):
    """Base abstract class for a Wapt Packages repository
    """

    _default_config = {
        'public_certs_dir': '',
        'check_certificates_validity': '1',
    }

    def __init__(self, name='abstract', cabundle=None, config=None, section=None):
        """Init properties, get default values from _default_config, and override them
                with constructor paramaters

        Args:
            name (str): internal name of the repository
            cabundle (CASSLBundle) : ca signature checking.

        Returns:
            self
        """

        self.name = name
        self._section = None
        self._packages = None
        self._index = {}
        self._index_by_uuid = {}

        self._packages_date = None
        self._cabundle = None
        self._public_certs_dir = ''
        self._index_config_fingerprint = None

        self.discarded = []
        self.check_certificates_validity = None

        self.packages_whitelist = None
        self.packages_blacklist = None

        self.maturities = None

        self.load_config(config=config, section=section)

        # if not None, control's signature will be check against this certificates list
        if cabundle is not None:
            self._cabundle = cabundle

    @property
    def repo_url(self):
        return None

    @property
    def public_certs_dir(self):
        return self._public_certs_dir

    @public_certs_dir.setter
    def public_certs_dir(self, value):
        if value != self._public_certs_dir:
            self._cabundle = None
            self._public_certs_dir = value

    @property
    def cabundle(self):
        if self._cabundle is not None:
            return self._cabundle
        elif self.public_certs_dir:
            if self._cabundle is None:
                self._cabundle = SSLCABundle()
                self._cabundle.add_pems(self.public_certs_dir, trust_first=True, load_keys=False)
            return self._cabundle
        else:
            return None

    @cabundle.setter
    def cabundle(self, value):
        # direct setting
        if value != self._cabundle:
            self._cabundle = value
            self._public_certs_dir = None

    def load_config(self, config=None, section=None):
        """Load configuration from inifile section.
        Use name of repo as section name if section is not provided.
        Use 'global' if no section named section in ini file
        Value not defined in ini file are taken from class _default_config dict

        load_config is called at __init__, eventually with config = None.
        In this case, all parameters are initialized from defaults

        Args:
            config (RawConfigParser): ini configuration
            section (str)           : section where to loads parameters
                                      defaults to name of repository

        Returns:
            self: return itself to chain calls.
        """
        if not section:
            section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            section = 'global'

        if config.has_option(section, 'public_certs_dir') and config.get(section, 'public_certs_dir') != '':
            self.public_certs_dir = config.get(section, 'public_certs_dir')

        if config.has_option(section, 'check_certificates_validity'):
            self.check_certificates_validity = config.getboolean(section, 'check_certificates_validity')

        if config.has_option(section, 'packages_whitelist'):
            self.packages_whitelist = ensure_list(config.get(section, 'packages_whitelist'), allow_none=True)

        if config.has_option(section, 'packages_blacklist'):
            self.packages_blacklist = ensure_list(config.get(section, 'packages_blacklist'), allow_none=True)

        if config.has_option(section, 'maturities'):
            self.maturities = ensure_list(config.get(section, 'maturities'), allow_none=True)
            if not self.maturities:
                self.maturities = None

        self._section = section

        self._cabundle = None

        return self

    def config_fingerprint(self):
        config_attributes = ['_packages_date', 'public_certs_dir', 'check_certificates_validity', 'packages_whitelist', 'packages_blacklist', 'maturities', 'repo_url', 'localpath', 'proxies']
        return hashlib.sha256((''.join(['%s' % getattr(self, a) for a in config_attributes if hasattr(self, a)])).encode('utf8')).hexdigest()

    def load_config_from_file(self, config_filename, section=None):
        """Load repository configuration from an inifile located at config_filename

        Args:
            config_filename (str) : path to wapt inifile
            section (str): ini section from which to get parameters. default to repo name

        Returns:
            WaptBaseRepo: self

        """
        if section is None:
            section = self.name

        ini = RawConfigParser()
        ini.read(config_filename)
        self.load_config(ini, section)

        return self

    def _add_package(self,entry: 'PackageEntry'):
        """Add a package to the in memory repository index
        """
        if entry.package_uuid:
            package_uuid = entry.package_uuid
        else:
            package_uuid = entry.make_fallback_uuid()

        if not package_uuid in self._index_by_uuid:
            # index by uuid
            self._index_by_uuid[package_uuid] = entry
            self._packages.append(entry)

        # index last version
        if entry.package not in self._index or self._index[entry.package] < entry:
            self._index[entry.package] = entry

        entry.repo = self.name
        entry.repo_url = self.repo_url

    def _load_packages_index(self):
        """Must be overriden to set _packages and _packages_date to something
        different than None
        """
        self._packages = []
        self._index = {}
        self._index_by_uuid = {}

        self._packages_date = datetime2isodate()
        self.discarded = []

    def _get_packages_index_data(self):
        """Method to get packages index as bytes from repository and last update date of ths index

        Returns:
            tuple (bytes,datetime) : data and last update datetime UTC
        """
        return (None, datetime.datetime.utcnow())

    def get_certificates(self, packages_zipfile=None):
        """Download signers certificates and crl from Package index on remote repository.

            These certificates and CRL are appended to Packages index when scanning
            packages.

        Args:
            packages_zipfile (zipfile): if None, donwload it from repo

        Returns :
            SSLCABundle or None if Packages does not exists
        """
        signer_certificates = SSLCABundle()
        if packages_zipfile is None:
            (packages_index_data, _dummy_date) = self._get_packages_index_data()
            if packages_index_data:
                packages_zipfile = CustomZipFile(io.BytesIO(packages_index_data))

        if packages_zipfile:
            files = packages_zipfile.filelist
            for fn in files:
                if not fn.is_dir():
                    if fn.filename.startswith('ssl/'):
                        cert = SSLCertificate(crt_string=packages_zipfile.read(name=fn.filename))
                        if not self.check_certificates_validity or cert.is_valid():
                            signer_certificates.add_certificates(cert)
                    if fn.filename.startswith('crl/'):
                        try:
                            data = packages_zipfile.read(name=fn.filename)
                            crl = SSLCRL(der_data=data)
                        except:
                            crl = SSLCRL(pem_data=data)
                        signer_certificates.add_crl(crl)

        #logger.debug('Packages embedded certificates : %s' % signer_certificates.certificates())
        return signer_certificates

    def invalidate_packages_cache(self):
        """Reset in memory packages index
        Returns the old content of cached (packages, packages index date, discarded packages)

        Returns:
            dict : old cache status dict(_packages=self._packages,_packages_date=self._packages_date,discarded=self.discarded)
        """
        old_status = dict(_packages=self._packages, _packages_date=self._packages_date, discarded=self.discarded)
        self._packages = None
        self._packages_date = None
        self._index = {}
        self._index_by_uuid = {}

        self.discarded = []
        self._index_config_fingerprint = None
        return old_status

    def update(self):
        """Update local index of packages from source index

        Returns:
            last packages update  file date
        """
        self._load_packages_index()
        self._index_config_fingerprint = self.config_fingerprint()
        return self._packages_date

    def is_locally_allowed_package(self, package):
        """Return True if package is not in blacklist and is in whitelist if whitelist is not None
        packages_whitelist and packages_blacklist are list of package name wildcards (file style wildcards)
        blacklist is taken in account first if defined.
        whitelist is taken in acoount if not None, else all not blacklisted package names are allowed.
        """
        if self.maturities is not None:
            # historical special case for PROD or empty maturity
            if package.maturity in ('', 'PROD'):
                if not ('PROD' in self.maturities or '' in self.maturities):
                    return False
            elif not package.maturity in self.maturities:
                return False

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

    def packages(self):
        """Return list of packages, load it from repository if not yet available in memory
        To force the reload, call invalidate_index_cache() first or update()

        """
        if self._index_config_fingerprint != self.config_fingerprint():
            self.invalidate_packages_cache()
        if self._packages is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()
        return self._packages

    def packages_date(self):
        """Date of last known packages index

        Returns:
            str: date/time of Packages index in iso format (string)
        """
        if self._packages_date is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()

        return self._packages_date

    def is_available(self):
        """Return isodate of last updates of the repo is available else None
        """
        return self.packages_date()

    def need_update(self, last_modified=None):
        """Check if packages index has changed on repo and local index needs an update

        Compare date on local package index DB with the Packages file on remote
          repository with a HEAD http request.

        Args:
            last_modified (str): iso datetime of last known update of packages.

        Returns
            bool:   True if either Packages was never read or remote date of Packages is
                    more recent than the provided last_modifed date.

        >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> waptdb = WaptDB('c:/wapt/db/waptdb.sqlite')
        >>> res = repo.need_update(waptdb.read_param('last-%s'% repo.url))
        >>> isinstance(res,bool)
        True
        """
        # config has changed
        if self._index_config_fingerprint is not None and self._index_config_fingerprint != self.config_fingerprint():
            return True

        # package_date is unknown
        if not last_modified and not self._packages_date:
            logger.debug('need_update : no last_modified date provided, update is needed')
            return True

        if not last_modified:
            last_modified = self._packages_date

        # check if remote packages index date has been changed
        if last_modified:
            logger.debug('Check last-modified header for %s to avoid unecessary update' % (self.name,))
            current_update = self.is_available()
            if current_update == last_modified:
                logger.info('Index from %s has not been updated (last update %s), skipping update' % (self.repo_url, current_update))
                return False
            else:
                logger.info('Index from %s has been updated (on %s)' % (self.repo_url, current_update))
                return True
        else:
            return True

    def search(self, searchwords=[], sections=[], newest_only=False, exclude_sections=[], description_locale=None,
               host_capabilities=None, package_request=None, dependencies_list=[]):
        """Return list of package entries
            with description or name matching all the searchwords and section in
            provided sections list

        Args:
            searchwords (list or csv) : list of word to lookup in description and package names
            sections (list or csv) : list of package sections to use when searching
            newest_only (bool) : returns only highest version of package
            exclude_sections (list or csv): list of package sections to exclude when searching
            description_locale (str): if not None, search in description using this locale
            host_capabilities (HostCapabilities or dict): restrict output to these capabilities (os version locales, arch etc..)
            package_request (PackageRequest or dict) : restrict output to these filters, and sort output based on them

        Returns:
            list of PackageEntry with additional _localized_description added if description_locale is provided

        >>> r = WaptRemoteRepo(name='test',url='http://wapt.tranquil.it/wapt')
        >>> r.search('test')
        """
        searchwords = ensure_list(searchwords)
        sections = ensure_list(sections)
        exclude_sections = ensure_list(exclude_sections)
        if host_capabilities is not None and not isinstance(host_capabilities, HostCapabilities):
            # if dict
            host_capabilities = HostCapabilities(**host_capabilities)

        if package_request is not None and not isinstance(package_request, PackageRequest):
            # if given as dict from lazarus
            package_request = PackageRequest(**package_request)

        words = [w.lower() for w in searchwords]

        result = []
        if package_request is not None:
            packages = self.packages_matching(package_request)
        else:
            packages = self.packages()

        for package in packages:
            if host_capabilities is not None and not host_capabilities.is_matching_package(package):
                continue
            selected = True
            if description_locale is not None:
                _description = package.get_localized_description(description_locale)
                package._localized_description = _description
            else:
                _description = package.description

            for w in words:
                if w not in (_description+' '+package.package).lower():
                    selected = False
                    break

            if not newest_only and len(dependencies_list) > 0:
                has_at_least_one_dependency = False
                depends_list = package.depends.split(',')
                for dependency in dependencies_list:
                    if dependency in depends_list:
                        has_at_least_one_dependency = True
                        break
                selected = selected and has_at_least_one_dependency

            if sections:
                if package.section not in sections:
                    selected = False

            if selected and package.section in exclude_sections:
                selected = False

            if selected:
                result.append(package)

        if host_capabilities:
            result = sorted(result,reverse=True, key=host_capabilities.get_package_request_filter().get_package_compare_key)
        elif package_request:
            result = sorted(result,reverse=True, key=package_request.get_package_compare_key)
        else:
            result = sorted(result,reverse=True, key=PackageEntry.package_ident)

        if newest_only:
            filtered = {}
            for p in result:
                if p.package in filtered and Version(p.version) < Version(filtered[p.package].version):
                    continue
                valid = True
                if len(dependencies_list) > 0:
                    depends_list = p.depends.split(',')
                    valid = False
                    for dependency in dependencies_list:
                        if dependency in depends_list:
                            valid = True
                            break
                if p.package in filtered and not valid:
                    del filtered[p.package]
                if valid:
                    filtered[p.package] = p
            return list(filtered.values())
        else:
            return sorted(result)

    def get_package_entries(self, packages_names):
        r"""Return most up to date packages entries for packages_names
        packages_names is either a list or a string
        Returns:
            dict: a dictionnary with {'packages':[],'missing':[]}

        >>> r = WaptRemoteRepo()
        >>> r.load_config_from_file('c:/wapt/wapt-get.ini')
        >>> res = r.get_package_entries(['tis-firefox','tis-putty'])
        >>> isinstance(res['missing'],list) and isinstance(res['packages'][0],PackageEntry)
        True
        """
        result = {'packages': [], 'missing': []}
        if isinstance(packages_names, str) or isinstance(packages_names, str):
            packages_names = [p.strip() for p in packages_names.split(",")]
        for package_name in packages_names:
            matches = self.packages_matching(package_name)
            if matches:
                result['packages'].append(matches[-1])
            else:
                result['missing'].append(package_name)
        return result

    def packages_matching(self, package_cond: Union[str,PackageRequest] = None, **kwargs) -> list:
        """Return an ordered list of available packages entries which match
        the condition "packagename[([=<>]version)]?"
        version ascending

        Args:
            package_cond (str or PackageRequest): package name with optional version specifier.

        Returns:
            list of PackageEntry

        >>> from waptpackage import *
        >>> r = WaptRemoteRepo('http://wapt.tranquil.it/wapt')
        >>> r.packages_matching('tis-firefox(>=20)')
        [PackageEntry('tis-firefox','20.0.1-02'),
         PackageEntry('tis-firefox','21.0.0-00'),
         ...]
        """
        if package_cond is not None and not isinstance(package_cond, PackageRequest):
            package_cond = PackageRequest(request=package_cond, **kwargs)
        elif package_cond is None and kwargs is not None:
            package_cond = PackageRequest(**kwargs)

        if package_cond is None:
            return sorted(self.packages())
        else:
            # sort using filter criteria preferences
            return sorted(
                [p for p in self.packages() if package_cond.is_matched_by(p)],
                key=package_cond.get_package_compare_key
            )

    def __iter__(self):
        """Return an iterator for package names (higer version)"""
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()

        return self._index.__iter__()

    def __getitem__(self, packagename):
        """Return the highest version PackageEntry for supplied packagename
        """
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()

        return self._index[packagename]

    def get(self, packagename, default=None):
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()

        return self._index.get(packagename, default)

    def as_dict(self) -> dict:
        result = {
            'name': self.name,
            'packages_whitelist': self.packages_whitelist,
            'packages_blacklist': self.packages_blacklist,
            'check_certificates_validity': self.check_certificates_validity,
            'authorized_certificates': self.authorized_certificates,
            'maturities': self.maturities,
        }
        return result

    @property
    def authorized_certificates(self) -> Sequence[dict]:
        """List of authorized signers certificates attributes

        Returns:
            list [dict]
        """
        return [[dict(c) for c in self.cabundle.certificates()] if self.cabundle else None]

    def get_package_by_uuid(self,package_uuid: str) -> PackageEntry:
        # ensure packages is loaded
        if self._packages is None:
            self._load_packages_index()
            self._index_config_fingerprint = self.config_fingerprint()
        return self._index_by_uuid.get(package_uuid,None)


class WaptLocalRepo(WaptBaseRepo):
    """Index of Wapt local repository.
        Index of packages is located in a Packages zip file, having one
            Packages file, containing the concatenated content of "control"
            files of the packages.

            A blank line means new package.
    >>> localrepo = WaptLocalRepo('c:/wapt/cache')
    >>> localrepo.update()
    """

    def __init__(self, localpath=None, name='waptlocal', cabundle=None, config=None, section=None):
        # store defaults at startup
        self._default_config.update({
            'localpath': '',
        })

        WaptBaseRepo.__init__(self, name=name, cabundle=cabundle, config=None, section=section)

        # override defaults and config with supplied parameters
        if localpath is not None:
            self.localpath = ensure_unicode(localpath.rstrip(os.path.sep))

    @property
    def repo_url(self):
        return 'file:///%s' % self.localpath.replace('\\','/')

    @property
    def packages_path(self):
        return os.path.abspath(os.path.join(self.localpath, 'Packages'))


    def is_available(self, url=None):
        """Check if repo is reachable an return creation date of Packages.

        Returns:
            str: Iso creation date of remote Package file as returned in http headers

        """
        if os.path.isfile(self.packages_path):
            return fileisoutcdate(self.packages_path)
        else:
            return None


    def _get_packages_index_data(self):
        """Download or load local Packages index raw zipped data

        Returns:
            file: File like object for Packages Zipped data (local or remote)
        """
        if os.path.isfile(self.packages_path):
            with open(self.packages_path, mode='rb') as f:
                return (f.read(), fileutcdate(self.packages_path))
        else:
            return (None, None)

    def _load_packages_index(self):
        """Parse Packages index from local repo Packages file

        Packages file is zipped file with one file named Packages.

        This files is the concatenation of control files of each package
          in the repository

        Returns:
            None

        >>> repo = WaptLocalRepo(localpath='c:\\wapt\\cache')
        >>> repo._load_packages_index()
        >>> isinstance(repo.packages,list)
        True
        """
        # Packages file is a zipfile with one Packages file inside
        if not os.path.isdir(os.path.dirname(self.packages_path)):
            raise EWaptException('Directory for wapt local repo %s does not exist' % self.packages_path)

        if os.path.isfile(self.packages_path):
            (packages_data_str, _packages_datetime) = self._get_packages_index_data()
            self._packages_date = datetime2isodate(_packages_datetime)
            with CustomZipFile(io.BytesIO(packages_data_str)) as packages_file:
                packages_lines = packages_file.read(name='Packages').decode('utf8').splitlines()

            if self._packages is not None:
                del(self._packages[:])
            else:
                self._packages = []
            self._index.clear()
            self._index_by_uuid.clear()

            self.discarded = []

            startline = 0
            endline = 0

            def add(start, end):
                if start != end:
                    package = PackageEntry()
                    package._load_control('\n'.join(packages_lines[start:end]))
                    logger.debug("%s (%s)" % (package.package, package.version))
                    package.repo_url = 'file:///%s' % (self.localpath.replace('\\', '/'))
                    package.repo = self.name
                    package.localpath = os.path.join(self.localpath,sanitize_filename(package.filename))

                    if self.is_locally_allowed_package(package):
                        try:
                            if self.cabundle is not None:
                                package.check_control_signature(self.cabundle)
                            self._add_package(package)
                        except Exception as e:
                            logger.info('Package %s discarded because: %s' % (package.localpath, e))
                            self.discarded.append(package)
                    else:
                        logger.info('Discarding %s on repo "%s" because of local whitelist of blacklist rules' % (package.asrequirement(), self.name))
                        self.discarded.append(package)

            for line in packages_lines:
                if line.strip() == '':
                    add(startline, endline)
                    endline += 1
                    startline = endline
                # add ettribute to current package
                else:
                    endline += 1
            # last one
            add(startline, endline)
        else:
            self.invalidate_packages_cache()
            self._packages = []
            logger.info('Index file %s does not yet exist' % self.packages_path)

    def _extract_icon(self, entry):
        # looks for an icon in wapt package
        icons_path = os.path.abspath(os.path.join(self.localpath, 'icons'))
        if not os.path.isdir(icons_path):
            os.makedirs(icons_path)
        icon_fn = os.path.join(icons_path, "%s.png" % entry.icon_sha256sum)
        if entry.icon_sha256sum and not os.path.isfile(icon_fn):
            try:
                icon = extract_iconpng_from_wapt(entry.localpath)
                with open(icon_fn, 'wb') as f:
                    f.write(icon)
            except Exception as e:
                logger.debug(r"Unable to extract icon for %s:%s" % (entry.localpath, e))

    def _append_package_to_index(self, entry: PackageEntry):
        """Append a single package to zipped index Packages without checking if it exists already

        Returns:
            str: local path

        """
        packages_fname = os.path.abspath(os.path.join(self.localpath, 'Packages'))
        self._packages = None

        if not entry.md5sum and entry.localpath and os.path.isfile(entry.localpath):
            logger.warning("Missing md5sum, calc it now.")
            entry.md5sum = entry._calc_md5sum()
            entry.size = os.path.getsize(entry.localpath)
            new_fn = entry.make_package_filename(with_md5sum = True)
            if new_fn != entry.filename:
                logger.warning("Renaming entry filename from %s to %s" % (entry.filename,new_fn))
                entry.filename = new_fn
                entry.localpath = os.path.join(os.path.dirname(entry.localpath),entry.filename)

        logger.info("Building new %s" % packages_fname)
        tmp_packages_fname = packages_fname+'.%s' % datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        try:
            shutil.copy2(packages_fname, tmp_packages_fname)
            with CustomZipFile(tmp_packages_fname, "a", compression=zipfile.ZIP_DEFLATED) as myzipfile:
                packages_lines = myzipfile.read('Packages').decode('utf8').splitlines()
                if packages_lines and packages_lines[-1] != '':
                    packages_lines.append('')
                packages_lines.append(entry.ascontrol(with_repo_attributes=True))
                packages_lines.append('')

                myzipfile.remove("Packages")
                zi = zipfile.ZipInfo("Packages", date_time=time.localtime())
                zi.compress_type = zipfile.ZIP_DEFLATED
                myzipfile.writestr(zi, '\n'.join(packages_lines).encode('utf8'))

                # Add list of signers certificates
                certs = entry.package_certificates()
                if certs:
                    for crt in certs:
                        crt_filename = "ssl/%s.crt" % crt.fingerprint
                        if not myzipfile.NameToInfo.get(crt_filename):
                            zi = zipfile.ZipInfo(crt_filename, date_time=time.localtime())
                            zi.compress_type = zipfile.ZIP_DEFLATED
                            myzipfile.writestr(zi, crt.as_pem())

            if os.path.isfile(packages_fname):
                with open(packages_fname,'rb') as old_packages, open(tmp_packages_fname,'rb') as new_packages:
                    old_data = old_packages.read()
                    new_data = new_packages.read()
                if old_data != new_data:
                    # we discard old file and rename new one to Packages
                    logger.info("Writing new %s" % packages_fname)
                    os.unlink(packages_fname)
                    shutil.move(tmp_packages_fname, packages_fname)
                else:
                    # we discard new file as it is indentical to old one
                    logger.info("Skipping new %s" % packages_fname)
                    os.unlink(tmp_packages_fname)
            else:
                logger.info("Writing initial %s" % packages_fname)
                shutil.move(tmp_packages_fname, packages_fname)
            logger.info("Finished")
            return entry.localpath

        except Exception as e:
            if os.path.isfile(tmp_packages_fname):
                os.unlink(tmp_packages_fname)
            logger.critical('Unable to create new Packages file : %s' % e)
            raise e

    def _ensure_canonical_package_filename(self, entry, with_md5sum=False):
        """Rename the local wapt package so that it complies with canonical package naming rules

        """
        theoritical_package_filename = entry.make_package_filename(with_md5sum = with_md5sum)
        package_filename = entry.filename
        if package_filename != theoritical_package_filename:
            logger.warning('Package filename %s should be %s to comply with control metadata. Renaming...' % (package_filename, theoritical_package_filename))
            new_fn = os.path.join(os.path.dirname(entry.localpath), theoritical_package_filename)
            shutil.move(entry.localpath, new_fn)
            entry.filename = theoritical_package_filename
            return new_fn
        else:
            return None

    def update_packages_index(self, force_all=False, proxies=None,
            canonical_filenames=False,
            include_host_packages=False,
            include_certificates=True,
            include_crls=True,
            extract_icons=True):
        """Scan self.localpath directory for WAPT packages and build a Packages (utf8) zip file with control data and MD5 hash

        Extract icons from packages (WAPT/icon.png) and stores them in <repo path>/icons/<package name>.png
        Extract certificate and add it to Packages zip file in ssl/<fingerprint.crt>
        Append CRL for certificates.

        Returns:
            dict :  {'processed':processed,'kept':kept,'errors':errors,'packages_filename':packages_fname}

        """
        if not os.path.isdir(self.localpath):
            os.makedirs(self.localpath)

        if include_crls:
            include_certificates = True

        packages_fname = os.path.abspath(os.path.join(self.localpath, 'Packages'))
        if force_all:
            self._packages = []

        if include_certificates:
            # A bundle for package signers certificates
            if force_all:
                signer_certificates = SSLCABundle()
            else:
                signer_certificates = self.get_certificates()

        old_entries = {}

        for package in self.packages():
            # keep only entries which are older than index. Other should be recalculated.
            localwaptfile = os.path.abspath(os.path.join(self.localpath, os.path.basename(sanitize_filename(package.filename))))
            if os.path.isfile(localwaptfile):
                if fileisoutcdate(localwaptfile) <= self._packages_date:
                    old_entries[os.path.basename(package.filename)] = package
                else:
                    logger.info("Don't keep old entry for %s, wapt package is newer than index..." % package.asrequirement())
            else:
                logger.info('Stripping entry without matching file : %s' % localwaptfile)

        if not os.path.isdir(self.localpath):
            raise Exception('%s is not a directory' % (self.localpath))
        waptlist = glob.glob(os.path.abspath(os.path.join(self.localpath, '*.wapt')))
        packages_lines = []
        kept = []
        processed = []
        errors = []
        if self._packages is None:
            self._packages = []
        else:
            del(self._packages[:])
        self._index.clear()
        self._index_by_uuid.clear()
        # we will store the max date of signature of packages to put it on Packages index
        max_package_signature_date = None

        for fname in waptlist:
            try:
                package_filename = os.path.basename(fname)
                if force_all or not package_filename in old_entries or canonical_filenames:
                    logger.info("  Processing new %s" % fname)
                    entry = PackageEntry()
                    entry.load_control_from_wapt(fname, calc_md5=(force_all or canonical_filenames or (not package_filename in old_entries)), keep_control_lines = True)
                    if self.cabundle is not None:
                        try:
                            entry.check_control_signature(self.cabundle)
                        except (EWaptNotSigned, SSLVerifyException) as e:
                            logger.info('Package %s discarded because: %s' % (package_filename, e))
                            continue
                    if max_package_signature_date is None or entry.signature_date > max_package_signature_date:
                        max_package_signature_date = entry.signature_date
                    processed.append(fname)
                    if canonical_filenames:
                        self._ensure_canonical_package_filename(entry,True)

                    if include_certificates:
                        # looks for the signer certificate and add it to Packages if not already
                        certs = entry.package_certificates()
                        if certs:
                            signer_certificates.add_certificates(certs)

                    if extract_icons:
                        self._extract_icon(entry)

                        # delete icon if still has the old name (PKGNAME.png)
                        icons_path = os.path.abspath(os.path.join(self.localpath, 'icons'))
                        if os.path.isdir(icons_path):
                            icon_fn = os.path.join(icons_path, "%s.png" % entry.package)
                            if (os.path.exists(icon_fn)):
                                os.remove(icon_fn)
                                logger.info('Deleted icon %s' % (icon_fn))

                else:
                    logger.debug("  Keeping %s" % package_filename)
                    kept.append(fname)
                    entry = old_entries[package_filename]

                if not entry.md5sum:
                    entry.md5sum = entry._calc_md5sum()
                if not entry.size:
                    entry.size = os.path.getsize(entry.localpath)

                if include_host_packages or entry.section != 'host':
                    # put control data exactly as in package if available
                    if hasattr(entry,'_control_lines') and entry._control_lines is not None:
                        # append non control
                        packages_lines.extend(entry._control_lines)
                        # perhaps we should calc always the filename, md5sum and size even if we already know them
                        for att in entry.repo_attributes:
                            if getattr(entry, att):
                                packages_lines.append("%-18s: %s" % (att, getattr(entry, att)))
                    else:
                        packages_lines.append(entry.ascontrol(with_repo_attributes=True))
                    # add a blank line between each package control
                    packages_lines.append('')

                self._add_package(entry)

            except Exception as e:
                logger.critical("package %s: %s" % (fname, ensure_unicode(e)))
                errors.append(fname)

        if include_crls:
            try:
                logger.info("Check / update CRL for embedded certificates")
                signer_certificates.update_crl(force=force_all, proxies=proxies)
            except Exception as e:
                logger.critical('Error when updating CRL for signers certificates : %s' % e)

        logger.info("Building new %s" % packages_fname)
        tmp_packages_fname = packages_fname+'.%s' % datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        try:
            with CustomZipFile(tmp_packages_fname, "w", compression=zipfile.ZIP_DEFLATED) as myzipfile:
                packages_date_utc = None

                # first use max signature date if we have already packages in index and we have scanned it.
                if max_package_signature_date:
                    packages_date_utc = isodate2datetime(max_package_signature_date)

                if os.path.isfile(packages_fname):
                    with CustomZipFile(packages_fname, "r", compression=zipfile.ZIP_DEFLATED) as oldzipfile:
                        current_packages_date_utc = datetime.datetime(* oldzipfile.getinfo('Packages').date_time)
                        if packages_date_utc is None or current_packages_date_utc > packages_date_utc:
                            packages_date_utc = current_packages_date_utc

                if packages_date_utc is None:
                	# we use the current datetime
                    packages_date_utc = datetime.datetime.utcnow()

                logger.debug('Packages UTC date: %s' % packages_date_utc)
                zi = zipfile.ZipInfo("Packages", date_time=packages_date_utc.timetuple())
                zi.compress_type = zipfile.ZIP_DEFLATED
                myzipfile.writestr(zi, '\n'.join(packages_lines).encode('utf8'))

                if include_certificates:
                    # Add list of signers certificates
                    for crt in signer_certificates.certificates():
                        zi = zipfile.ZipInfo("ssl/%s.crt" % crt.fingerprint, date_time=crt.not_before.timetuple())
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        myzipfile.writestr(zi, crt.as_pem())

                if include_crls:
                    for crl in signer_certificates.crls:
                        aki = crl.authority_key_identifier
                        zi = zipfile.ZipInfo("crl/%s.crl" % codecs.encode(aki,'hex').decode('ascii'), date_time=crl.last_update.timetuple())
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        myzipfile.writestr(zi, crl.as_der())

            # rewrite Package zip file only if has actually changed.
            if os.path.isfile(packages_fname):
                with open(packages_fname,'rb') as old_packages, open(tmp_packages_fname,'rb') as new_packages:
                    old_data = old_packages.read()
                    new_data = new_packages.read()
                # compare actual content
                if old_data != new_data:
                    # we discard old file and rename new one to Packages
                    logger.info("Writing new %s" % packages_fname)
                    logger.info("Writing new %s" % tmp_packages_fname)
                    os.unlink(packages_fname)
                    shutil.move(tmp_packages_fname, packages_fname)
                else:
                    # we discard new file as it is indentical to old one
                    logger.info("Skipping new %s" % packages_fname)
                    os.unlink(tmp_packages_fname)
            else:
                logger.info("Writing initial %s" % packages_fname)
                shutil.move(tmp_packages_fname, packages_fname)


            logger.info("Finished")
        except Exception as e:
            if os.path.isfile(tmp_packages_fname):
                os.unlink(tmp_packages_fname)
            logger.critical('Unable to create new Packages file : %s' % e)
            raise e
        return {'processed': processed, 'kept': kept, 'errors': errors, 'packages_filename': packages_fname}

    def load_config(self, config=None, section=None):
        """Load waptrepo configuration from inifile section.

                Use name of repo as section name if section is not provided.
                Use 'global' if no section named section in ini file
        Args:
            config (RawConfigParser): ini configuration
            section (str)           : section where to loads parameters
                                      defaults to name of repository

        Returns:
            WaptRemoteRepo: return itself to chain calls.
        """

        if not section:
            section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            section = 'global'

        WaptBaseRepo.load_config(self, config, section)

        if config.has_option(section, 'localpath'):
            self.localpath = config.get(section, 'localpath')

        return self

    def as_dict(self):
        result = super(WaptLocalRepo, self).as_dict()
        result.update(
            {'localpath': self.localpath,
             })
        return result


class WaptRemoteRepo(WaptBaseRepo):
    """Gives access to a remote http repository, with a zipped Packages packages index

    >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
    >>> last_modified = repo.is_available()
    >>> isinstance(last_modified,str)
    True
    """

    def __init__(self, url=None, name='', verify_cert=None, http_proxy=None, timeout=None, cabundle=None, config=None, section=None):
        """Initialize a repo at url "url".

        Args:
            name (str): internal local name of this repository
            url  (str): http URL to the repository.
                 If url is None, the url is requested from DNS by a SRV query
            http_proxy (str): url of proxy like  http://proxy:port
            timeout (float): timeout in seconds for the connection to the rmeote repository
            config (RawConfigParser) : loads conf from this Parser
        """

        # additional properties
        self._default_config.update({
            'repo_url': '',
            'timeout': 5.0,
            'verify_cert': '1',  # default is to check repo https certificates
            'http_proxy': '',
        })

        # create additional properties
        self._repo_url = None
        self.http_proxy = None

        # path to directory of PEM ca files or path to a PME bundle file
        self.verify_cert = None

        # path to the client auth pem encoded X509 cert if needed
        self.client_certificate = None
        # path to the client auth pem encoded RSA private key if needed
        self.client_private_key = None
        # password callback to get private key password
        # this tales 2 str parameters to inform user or callback about target key and usage
        #    location, identity
        self.private_key_password_callback = None

        self.timeout = None

        self.limit_bandwidth = None

        # this load and empty config
        WaptBaseRepo.__init__(self, name=name, cabundle=cabundle, config=config, section=section)

        # forced URL
        if url is not None:
            if url and url[-1] == '/':
                url = url.rstrip('/')
            self._repo_url = url

        if verify_cert is not None:
            self.verify_cert = get_verify_cert(verify_cert)
        elif self._section is not None and config and config.has_option(self._section, 'verify_cert'):
            self.verify_cert = get_verify_cert(config.get(self._section, 'verify_cert'))

        if timeout is not None:
            self.timeout = timeout

        if http_proxy is not None:
            self.http_proxy = http_proxy
        #elif config.has_option(section, 'http_proxy'):
        #    self.http_proxy = http_proxy

    def get_private_key_password(self, location, identity):
        if self.private_key_password_callback is not None:
            return self.private_key_password_callback(location, identity)
        else:
            return None

    def get_requests_session(self, url=None, http_proxy=None):
        """Returns a requests session object with optional ssl client side auth and proxies

        Returns:
            requests.Session

        """
        if self.client_private_key and is_pem_key_encrypted(self.client_private_key):
            password = self.get_private_key_password(location=self.repo_url if url is None else url, identity=self.client_private_key)
        else:
            password = None
        cert = (self.client_certificate, self.client_private_key, password)
        session = get_requests_client_cert_session(url=self.repo_url if url is None else url, cert=cert, verify=self.verify_cert, proxies={'http': http_proxy, 'https': http_proxy} if http_proxy else self.proxies)
        return session

    @property
    def repo_url(self):
        return self._repo_url

    @property
    def proxies(self):
        """dict for http proxies url suitable for requests based on the http_proxy repo attribute

        Returns:
            dict: {'http':'http://proxy:port','https':'http://proxy:port'}
        """

        if self.http_proxy:
            return {'http': self.http_proxy, 'https': self.http_proxy}
        else:
            return {'http': None, 'https': None}

    @repo_url.setter
    def repo_url(self, value):
        """Set the repo_url
        invalidate local packages list cache if it differs from previous one

        """
        if value:
            value = value.rstrip('/')

        if value != self._repo_url:
            self._repo_url = value
            self.invalidate_packages_cache()

    def load_config(self, config=None, section=None):
        """Load waptrepo configuration from inifile section.

        Use name of repo as section name if section is not provided.

        Use 'global' if no section named section in ini file

        Args:
            config (RawConfigParser): ini configuration
            section (str)           : section where to loads parameters
                                      defaults to name of repository

        Returns:
            WaptRemoteRepo: return itself for chain calls.
        """
        if not section:
            section = self.name

        # creates a default parser with a default section if None provided to get defaults
        if config is None:
            config = RawConfigParser(self._default_config)
            config.add_section(section)

        if not config.has_section(section):
            section = 'global'

        WaptBaseRepo.load_config(self, config, section)

        if config.has_option(section, 'repo_url'):
            self.repo_url = config.get(section, 'repo_url')

        if config.has_option(section, 'verify_cert'):
            self.verify_cert = get_verify_cert(config.get(section, 'verify_cert'))

        if config.has_option(section, 'repo_url'):
            self.repo_url = config.get(section, 'repo_url')

        if config.has_option(section, 'http_proxy'):
            if not config.has_option(section, 'use_http_proxy_for_repo') or config.getboolean(section, 'use_http_proxy_for_repo'):
                self.http_proxy = config.get(section, 'http_proxy')

        if config.has_option(section, 'timeout'):
            self.timeout = config.getfloat(section, 'timeout')

        if config.has_option(section, 'client_certificate') and config.get(section, 'client_certificate'):
            self.client_certificate = config.get(section, 'client_certificate')

        if config.has_option(section, 'client_private_key') and config.get(section, 'client_private_key'):
            self.client_private_key = config.get(section, 'client_private_key')


        if config.has_option(section, 'limit_bandwidth'):
            self.limit_bandwidth = config.getfloat(section, 'limit_bandwidth')

        return self

    def packages_url(self, url=None):
        """return url of Packages index file

        >>> repo = WaptRemoteRepo(name='main',url='http://wapt/wapt',timeout=4)
        >>> repo.packages_url
        'http://wapt/wapt/Packages'

        hardcoded path to the Packages index.
        """
        return (self.repo_url + '/Packages') if url is None else (url + '/Packages')

    def client_auth(self):
        """Return SSL trio filenames for client side SSL auth

        Returns:
            tuple: (cert filename,key filename,key pwd)
        """
        if self.client_certificate and os.path.isfile(self.client_certificate):
            if self.client_private_key is None:
                cert = SSLCertificate(self.client_certificate)
                key = cert.matching_key_in_dirs(password_callback=self.get_private_key_password)
                self.client_private_key = key.private_key_filename
            return (self.client_certificate, self.client_private_key, self.get_private_key_password(self.repo_url, self.client_certificate))
        else:
            return None

    def is_available(self, url=None, http_proxy=None):
        """Check if repo is reachable an return creation date of Packages.

        Try to access the repo and return last modified date of repo index or None if not accessible

        Returns:
            str: Iso creation date of remote Package file as returned in http headers

        >>> repo = WaptRemoteRepo(name='main',url='https://wapt/wapt',timeout=1)
        >>> repo.is_available() <= datetime2isodate()
        True
        >>> repo = WaptRemoteRepo(name='main',url='https://badwapt/wapt',timeout=1)
        >>> repo.is_available() is None
        True
        """
        try:
            with self.get_requests_session(url, http_proxy) as session:
                logger.debug('Checking availability of %s' % (self.packages_url(url=url)))
                req = session.head(
                    self.packages_url(url=url),
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                req.raise_for_status()
                packages_last_modified = req.headers.get('last-modified')
                return httpdatetime2isodate(packages_last_modified)
        except requests.exceptions.SSLError:
            logger.error('Certificate check failed for %s and verify_cert %s' % (self.packages_url(url=url), self.verify_cert))
            raise
        except requests.RequestException as e:
            logger.info('Repo packages index %s is not available : %s' % (self.packages_url(url=url), e))

            return None

    def _load_packages_index(self):
        """Try to load index of packages as PackageEntry list from repository

        HTTP Get remote Packages zip file and parses the entries.

        The list of package entries is stored in the packages property.

        Returns
            dict: list of added or removed packages and create date {'added':list,'removed':list,'last-modified':isodatetime}
        """
        if not self.repo_url:
            raise EWaptException('Repository URL for %s is empty. Add a %s section in ini' % (self.name, self.name))

        if self._packages is None:
            self._packages = []
            self._packages_date = None

        self._index.clear()
        self._index_by_uuid.clear()
        self.discarded = []

        new_packages = []
        logger.debug('Read remote Packages zip file %s' % self.packages_url())

        (_packages_index_str, _packages_index_date) = self._get_packages_index_data()
        with CustomZipFile(io.BytesIO(_packages_index_str)) as waptzip:
            packages_lines = codecs.decode(waptzip.read(name='Packages'), 'UTF-8').splitlines()

            if self.cabundle is not None:
                # load certificates and CRLs
                signer_certificates = self.get_certificates(packages_zipfile=waptzip)
                logger.debug('Packages index from repo %s has %s embedded certificates' % (self.name, len(signer_certificates._certificates)))

        startline = 0
        endline = 0

        def add(start, end):
            if start != end:
                package = PackageEntry()
                package._load_control('\n'.join(packages_lines[start:end]))
                #logger.debug(u"%s (%s)" % (package.package,package.version))
                package.repo_url = self.repo_url
                package.repo = self.name

                if self.is_locally_allowed_package(package):
                    try:
                        if self.cabundle is not None:
                            package.check_control_signature(trusted_bundle=self.cabundle, signers_bundle=signer_certificates)
                        new_packages.append(package)

                        if package.package_uuid:
                            self._index_by_uuid[package.package_uuid] = package
                        else:
                            self._index_by_uuid[package.make_fallback_uuid()] = package

                        if package.package not in self._index or self._index[package.package] < package:
                            self._index[package.package] = package
                    except Exception as e:
                        logger.info('Discarding %s on repo "%s": %s' % (package.asrequirement(), self.name, e))
                        #logger.debug('Certificate bundle : %s' % self.cabundle)
                        self.discarded.append(package)
                else:
                    logger.info('Discarding %s on repo "%s" because of local whitelist or blacklist rules' % (package.asrequirement(), self.name))
                    self.discarded.append(package)

        for line in packages_lines:
            if line.strip() == '':
                add(startline, endline)
                endline += 1
                startline = endline
            # add ettribute to current package
            else:
                endline += 1
        # last one
        add(startline, endline)
        added = [p for p in new_packages if p not in self._packages]
        removed = [p for p in self._packages if p not in new_packages]
        self._packages = new_packages
        self._packages_date = datetime2isodate(_packages_index_date)
        return {'added': added, 'removed': removed, 'last-modified': self.packages_date(), 'discarded': self.discarded}

    def _get_packages_index_data(self):
        """Download or load local Packages index raw zipped data

        Returns:
            (str,datetime.datetime): Packages data (local or remote) and last update date
        """
        with self.get_requests_session() as session:
            packages_answer = session.get(
                self.packages_url(),
                timeout=self.timeout,
                allow_redirects=True,
            )
            packages_answer.raise_for_status()
            packages_last_modified = packages_answer.headers.get('last-modified')
            _packages_index_date = httpdatetime2datetime(packages_last_modified)
            return (packages_answer.content, _packages_index_date)

    def as_dict(self):
        """returns a dict representation of the repository configuration and parameters"""
        result = super(WaptRemoteRepo, self).as_dict()
        result.update({
            'repo_url': self._repo_url,
            'http_proxy': self.http_proxy,
            'timeout': self.timeout,
            'verify_cert': self.verify_cert,
        })
        return result

    def download_packages(self, package_requests, target_dir=None, usecache=True, printhook=None):
        r"""Download a list of packages (requests are of the form packagename (>version) )
           returns a dict of {"downloaded,"skipped","errors"}

        If package_requests is a list of PackageEntry, update localpath of entry to match downloaded file.

        Args:
            package_requests (list) : list of PackageEntry to download or list of package with optional version

        Returns:
            dict: 'packages', 'downloaded', 'skipped', 'errors'

        >>> repo = WaptRemoteRepo(url='http://wapt.tranquil.it/wapt')
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """
        if not isinstance(package_requests, (list, tuple)):
            package_requests = [package_requests]
        if not target_dir:
            target_dir = tempfile.mkdtemp()

        downloaded = []
        skipped = []
        errors = []
        packages = []
        for p in package_requests:
            if isinstance(p, str):
                mp = self.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p, 'Unavailable package %s' % (p.as_key(),)))
                    logger.critical('Unavailable package %s' % (p.as_key(),))
            elif isinstance(p, PackageEntry):
                packages.append(p)
            else:
                raise Exception('Invalid package request %s' % p)

        with self.get_requests_session() as session:
            for entry in packages:
                if entry.filename:
                    download_url = self.repo_url+'/'+entry.filename
                else:
                    # fallback
                    download_url = self.repo_url+'/'+entry.make_package_filename()
                fullpackagepath = os.path.join(target_dir, entry.make_package_filename())
                if not fullpackagepath.endswith('.wapt'):
                    raise EWaptNotAPackage('The file %s does not have a .wapt extension' % fullpackagepath)
                skip = False
                if usecache and os.path.isfile(fullpackagepath) and os.path.getsize(fullpackagepath) == entry.size:
                    # check version
                    try:
                        cached = PackageEntry()
                        cached.load_control_from_wapt(fullpackagepath)
                        if entry == cached:
                            cached.md5sum = cached._calc_md5sum()
                            if entry.md5sum == cached.md5sum:
                                entry.localpath = cached.localpath
                                skipped.append(fullpackagepath)
                                logger.info("  Use cached package file from " + fullpackagepath)
                                skip = True
                            else:
                                logger.critical("Cached file MD5 doesn't match MD5 found in packages index. Discarding cached file")
                                os.remove(fullpackagepath)
                    except Exception as e:
                        # error : reload
                        logger.debug('Cache file %s is corrupted, reloading it. Error : %s' % (fullpackagepath, e))

                if not skip:
                    logger.info("  Downloading package from %s" % download_url)
                    try:
                        fullpackagepath = wget(download_url,
                             fullpackagepath,
                             printhook=printhook,
                             connect_timeout=self.timeout,
                             resume=usecache,
                             md5=entry.md5sum,
                             requests_session=session,
                             limit_bandwidth=self.limit_bandwidth,
                             )
                        entry.localpath = fullpackagepath
                        downloaded.append(fullpackagepath)
                    except Exception as e:
                        if os.path.isfile(fullpackagepath):
                            os.remove(fullpackagepath)
                        logger.critical("Error downloading package from http repository, please update... error : %s" % e)
                        errors.append((download_url, "%s" % e))

        return {"downloaded": downloaded, "skipped": skipped, "errors": errors, "packages": packages}

    def download_icons(self, package_requests, target_dir=None, usecache=True, printhook=None):
        r"""Download a list of icons from packages (requests are of the form packagename (>version) )
        returns a dict of {"downloaded,"skipped","errors"}

        If package_requests is a list of PackageEntry, update localpath of entry to match downloaded file.

        Args:
            package_requests (list) : list of PackageEntry to download or list of package with optional version

        Returns:
            dict: 'packages', 'downloaded', 'skipped', 'errors'

        >>> repo = WaptRemoteRepo(url='http://wapt.tranquil.it/wapt')
        >>> wapt.download_packages(['tis-firefox','tis-waptdev'],printhook=nullhook)
        {'downloaded': [u'c:/wapt\\cache\\tis-firefox_37.0.2-9_all.wapt', u'c:/wapt\\cache\\tis-waptdev.wapt'], 'skipped': [], 'errors': []}
        """
        if not isinstance(package_requests, (list, tuple)):
            package_requests = [package_requests]
        if not target_dir:
            target_dir = tempfile.mkdtemp()

        if not os.path.isdir(target_dir):
            os.mkdir(target_dir)

        downloaded = []
        skipped = []
        errors = []
        packages = []

        for p in package_requests:
            if isinstance(p, str):
                mp = self.packages_matching(p)
                if mp:
                    packages.append(mp[-1])
                else:
                    errors.append((p, 'Unavailable package %s' % (p,)))
                    logger.critical('Unavailable package %s' % (p,))
            elif isinstance(p, PackageEntry):
                packages.append(p)
            else:
                raise Exception('Invalid package request %s' % p)

        with self.get_requests_session() as session:
            for entry in packages:
                if not entry.icon_sha256sum:
                    continue
                icon_file = entry.icon_sha256sum + '.png'
                target_fn = os.path.join(target_dir, icon_file)
                if os.path.isfile(target_fn):
                    skipped.append(icon_file)
                else:
                    download_url = self.repo_url + '/icons/' + icon_file
                    try:
                        wget(download_url,
                            target_fn,
                            printhook = printhook,
                            connect_timeout=self.timeout,
                            resume=usecache,
                            sha256=entry.icon_sha256sum,
                            requests_session=session,
                            limit_bandwidth=self.limit_bandwidth
                            )
                        downloaded.append(icon_file)
                    except Exception as e:
                        if os.path.isfile(icon_file):
                            os.remove(icon_file)
                        errors.append((download_url,"%s" % e))
        return {"downloaded": downloaded, "skipped": skipped, "errors": errors, "packages": packages}


def update_packages(adir, force=False, proxies=None, canonical_filenames=False):
    """Helper function to update a local packages index

    This function is used on repositories to rescan all packages and
      update the Packages index.

    >>> if os.path.isdir('c:\\wapt\\cache'):
    ...     repopath = 'c:\\wapt\\cache'
    ... else:
    ...     repopath = '/var/www/wapt'
    >>> p = PackageEntry()
    >>> p.package = 'test'
    >>> p.version = '10'
    >>> new_package_fn = os.path.join(repopath,p.make_package_filename())
    >>> if os.path.isfile(new_package_fn):
    ...     os.unlink(new_package_fn)
    >>> res = update_packages(repopath)
    >>> os.path.isfile(res['packages_filename'])
    True
    >>> r = WaptLocalRepo(localpath=repopath)
    >>> l1 = r.packages()
    >>> res = r.update_packages_index()
    >>> l2 = r.packages()
    >>> [p for p in l2 if p not in l1]
    ["test (=10)"]
    """
    repo = WaptLocalRepo(localpath=os.path.abspath(adir))
    return repo.update_packages_index(force_all=force, proxies=proxies, canonical_filenames=canonical_filenames)


def make_packages_filter_string(host_capabilities: dict) -> dict:
    """Build a string to group hosts by unique package matches.
    Returns:
        str csv of os,os_version,architectures,tags,locales,maturities
    """
    return "%s~%s~%s~%s~%s~%s" % (
            host_capabilities.get('os'),
            host_capabilities.get('os_version'),
            host_capabilities.get('architecture'),
            '|'.join(host_capabilities.get('tags',[])),
            '|'.join(ensure_list(host_capabilities.get('packages_locales',[]))),
            '|'.join(ensure_list(host_capabilities.get('packages_maturities',[])))
            )

if __name__ == '__main__':
    sys.exit(0)
