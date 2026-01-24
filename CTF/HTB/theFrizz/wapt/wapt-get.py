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
import sys

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
# there is a security bug in this module. known files are by default ['/etc/mime.types', '/etc/... even on winddows
# this allow a regular user to trigger memory overflow if he create a huge file /etc/mime.type
import mimetypes
mimetypes.knownfiles.clear()

from waptutils import __version__

from waptutils import __file__ as waptutils__file__

import getpass
import glob
import json
import logging
import urllib.parse
import traceback
import re

"""
try:
    # use embedded pyldap module from host executable (ie wapt-get.exe)
    import pyldap
except ImportError:
    # in case wapt-get.py is launched from a generic python interpreter or from IDE
    from waptlicences import pyldap
"""

from optparse import OptionParser

from waptutils import setloglevel, ensure_unicode, ensure_list, expand_args, ppdicttable
from waptutils import jsondump,update_ini_from_json_config

from waptpackage import PackageEntry
from waptpackage import update_packages

from waptcrypto import EWaptCryptoException, SSLCertificate, default_pwd_callback
from waptpackage import EWaptException

# be sure to load properly the openssl DLLs before cryptography
import ssl
import cryptography.hazmat.backends.openssl.backend

import common
import pprint
import textwrap

from common import Wapt

if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
    if 'PYTHONPATH' in os.environ:
        del os.environ['PYTHONPATH']
    if 'PYTHONHOME' in os.environ:
        del os.environ['PYTHONHOME']


if not sys.platform == 'win32':
    import setproctitle
    setproctitle.setproctitle('wapt-get')

import setuphelpers

try:
    from waptservice.enterprise import start_waptexit
except ImportError:
    start_waptexit = None

if sys.platform == 'win32':
    from waptwua.client import WaptWUA

waptguihelper = None

v = (sys.version_info.major, sys.version_info.minor)
if v[0] != 3:
    raise Exception('wapt-get supports only Python 3, not %d.%d' % v)


usage = """\
%prog -c configfile action

WAPT install system.

action is either :
  install <package> : install one or several packages by name, directory or wapt file
  update            : update package database
  upgrade           : upgrade installed packages, install host package if not installed.
  remove <package>  : remove installed packages

  download <package>: force download one or several packages
  show <package>    : show attributes of one or more packages

  forget <package>  : removes the installation status of <package> from local Wapt database.

  list [keywords]   : list installed packages containing keywords
  list-upgrade      : list upgradable packages
  check-upgrades    : show last update/upgrade status
  download-upgrade  : download available upgradable packages
  search [keywords] : search installable packages whose description contains keywords
  clean             : remove all WAPT cached files from local drive
  upgradedb         : manually upgrade the schema used by the WAPT database. If the database file can't be found, it will be recreated.

  add-upgrade-shutdown    : add a local shutdown policy to launch upgrade
                            of packages at windows shutdown (via waptexit.exe)
  remove-upgrade-shutdown : remove shutdown policy

  restart-waptservice : restart waptservice

  register [description] : Add the computer to the WAPT server database,
                                     change the description of the computer.
  inventory         : get json encoded list of host data, installed packages and softwares as supplied to server with register
  update-status     : Send packages and softwares status to the WAPT server,

  setlocalpassword  : Set the local admin password for waptservice access to
                      packages install/remove (for standalone usage)

  reset-uuid [new-uuid]  : reset host's UUID to the uuid provided by the BIOS or a specific optional <new-uuid>
  generate-uuid          : regenerate a random host's UUID, stored in wapt-get.ini.

  get-server-certificate : get the public key from waptserver and save it to <waptbasedir>\\ssl\\server
  enable-check-certificate : get the public key from waptserver,save it to <waptbasedir>\\ssl\\server and enable verify in config file.

  add-config-from-url <filelink> <sha256hashfile> : add a configuration file from url
  add-config-from-file
  add-config-from-base64
  remove-config  <config-name> : remove a json synamic config by its base name.
  list-config
  list-available-config

 For user session setup
  session-setup [packages,ALL] : setup local user environment for specific or all installed packages

 For packages development (Wapt default configuration is taken from user's waptconsole.ini if it exists)
  list-registry [keywords]  : list installed softwares from system registry
  installed-softwares [keywords]  : same behaviour than list-registry
  sources <package>         : checkout or update sources of a package from SVN repository (if attribute Sources was supplied in control file)
  make-template <installer-path> [<packagename> [<source directoryname>]] : initializes a package template with an installer (exe or msi)
  make-host-template <machinename> [[<package>,<package>,...] [directory]] :
                                initializes a package meta template with packages.
                                If no package name is given, use FQDN
  make-group-template <groupname> [[<package>,<package>,...] [directory]] :
                                initializes a meta package template with supplied dependencies.

  build-package <directory> : creates a WAPT package from supplied directory
  sign-package <directory or package>  : add a signature of the manifest using a private SSL key
  build-upload <directory> : creates a WAPT package from supplied directory, sign it and upload it
  duplicate <directory or package> <new-package-name> [<new-version> [<target directory>]] : duplicate an existing package,
                                            changing its name (can be used for duplication of host packages...)
  edit <package> [p1,p2,..]: download and unzip a package. Open in Explorer the target directory. Appends dependencies p1, p2 ...
  edit-host <host fqdn> [p1,p2,..]: download an unzip a host package. Open in Explorer the target directory. Appends dependencies p1, p2 ...

  update-package-sources <directory> : source <directory>/setup.py module and launch the update_package() hook to update binaries and other informations automatically.

 For repository management
  upload-package  <filenames> : upload package to repository (using winscp for example.)
  scan-packages <directory> : rebuild a "Packages" file for http package repository

 For windows updates WaptWUA management (Enterprise only)
   waptwua-scan : scan status of windows against current rules and send result to server
   waptwua-download : scan status of windows against current rules, download missing kb and send result to
   waptwua-install : install pending updates

 For (Enterprise only)
   propose-upgrade : Launch an upgrade proposal by launching waptexit in open sessions

 For initial setup
   create-keycert  : create a RSA key pair and X509 certificate with /CommonName, /CodeSigning and /CA params. Use /PrivateKeyPassword for key encrypt. Store crt and pem into /BaseDir
   build-waptagent : compile a waptagent.exe and waptupgrade package using /ConfigFilename parameter to ini file. By default, use waptconsole configuration.
   stuff-waptsetup ! append a json wapt config file to waptsetup.exe for initial setup.


"""

with open(os.path.join(os.path.dirname(os.path.abspath(waptutils__file__)), 'version-full'), 'r') as f:
    full_version = f.read()

parser = OptionParser(usage=usage, version='wapt-get.py: ' +
    __version__+'\ncommon.py: '+common.__version__+
    '\nsetuphelpers.py: '+setuphelpers.__version__+
    '\nfull-version: '+full_version+
    '\nOpenSSL: %s' % cryptography.hazmat.backends.openssl.backend.openssl_version_text())

default_waptservice_ini = os.path.join(os.path.dirname(os.path.abspath(waptutils__file__)),'wapt-get.ini')
default_waptconsole_ini = setuphelpers.makepath(setuphelpers.user_local_appdata(), 'waptconsole', 'waptconsole.ini')

parser.add_option("-c", "--config", dest="config", default=None, help="Config file full path (default: %default)")
parser.add_option("-l", "--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug', 'warning', 'info', 'error', 'critical'], metavar='LOGLEVEL', help="Loglevel (default: warning)")
parser.add_option("-D", "--direct",    dest="direct",    default=False, action='store_true', help="Don't use http service for update/upgrade (default: %default)")
parser.add_option("-S", "--service",    dest="service",    default=False, action='store_true', help="User http service for update/upgrade/install/remove (default: %default)")
parser.add_option("-u", "--update-packages",    dest="update_packages",  default=False, action='store_true', help="Update Packages first then action (default: %default)")
parser.add_option("-f", "--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
parser.add_option("-p", "--params", dest="params", default='{}', help="Setup params as a JSon Object (example : {'licence':'AZE-567-34','company':'TIS'}} (default: %default)")
parser.add_option("-r", "--repository", dest="wapt_url", default='', help="URL of main wapt repository (override url from ini file, example http://wapt/wapt) (default: %default)")
parser.add_option("-y", "--hide", dest="hide_console", default=False, action='store_true', help="Hide the console (default: %default)")
parser.add_option("-F", "--use-host-caps", type='int', dest="filter_on_host_cap", default=None, help="Filter the packages based on the current host capabilities (0/1) (default: %default)")
parser.add_option("-i", "--inc-release",    dest="increlease",    default=False, action='store_true', help="Increase release number when building package (default: %default)")
parser.add_option("-a", "--update-server-status",  type='int',    dest="update_server_status",    default=1, help="Send updated status of host (soft, packages, etc..) to server after action  (0/1)(default: %default)")
parser.add_option("--keep-signature-date", dest="keep_signature_date", default=False, action='store_true', help="Keep the current package signature date, and file changetime (default: %default)")
parser.add_option("-s", "--sections",    dest="section_filter",    default=None,  help="Add a filter section to search query (default: ALL)")
parser.add_option("-o", "--output",     dest="redirect_output", default=None,   help="Redirect the outputs to a given file (default: use redirect_stdout_to ini value)")
parser.add_option("-j", "--json",    dest="json_output",    default=False, action='store_true', help="Switch to json output for scripts purpose (default: %default)")
parser.add_option("-e", "--encoding",    dest="encoding",    default=None, help="Chararacter encoding for the output (default: no change)")
parser.add_option("-x", "--excludes",    dest="excludes",    default=None, help="Comma separated list of files or directories to exclude for build-package (default: %default)")
parser.add_option("-k", "--certificate", dest="personal_certificate_path",    default='', help="Path to the PEM X509 personal certificate to sign packages. Package are unsigned if not provided (default: %default)")
parser.add_option("-w", "--private-key-passwd", dest="private_key_passwd", default='', help="Path to the password of the private key. (default: %default)")
parser.add_option("-U", "--user", dest="user", default=None, help="Interactive user (default: no change)")
parser.add_option("-g", "--usergroups", dest="usergroups", default='[]', help="Groups of the final user as a JSon array for checking install permission (default: %default)")
parser.add_option("-t", "--maxttl", type='int',  dest="max_ttl", default=60, help="Max run time in minutes of wapt-get process before being killed by subsequent wapt-get (default: %default minutes)")
parser.add_option("-L", "--language",    dest="language",    default=setuphelpers.get_language(), help="Override language for install (example : fr) (default: %default)")
parser.add_option("-m", "--message-digest", dest="md", default=None, help="Message digest type for signatures.  (default: sha256)")
parser.add_option("-n","--newest-only", dest="newest_only", default=False, action='store_true', help="Return only the newest version of packages when searching. (default: %default)")
parser.add_option("--locales", dest="locales", default=None, help="Override packages locales filter. (default: None)")
parser.add_option("--maturity", dest="maturity", default=None, help="Set/change package maturity when building package.  (default: None)")
parser.add_option("--pin-server-cert", dest="set_verify_cert", default=None, action='store_true', help="When registering, pin the server certificate. (default: %default)")
parser.add_option("--wapt-server-url", dest="set_waptserver_url", default=None, help="When registering, set wapt-get.ini wapt_server setting. (default: %default)")
parser.add_option("--wapt-repo-url", dest="set_waptrepo_url", default=None, help="When registering, set wapt-get.ini repo_url setting. (default: %default)")
parser.add_option("--wapt-server-user", dest="wapt_server_user", default=None, help="User to upload packages to waptserver. (default: %default)")
parser.add_option("--wapt-server-passwd", dest="wapt_server_passwd", default=None, help="Password to upload packages to waptserver. (default: %default)")
parser.add_option("--log-to-windows-events", dest="log_to_windows_events",    default=False, action='store_true', help="Log steps to the Windows event log (default: %default)")
parser.add_option("--use-gui", dest="use_gui_helper", default=False, action='store_true', help="Force use of GUI Helper even if not in dev mode. (default: %default)")
parser.add_option("--no-ide", dest="no_ide", default=False, action='store_true', help="Don't launch ide when editing a package. (default: %default)")
parser.add_option("--not-interactive", dest="not_interactive", default=False, action='store_true', help="Disable dialog which asks user credentials (for batch mode). (default: %default)")
parser.add_option("--waptbasedir", dest="wapt_base_dir", default=None, help="Force a different wapt-base-dir then default dir of waptutils.py. (default: %default)")
parser.add_option("--devmode", dest="devmode", default=False, action='store_true', help="Enable devmode. dbpath is set to :memory: and cert/key are in userappdata. (default: %default)")
parser.add_option("--json-config-name", dest="json_config_name", default="default", help="The name of the json file given with the action json-config-from-file/base64/url.")
parser.add_option("--json-config-priority", dest="json_config_priority", default=None, help="The priority of the json file given with the action json-config-from-file/base64/url.")
parser.add_option("--only-priorities", "--only_priorities", dest="only_priorities", default=None, help="Upgrade packages with specific priorities (default: %default)")
parser.add_option("--only-if-not-process-running", "--only_if_not_process_running", dest="only_if_not_process_running", default=False, action='store_true', help="Upgrade packages only if impacted processes are not running (default: %default)")

(options, args) = parser.parse_args()

encoding = options.encoding

logger = logging.getLogger()
loglevel = options.loglevel

if len(logger.handlers) < 1:
    hdlr = logging.StreamHandler(sys.stderr)
    hdlr.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(hdlr)

if loglevel:
    setloglevel(logger, loglevel)
else:
    setloglevel(logger, 'warning')

logger.debug('Default encoding : %s ' % sys.getdefaultencoding())
# logger.debug('Setting encoding for stdout and stderr to %s ' % encoding)

private_key_password_cache = None


if options.use_gui_helper:
    old_argv = sys.argv
    if (sys.platform == 'win32' and (not setuphelpers.running_as_system())) or sys.platform != 'win32':
        try:
            import waptguihelper
        except (ImportError, SystemError):
            waptguihelper = None
    assert sys.argv == old_argv

class JsonOutput(object):
    """file like to print output to json"""

    def __init__(self, console, outputlist, logger):
        self.console = console
        self.output = outputlist
        self.logger = logger

    def write(self, txt):
        txt = ensure_unicode(txt)
        if txt != '\n':
            logger.info(txt)
            self.output.append(txt)

    def __getattr__(self, name):
        if hasattr(self.console, '__getattr__'):
            return self.console.__getattr__(name)
        else:
            return self.console.__getattribute__(name)


def guess_waptserver_url(host):
    result = host.lower()
    if not result.startswith('http://') and not result.startswith('https://'):
        result = 'https://%s' % result
    return result


def guess_waptrepo_url(host):
    result = host.lower()
    if not result.startswith('http://') and not result.startswith('https://'):
        result = 'https://%s' % result

    url = urllib.parse.urlparse(result)
    if not url.path:
        result = result+'/wapt'
    return result


def guess_package_root_dir(fn):
    """return the root dir of package development dir given
            control fn,
            setup fn or
            package directory
    """
    if os.path.isdir(os.path.expanduser(fn)):
        if os.path.isfile(os.path.expanduser(os.path.join(fn, 'WAPT', 'control'))):
            return fn
        elif os.path.isfile(os.path.expanduser(os.path.join(fn, 'control'))):
            return os.path.abspath(os.path.join(fn, '..'))
        else:
            return fn
    elif os.path.isfile(os.path.expanduser(fn)):
        if os.path.basename(fn) == 'control':
            return os.path.abspath(os.path.join(os.path.dirname(fn), '..'))
        elif os.path.basename(fn) == 'setup.py':
            return os.path.abspath(os.path.dirname(fn))
        else:
            return fn
    else:
        return fn


def ask_user_password(title=''):
    global options
    user = options.wapt_server_user
    password = options.wapt_server_passwd
    if not options.not_interactive:
        if (options.use_gui_helper or sys.stdin is not sys.__stdin__) and waptguihelper:
            res = waptguihelper.login_password_dialog('Credentials for wapt server', ensure_unicode(title or ''), ensure_unicode(user or 'admin'), ensure_unicode(password or ''))
            if res:
                user = res['user']
                password = res['password']
        else:
            if not user:
                if title:
                    user = input('Please get login for %s:' % title)
                else:
                    user = input('Please get login:')
            if user == '':
                user = 'admin'
            if password is None or password == '':
                password = getpass.getpass('Password:')
    if user is None:
        raise Exception('No username given')
    if password is None:
        raise Exception('No password given')
    return (ensure_unicode(user).encode('utf8'), ensure_unicode(password).encode('utf8'))



def do_update(mywapt, options):
    # abort if there is already a running install in progress
    running_install = mywapt.check_install_running(max_ttl=options.max_ttl)
    if running_install:
        raise Exception('Running wapt processes (%s) in progress, please wait...' % (running_install,))
    print("Update package list from %s" % ', ' .join([r.repo_url for r in mywapt.repositories]))
    result = mywapt.update(force=options.force)
    if not options.json_output:
        print("Total packages : %i" % result['count'])
        print("Added packages : \n%s" % "\n".join(["  %s" % (p,) for p in result['added']]))
        print("Removed packages : \n%s" % "\n".join(["  %s" % (p,) for p in result['removed']]))
        print("Discarded packages count : %s" % result['discarded_count'])
        print("Pending operations : \n%s" % "\n".join(["  %s: %s" % (k, ' '.join(result['upgrades'][k])) for k in result['upgrades']]))
        print("Repositories URL : \n%s" % "\n".join(["  %s" % (p,) for p in result['repos']]))
    return result


def do_enable_check_certificate(mywapt, options):
    """

    Returns:
        tuple (verify_cert,sha1)
    """
    mywapt.waptserver.verify_cert = False
    if mywapt.waptserver and mywapt.waptserver_available():
        cert_filename = mywapt.waptserver.save_server_certificate(os.path.join(mywapt.wapt_base_dir, 'ssl', 'server'), overwrite=options.force)
        print('Server certificate : %s' % cert_filename)
        if cert_filename:
            cert = SSLCertificate(cert_filename)
            sha1_fingerprint = cert.digest('sha1')

            server_host_name = urllib.parse.urlparse(mywapt.waptserver.server_url).netloc
            if not server_host_name.lower() in cert.subject_alt_names:
                logger.warning('Server hostname (%s) is not in certificate subjectAltNames extension %s' % (server_host_name, cert.subject_alt_names))

            # check if certificate match repo_url defined in global too
            if mywapt.config.has_option('global', 'repo_url'):
                repo_host_name = urllib.parse.urlparse(mywapt.config.get('global', 'repo_url')).netloc
                if not repo_host_name.lower() in cert.subject_alt_names:
                    logger.warning('Server hostname (%s) is not in certificate subjectAltNames extension %s' % (repo_host_name, cert.subject_alt_names))

            print('Certificate CN: %s' % cert.cn)
            print('Pining certificate %s' % cert_filename)

            mywapt.config.set('global', 'verify_cert', cert_filename)
            mywapt.write_config()
            if not options.json_output:
                print('wapt config file updated')
                print('Please check sha1 fingerprint of server certificate : %s' % sha1_fingerprint)
                print('Don''t forget to restart waptservice to take the new settings in account !')
        else:
            print('No server certificate retrieved')
    else:
        print('Server not available')
    return (cert_filename, sha1_fingerprint)

def main():
    jsonresult = {'output': []}
    if options.json_output:
        # redirect output to json list
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stderr = sys.stdout = JsonOutput(sys.stdout, jsonresult['output'], logger)

    try:
        available_actions = ['install', 'download', 'remove', 'update', 'upgrade', 'session-setup',
            'edit', 'edit-host', 'search', 'sources', 'show', 'show-params', 'showlog', 'show-log',
            'list-registry', 'list-upgrade', 'list', 'uninstall', 'installed-softwares', 'audit',
            'check-upgrades', 'download-upgrade', 'forget', 'scan-packages',
            'update-package-sources', 'make-template', 'make-host-template', 'make-group-template',
            'build-package', 'build-upload', 'sign-package', 'upload-package', 'clean', 'cleanup',
            'register', 'unregister', 'setlocalpassword', 'generate-uuid', 'duplicate', 'reset-uuid',
            'inventory', 'add-upgrade-shutdown', 'remove-upgrade-shutdown', 'waptwua-scan', 'waptwua-install',
            'waptwua-download', 'waptwua-status', 'propose-upgrade', 'get-server-certificate',
            'enable-check-certificate', 'update-status', 'add-config-from-file', 'add-config-from-base64',
            'add-config-from-url', 'restart-waptservice', 'list-config','remove-config']

        if len(args) == 0 or not args[0] in available_actions:
            if len(args) == 0:
                print("ERROR : You must provide one action to perform")
            else:
                print('ERROR : Unknown action %s' % args[0])
            parser.print_usage()
            sys.exit(2)

        action = args[0]
        development_actions = ['sources', 'make-template',
                               'make-host-template', 'make-group-template', 'build-package',
                               'sign-package', 'build-upload', 'duplicate', 'edit', 'edit-host',
                               'upload-package', 'update-package-sources']
        if not options.config:
            if action in development_actions and os.path.isfile(os.path.expanduser(default_waptconsole_ini)):
                config_file = default_waptconsole_ini
                logger.info('/!\ Development mode, using Waptconsole configuration %s ' % config_file)
            else:
                config_file = default_waptservice_ini
                logger.info('Using local waptservice configuration %s ' % config_file)
        else:
            if os.path.isfile(os.path.expanduser(options.config)):
                config_file = options.config
            else:
                other_waptconsole_ini = setuphelpers.makepath(setuphelpers.user_local_appdata(), 'waptconsole', '%s.ini' % options.config)
                if os.path.isfile(os.path.expanduser(other_waptconsole_ini)):
                    config_file = other_waptconsole_ini
                else:
                    config_file = options.config

        # Config file
        if not os.path.isfile(os.path.expanduser(config_file)):
            if config_file  == default_waptservice_ini:
                with open(config_file,'w') as f:
                    f.write('[global]')
            else:
                logger.error(("Error : could not find file : %s"
                              ", please check the path") % config_file)
                sys.exit(1)

        logger.debug('Config file: %s' % config_file)
        logger.info('Using openssl %s' % cryptography.hazmat.backends.openssl.backend.openssl_version_text())

        if options.wapt_base_dir is None:
            options.wapt_base_dir = setuphelpers.inifile_readstring(config_file,'global','wapt_base_dir',None)

        mywapt = Wapt(config_filename=config_file,wapt_base_dir=options.wapt_base_dir)
        if options.redirect_output or mywapt.redirect_stdout_to:
            if options.redirect_output:
                mywapt.redirect_stdout_to = options.redirect_output
            try:
                new_stdout = open(mywapt.redirect_stdout_to, 'w+')
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                sys.stdout = new_stdout
                sys.stderr = sys.stdout
            except Exception as e:
                logger.error('Couldn\'t redirect stdout to file {}: {}'.format(mywapt.redirect_stdout_to, e))
                mywapt.redirect_stdout_to = None

        if options.json_output:
            jsonresult['config_filename'] = config_file
        else:
            print('Using config file: %s' % config_file)

        if options.wapt_url:
            if options.json_output:
                jsonresult['repo_url'] = options.wapt_url
            else:
                print('Using repo_url: %s' % options.wapt_url)
            mywapt.config.set('global', 'repo_url', options.wapt_url)

        if options.md is not None:
            mywapt.sign_digests = ensure_list(options.md)

        if options.maturity:
            if options.json_output:
                jsonresult['maturities'] = options.maturity
            else:
                print('Using maturities: %s' % options.maturity)
            mywapt.maturities = ensure_list(options.maturity)

        if options.locales:
            if options.json_output:
                jsonresult['locales'] = options.locales
            else:
                print('Using locales: %s' % options.locales)
            mywapt.locales = ensure_list(options.locales)

        global loglevel
        if not loglevel and mywapt.config.has_option('global', 'loglevel'):
            loglevel = mywapt.config.get('global', 'loglevel')
            setloglevel(logger, loglevel)

        mywapt.options = options

        if options.log_to_windows_events:
            try:
                from logging.handlers import NTEventLogHandler
                hdlr = NTEventLogHandler('wapt-get')
                logger.addHandler(hdlr)
            except Exception as e:
                logger.critical('Unable to initialize windows log Event handler: %s' % e)

        if options.language:
            mywapt.language = options.language

        if options.usergroups:
            mywapt.usergroups = json.loads(options.usergroups.replace("'", '"'))
            logger.info('User Groups:%s' % (mywapt.usergroups,))

        if options.user:
            mywapt.user = options.user
            logger.info('Interactive user :%s' % (mywapt.user,))

        # key password management
        def get_private_key_passwd(*args):
            """Password callback for opening private key in supplied password file"""
            global options
            global private_key_password_cache
            if options.private_key_passwd and os.path.isfile(os.path.expanduser(options.private_key_passwd)):
                with open(options.private_key_passwd, 'r') as f:
                    private_key_password_cache = f.read().splitlines()[0].strip()
            else:
                if private_key_password_cache is None:
                    if (options.use_gui_helper or sys.stdin is not sys.__stdin__) and waptguihelper:
                        res = waptguihelper.key_password_dialog('Password for private key', ensure_unicode(mywapt.personal_certificate_path), ensure_unicode(private_key_password_cache or ''))
                        if res:
                            private_key_password_cache = res['keypassword']
                        else:
                            private_key_password_cache = None
                    else:
                        private_key_password_cache = default_pwd_callback(*args)
            return private_key_password_cache

        # development mode, using a memory DB.
        if options.devmode or action in development_actions:
            if action in development_actions or not os.path.isfile(os.path.expanduser(mywapt.dbpath)):
                mywapt.dbpath = r':memory:'
            mywapt.reload_config_if_updated()

            if options.personal_certificate_path:
                mywapt.personal_certificate_path = options.personal_certificate_path

            # interactive user password with waptguihelper
            if mywapt.waptserver:
                mywapt.waptserver.ask_user_password_hook = ask_user_password

            mywapt.private_key_password_callback = get_private_key_passwd

            mywapt.use_hostpackages = False
            if options.filter_on_host_cap is not None:
                mywapt.filter_on_host_cap = bool(options.filter_on_host_cap)
            else:
                mywapt.filter_on_host_cap = action in ('install', 'download', 'remove', 'uninstall', 'update', 'upgrade', 'session-setup')

            mywapt.private_dir = os.path.join(setuphelpers.user_appdata() if os.name=='nt' else setuphelpers.application_data(), 'wapt', 'private')
            logger.info('Updating in-memory packages index from repositories...')
            logger.info('Configuration file : %s' % config_file)
            logger.info('  waptserver     : %s' % mywapt.waptserver)
            logger.info('  repositories   : %s' % mywapt.repositories)
            for r in mywapt.repositories:
                r.cabundle = None

            # no need to have current repositories content for other actions than these ones
            if action in ('download', 'search', 'sources', 'show','duplicate'):
                mywapt._update_repos_list()
        else:
            mywapt.reload_config_if_updated()
            if options.personal_certificate_path:
                mywapt.personal_certificate_path = options.personal_certificate_path

            # interactive user password with waptguihelper
            if mywapt.waptserver:
                mywapt.waptserver.ask_user_password_hook = ask_user_password

            mywapt.private_key_password_callback = get_private_key_passwd

            if options.filter_on_host_cap is not None:
                mywapt.filter_on_host_cap = bool(options.filter_on_host_cap)
            else:
                mywapt.filter_on_host_cap = True
            # no need to have current repositories content for other actions than these ones
            if not mywapt.filter_on_host_cap and action in ('edit', 'edit-host', 'download', 'search', 'sources', 'show','duplicate'):
                mywapt.dbpath=':memory:'
                mywapt._update_repos_list()

        logger.info('WAPT base directory : %s' % mywapt.wapt_base_dir)
        logger.info('Package cache dir : %s' % mywapt.packages_cache_dir)
        logger.info('WAPT DB Structure version: %s' % mywapt.waptdb.db_version)

        try:
            params_dict = {}
            try:
                params_dict = json.loads(options.params.replace("'", '"'))
            except:
                raise Exception(
                    'Installation Parameters must be in json format')

            # cleanup environement, remove stalled wapt-get, update install_status
            if action in ('install', 'download', 'remove', 'uninstall', 'update', 'upgrade'):
                running_install = mywapt.check_install_running(max_ttl=options.max_ttl)
            else:
                running_install = []

            if action == 'install':
                result = {'install': []}
                if len(args) >= 2:
                    if os.path.isdir(os.path.expanduser(os.path.abspath(args[1]))) or os.path.isfile(os.path.expanduser(os.path.abspath(args[1]))) or '*' in args[1]:
                        all_args = expand_args(args[1:])
                        print("Installing WAPT files %s" % ", ".join(all_args))
                        # abort if there is already a running install in progress
                        if running_install:
                            raise Exception('Running wapt progresses (%s), please wait...' % (running_install,))
                        for fn in all_args:
                            fn = guess_package_root_dir(os.path.abspath(fn))
                            res = mywapt.install_wapt(fn, params_dict=params_dict, force=options.force)
                            result['install'].append((fn, res))
                    else:
                        print("%sing WAPT packages %s" % (action, ','.join(args[1:])))
                        if options.update_packages:
                            do_update(mywapt, options)

                        if running_install and action == 'install':
                            raise Exception('Running wapt processes (%s) in progress, please wait...' % (running_install,))

                        result = mywapt.install(
                            args[1:],
                            force=options.force,
                            params_dict=params_dict,
                            download_only=(action == 'download'),
                            usecache=not(action == 'download' and options.force),
                            only_priorities=ensure_list(options.only_priorities,allow_none=True),
                            only_if_not_process_running = options.only_if_not_process_running
                            )

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("\nResults :")
                    for k in ('install', 'additional', 'upgrade', 'skipped', 'errors'):
                        if result.get(k, []):
                            print("\n === %s packages ===\n%s" % (k, '\n'.join(["  %-30s | %s (%s)" % (ensure_unicode(s[0]), s[1].package, s[1].version) for s in result[k] if s is not None]),))
                    if result.get('unavailable', []):
                        print('Critical : ')
                        print(' === Unavailable packages ===\n%s' % '\n'.join(["  %-30s" % s[0] for s in result['unavailable']]))
                if options.update_server_status and mywapt.waptserver:
                    try:
                        mywapt.update_server_status(force=options.force)
                    except Exception as e:
                        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))

            elif action == 'download':
                if len(args) < 2:
                    print("You must provide at least one package name to download")
                    sys.exit(1)
                if options.update_packages:
                    do_update(mywapt, options)
                packages = []
                for a in args[1:]:
                    packages.extend(ensure_list(a))

                depends = mywapt.check_downloads(packages, usecache=not options.force)

                print("Downloading packages %s" % (','.join([p.asrequirement() for p in depends]),))
                result = mywapt.download_packages(depends, usecache=not options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if result['downloaded']:
                        print("\nDownloaded packages : \n%s" % "\n".join(["  %s" % (p,) for p in result['downloaded']]))
                    if result['skipped']:
                        print("Skipped packages : \n%s" % "\n".join(["  %s" % (p,) for p in result['skipped']]))
                if result['errors']:
                    logger.critical('Unable to download some files : %s' % (result['errors'],))
                    sys.exit(1)

            elif action == 'show':
                if len(args) < 2:
                    print("You must provide at least one package name to show")
                    sys.exit(1)
                result = []
                if options.update_packages:
                    do_update(mywapt, options)

                all_args = expand_args(args[1:])
                for arg in all_args:
                    if os.path.isdir(os.path.expanduser(arg)) or os.path.isfile(os.path.expanduser(arg)):
                        control = PackageEntry().load_control_from_wapt(arg)
                        result.append(control)
                    else:
                        result.extend(mywapt.waptdb.packages_matching(arg))

                if options.json_output:
                    jsonresult['result'] = result
                    for p in result:
                        try:
                            crt = p.check_control_signature(mywapt.cabundle, mywapt.cabundle)
                            print('%s OK control signature checked properly by certificate %s (fingerprint: %s )' % (p.filename, crt.cn, crt.fingerprint))
                        except (EWaptCryptoException, EWaptException) as e:
                            print('%s ERROR control signature can not be validated with certificates %s' % (p.filename, mywapt.authorized_certificates()))
                            logger.debug('%s : %s' % e)
                else:
                    if not result:
                        print('No package found for %s\nPerhaps you can update with "wapt-get --force update"' % (','.join(args[1:]),))
                    else:
                        print("Display package control data for %s\n" % (','.join(all_args),))
                        for p in result:
                            print(p.ascontrol(with_repo_attributes=True))
                            print('')
                            try:
                                logger.info('Verifying package control signature against certificates %s' % ', '.join(['"%s"' % crt.cn for crt in mywapt.authorized_certificates()]))
                                crt = p.check_control_signature(mywapt.cabundle, mywapt.cabundle)
                                print('OK Package control signature checked properly by certificate %s (fingerprint: %s )' % (crt.cn, crt.fingerprint))
                            except (EWaptCryptoException, EWaptException) as e:
                                print('WARNING: control data signature can not be validated with certificates %s' % mywapt.authorized_certificates())
                                logger.debug('%s: %s' % (p.package_uuid,e))
                            print('')

            elif action == 'show-params':
                if len(args) < 2:
                    print("You must provide at one package name to show params for")
                    sys.exit(1)
                for packagename in args[1:]:
                    params = mywapt.waptdb.params(packagename)
                    print("%s : %s" % (packagename, params))

            elif action in ['list-registry', 'installed-softwares']:
                result = setuphelpers.installed_softwares(' '.join(args[1:]))
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.name == 'nt':
                        print("%-39s%-70s%-20s%-70s" % ('UninstallKey', 'Software', 'Version', 'Uninstallstring'))
                        print('-' * 39 + '-' * 70 + '-' * 20 + '-' * 70)
                        for p in result:
                            print("%-39s%-70s%-20s%-70s" % (p['key'], p['name'], p['version'], p['uninstall_string']))
                    else:
                        print("%-70s%-20s" % ('Software', 'Version'))
                        print('-' * 70 + '-' * 20)
                        for p in result:
                            print("%-70s%-20s" % (p['name'], p['version']))

            elif action in ('showlog', 'show-log'):
                if len(args) < 2:
                    print("You must provide at least one package name")
                    sys.exit(1)
                if options.json_output:
                    jsonresult['result'] = []
                for packagename in args[1:]:
                    result = mywapt.last_install_log(packagename)
                    if options.json_output:
                        jsonresult['result'].append(result)
                    else:
                        print("Package: %s (%s) %s\n-------------------\nStatus: %s\n\n"
                              "Installation log:\n-------------------\n%s\n\n"
                              "Installation Parameters:\n-------------------\n%s\n\n"
                              "Last audit:\n-------------------\nStatus: %s\nDate: %s\n\nOutput:\n%s\n\nNext audit on: %s"
                              %
                              (result['package'], result['version'], result['maturity'],
                               result['install_status'], result['install_output'], result['install_params'],
                               result['last_audit_status'], result['last_audit_on'], result['last_audit_output'], result['next_audit_on'],
                               ))

            elif action == 'remove':
                if len(args) < 2:
                    print("You must provide at least one package name to remove")
                    sys.exit(1)
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt processes (%s) in progress, please wait...' % (running_install,))
                removed = []
                errors = []
                for packagename in expand_args(args[1:], expand_file_wildcards=False):
                    print("Removing %s ..." % (packagename,))
                    try:
                        packagename = guess_package_root_dir(packagename)
                        result = mywapt.remove(packagename,
                            force=options.force,
                            only_priorities=ensure_list(options.only_priorities,allow_none=True),
                            only_if_not_process_running = options.only_if_not_process_running)
                        errors.extend(result['errors'])
                        removed.extend(result['removed'])
                    except Exception:
                        errors.append((packagename,traceback.format_exc()))

                if options.json_output:
                    jsonresult['result'] = {'errors': errors, 'removed': removed}
                else:
                    if removed:
                        print("=== Removed packages ===\n%s" % "\n".join(["  %s" % (p,) for p in removed]))
                    else:
                        print("No package removed !")

                    if errors:
                        print("=== Error removing packages ===\n%s" % "\n".join(["  %s" % (p,) for p in errors]))

                if options.update_server_status and mywapt.waptserver:
                    try:
                        mywapt.update_server_status(force=options.force)
                    except Exception as e:
                        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))
                if errors:
                    sys.exit(3)


            elif action == 'session-setup':
                if len(args) < 2:
                    print("You must provide at least one package to be configured in user's session or ALL (in uppercase) for all currently installed packages of this system")
                    sys.exit(1)
                result = []

                if sys.platform != 'win32':
                    maxuid = 1000

                    if sys.platform.startswith('darwin'):
                        maxuid = 500

                    if os.path.isfile('/etc/login.defs'):
                        with open('/etc/login.defs', 'r') as f:
                            data = f.read()
                            if '\nUID_MIN' in data:
                                maxuid = int(data.split('\nUID_MIN')[1].split('\n')[0].strip())

                    if os.getuid() < maxuid:
                        print("Session-setup does not apply for a uid below %s" % maxuid)
                        sys.exit(0)

                if args[1] == 'ALL':
                    for package in mywapt.installed():
                        try:
                            result.append(mywapt.session_setup(package, force=options.force))
                        except Exception as e:
                            logger.critical(ensure_unicode(e))

                    if args[1] == 'ALL':
                        logger.debug('cleanup session db, removed not installed package entries')
                        mywapt.cleanup_session_setup()
                    print('%s packages configured for user %s' % (len(result), mywapt.user))
                else:
                    packages_list = expand_args(args[1:])
                    for packagename in packages_list:
                        try:
                            print("Configuring %s ..." % (packagename,))
                            packagename = guess_package_root_dir(packagename)
                            result.append(mywapt.session_setup(packagename, force=options.force))
                            print("Done")
                        except Exception as e:
                            logger.critical(ensure_unicode(e))

                if options.json_output:
                    jsonresult['result'] = result

            elif action == 'audit':
                result = []
                if len(args) < 2:
                    packages_list = mywapt.waptdb.installed_package_names()
                else:
                    packages_list = expand_args(args[1:], expand_file_wildcards=False)

                with mywapt.waptdb:
                    for packagename in packages_list:
                        try:
                            packagename = guess_package_root_dir(packagename)
                            audit_result = mywapt.audit(packagename, force=options.force)
                            result.append([packagename, audit_result])
                            print("%s -> %s\n" % (packagename, audit_result))
                        except Exception as e:
                            logger.critical('Audit %s : %s' % (packagename, ensure_unicode(e)))

                    if options.update_server_status and mywapt.waptserver:
                        try:
                            logger.info('Sending status to server')
                            mywapt.update_server_status(force=options.force)
                        except Exception as e:
                            logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))

                if options.json_output:
                    jsonresult['result'] = result

            elif action == 'uninstall':
                # launch the setup.uninstall() procedure for the given packages
                # can be used when registering in registry a custom install
                # with a python script
                if len(args) < 2:
                    print("You must provide at least one package to be uninstalled")
                    sys.exit(1)

                for packagename in expand_args(args[1:]):
                    print("Uninstalling %s ..." % (packagename,))
                    packagename = guess_package_root_dir(packagename)
                    print(mywapt.uninstall(packagename, params_dict=params_dict, force=options.force))
                    print("Uninstallation done")

            elif action == 'update':
                result = do_update(mywapt, options)

            elif action == 'upgradedb':
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt processes (%s) in progress, please wait...' % (running_install,))
                (old, new) = mywapt.waptdb.upgradedb(force=options.force)
                if old == new:
                    print("No database upgrade required, current %s, required %s" % (old, mywapt.waptdb.curr_db_version))
                else:
                    print("Old version : %s to new : %s" % (old, new))

            elif action == 'upgrade':
                if options.update_packages:
                    do_update(mywapt, options)
                # abort if there is already a running install in progress
                if running_install:
                    raise Exception('Running wapt processes (%s) in progress, please wait...' % (running_install,))
                result = mywapt.upgrade(only_priorities=ensure_list(options.only_priorities,allow_none=True), only_if_not_process_running = options.only_if_not_process_running)

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if not result['install'] and not result['additional'] and not result['upgrade'] and not result['skipped']:
                        print("Nothing to upgrade")
                    else:
                        for k in ('install', 'additional', 'upgrade', 'skipped', 'errors'):
                            if result[k]:
                                print("\n=== %s packages ===\n%s" % (k, '\n'.join(["  %-30s | %s (%s)" % (s[0], s[1].package, s[1].version) for s in result[k] if s is not None]),))
                if options.update_server_status and mywapt.waptserver:
                    try:
                        mywapt.update_server_status(force=options.force)
                    except Exception as e:
                        logger.critical('Unable to update server with current status : %s' % ensure_unicode(e))
                sys.exit(0)

            elif action == 'check-upgrades':
                if options.update_packages:
                    do_update(mywapt, options)
                result = mywapt.read_upgrade_status()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print(json.dumps(result, indent=True))

            elif action == 'list-upgrade':
                if options.update_packages:
                    do_update(mywapt, options)
                result = mywapt.list_upgrade()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if not result:
                        print("Nothing to upgrade")
                    for l in ('install', 'additional', 'upgrade', 'remove'):
                        if result[l]:
                            print("\n=== %s packages ===\n%s" % (l, '\n'.join(["  %-30s " % (p) for p in result[l]]),))

            elif action == 'download-upgrade':
                # abort if there is already a running install in progress
                if options.update_packages:
                    do_update(mywapt, options)
                result = mywapt.download_upgrades()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    for l in ('downloaded', 'skipped', 'errors'):
                        if result[l]:
                            print("\n=== %s packages ===\n%s" % (l, '\n'.join(["  %-30s " % (p) for p in result[l]]),))
                    if result['errors']:
                        logger.critical('Unable to download some files : %s' % (result['errors'],))
                        sys.exit(1)

            elif action == 'forget':
                if len(args) < 2:
                    print("You must provide the package names to forget")
                    sys.exit(1)
                result = mywapt.forget_packages(expand_args(args[1:]))
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("\n=== Packages removed from status ===\n%s" % ('\n'.join(["  %-30s " % (p) for p in result]),))

            elif action == 'scan-packages':
                if len(args) < 2:
                    print("You must provide the directory")
                    sys.exit(1)
                result = update_packages(args[1], force=options.force, proxies=mywapt.proxies)

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Packages filename : %s" % result['packages_filename'])
                    print("Processed packages :\n%s" % "\n".join(["  %s" % (p, ) for p in result['processed']]))
                    print("Skipped packages :\n%s" % "\n".join(["  %s" % (p, ) for p in result['kept']]))
                    if result['errors']:
                        logger.critical('Unable to process some files :\n%s' % "\n".join(["  %s" % (p, ) for p in result['kept']]))
                        sys.exit(1)

            elif action == 'sources':
                if len(args) < 2:
                    print("You must provide the package name")
                    sys.exit(1)
                result = mywapt.get_sources(args[1])
                os.startfile(result)
                if not options.no_ide:
                    common.wapt_sources_edit(result, mywapt.editor_for_packages)

            elif action == 'update-package-sources':
                if len(args) < 2:
                    print("You must provide the package directory")
                    sys.exit(1)
                result = []
                for package_dir in expand_args(args[1:]):
                    pe = PackageEntry(waptfile=package_dir)
                    update_package_py = os.path.abspath(os.path.join(package_dir,'update_package.py'))
                    if not os.path.isfile(os.path.expanduser(update_package_py)):
                        update_package_py = os.path.abspath(os.path.join(package_dir,'setup.py'))
                    is_updated = mywapt.call_python_code(update_package_py,'update_package', pe, force=options.force,params=params_dict,import_modules=['setupdevhelpers'])
                    if is_updated:
                        result.append(package_dir)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Packages updated :\n%s" % ' '.join(result))
                    if len(result) == 1 and not options.no_ide:
                        common.wapt_sources_edit(result[0], mywapt.editor_for_packages)

            elif action == 'make-template':
                if len(args) < 2:
                    print("You must provide the installer path or the package name")
                    sys.exit(1)

                if os.path.isfile(os.path.expanduser(args[1])) or os.path.isdir(os.path.expanduser(args[1])):
                    result = mywapt.make_package_template(*args[1:])
                else:
                    # no installer provided, only package name.
                    result = mywapt.make_package_template('', *args[1:])

                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0], result))
                    if mywapt.upload_cmd or mywapt.waptserver:
                        print("You can build and upload the WAPT package by launching\n  %s build-upload %s" % (sys.argv[0], result))
                    if not options.no_ide:
                        common.wapt_sources_edit(result, mywapt.editor_for_packages)

            elif action in ('make-host-template', 'make-group-template'):
                if action == 'make-host-template':
                    result = mywapt.make_host_template(*args[1:])
                else:
                    result = mywapt.make_group_template(*args[1:])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Template created. You can build the WAPT package by launching\n  %s build-package %s" % (sys.argv[0], result.sourcespath))
                    if mywapt.upload_cmd or mywapt.waptserver:
                        print("You can build and upload the WAPT package by launching\n  %s build-upload %s" % (sys.argv[0], result.sourcespath))
                    if not options.no_ide:
                        common.wapt_sources_edit(result.sourcespath, mywapt.editor_for_packages)

            elif action == 'duplicate':
                if len(args) < 3:
                    print("You must provide the source package and the new name")
                    sys.exit(1)
                target_directory = ''
                if len(args) >= 5:
                    target_directory = args[4]
                result = mywapt.duplicate_package(*args[1:4], target_directory = target_directory)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(os.path.expanduser(result.sourcespath)):
                        print("Package duplicated. You can build the new WAPT package by launching\n  %s build-package %s" % (sys.argv[0], result.sourcespath))
                        if not options.no_ide:
                            common.wapt_sources_edit(result.sourcespath, mywapt.editor_for_packages)
                    else:
                        print("Package duplicated. You can upload the new WAPT package to repository using the waptconsole / import package option\nFilename: %s" % (result.sourcespath,))
                        print("You can rebuild the new WAPT package by launching\n  %s build-package %s" % (sys.argv[0], result.sourcespath))

            elif action == 'edit':
                if len(args) < 2:
                    print("You must provide the package to edit")
                    sys.exit(1)
                if not os.path.exists(args[1]):
                    mywapt._update_repos_list()
                if len(args) >= 3:
                    result = mywapt.edit_package(packagerequest=args[1],
                                                 append_depends=args[2])
                else:
                    result = mywapt.edit_package(packagerequest=args[1])
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(os.path.expanduser(result.sourcespath)):
                        if not options.no_ide:
                            common.wapt_sources_edit(result.sourcespath, mywapt.editor_for_packages)
                        print("Package edited. You can build the new WAPT package by launching\n  %s -i build-package %s" % (sys.argv[0], result.sourcespath))

            elif action == 'edit-host':
                if len(args) == 1:
                    print("Using current host fqdn %s" % setuphelpers.get_hostname())
                    result = mywapt.edit_host(hostname=mywapt.host_packagename(), target_directory='')
                elif len(args) >= 3:
                    result = mywapt.edit_host(hostname=args[1],
                                              append_depends=args[2], target_directory='')
                else:
                    result = mywapt.edit_host(hostname=args[1], target_directory='')
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    if os.path.isdir(os.path.expanduser(result.sourcespath)):
                        if not options.no_ide:
                            common.wapt_sources_edit(result.sourcespath, mywapt.editor_for_packages)
                        print("Package edited. You can build the new WAPT package by launching\n  %s -i build-package %s" % (sys.argv[0], result.sourcespath))

            elif action in ('build-package', 'build-upload'):
                if len(args) < 2:
                    print("You must provide at least one source directory for package building")
                    sys.exit(1)
                if not mywapt.personal_certificate_path or not os.path.isfile(os.path.expanduser(mywapt.personal_certificate_path)):
                    print("You must provide the filepath to your personal certificate the [global]->personal_certificate_path key of configuration %s" % config_file)
                    sys.exit(1)

                packages = []
                errors = []

                all_args = expand_args(args[1:])
                print("Building packages %s packages" % len(all_args))

                certificates = mywapt.personal_certificate()
                print('Personal certificate is %s' % certificates[0].cn)
                key = mywapt.private_key()
                print('Private key is %s' % key)

                certificate = mywapt.personal_certificate()
                print('Personal certificate is %s' % certificate[0])
                key = mywapt.private_key()
                print('Private key is %s' % key)

                for source_dir in all_args:
                    try:
                        source_dir = guess_package_root_dir(source_dir)
                        package_fn = None

                        if os.path.isdir(os.path.expanduser(source_dir)):
                            print('Building  %s' % source_dir)
                            print('Signing %s with key %s and certificate %s (%s)' % (source_dir, key, certificates[0].cn, certificates[0].public_cert_filename))
                            signature = mywapt.sign_package(source_dir,
                                                            certificate=certificates,
                                                            private_key=key,
                                                            inc_package_release=options.increlease,
                                                            excludes=ensure_list(options.excludes),
                                                            set_maturity=options.maturity)
                            print("Package %s signed : signature : %s...%s" % (source_dir, signature[0:10].decode('utf8'), signature[-10:-1].decode('utf8')))
                            package_fn = mywapt.build_package(source_dir, excludes=ensure_list(options.excludes))

                            print('...done building. Package filename %s' % (package_fn,))
                            if package_fn:
                                packages.append(package_fn)
                            else:
                                logger.critical('package %s not created' % (package_fn,))

                        else:
                            logger.critical('Directory %s not found' % source_dir)
                    except Exception as e:
                        # remove potentially broken or unsigned resulting package file
                        if package_fn and os.path.isfile(os.path.expanduser(package_fn)):
                            os.unlink(package_fn)
                        errors.append(source_dir)
                        print('  ERROR building %s: %s' % (source_dir, e))

                print('%s packages successfully built' % len(packages))
                print('%s packages failed ' % len(errors))

                if errors:
                    print('List of errors :\n%s' % ('\n '.join(errors)))

                # continue with upload
                if action == 'build-upload':
                    waptfiles = packages
                    print('Building and uploading packages to %s' % mywapt.waptserver.server_url)
                    res = mywapt.upload_package(waptfiles)
                    if not res:
                        return
                    if not res['success']:
                        print('Error when uploading package : %s' % res['msg'])
                        sys.exit(1)
                    else:
                        print('Package uploaded successfully: %s' % res['msg'])

                    if mywapt.after_upload:
                        print('Run "after upload" script...')
                        # can include %(filenames)s
                        print(setuphelpers.run(mywapt.after_upload %
                                               {'filenames': ' '.join(['"%s"' % f for f in waptfiles])}))
                else:
                    print('\nYou can upload to repository with')
                    print('  %s upload-package %s ' % (
                        sys.argv[0], '%s' % (
                            ' '.join(['"%s"' % (p,) for p in packages]),
                        )
                    ))

            elif action == 'sign-package':
                if len(args) < 2:
                    print("You must provide at least one source directory or package to sign")
                    sys.exit(1)
                if not mywapt.personal_certificate_path or not os.path.isfile(os.path.expanduser(mywapt.personal_certificate_path)):
                    print("You must provide the filepath to your personal X509 PEM encoded certificate in the [global]->personal_certificate_path key of configuration %s" % config_file)
                    sys.exit(1)

                all_args = expand_args(args[1:])
                print("Signing packages %s" % ", ".join(all_args))

                certificate = mywapt.personal_certificate()
                print('Personal certificate is %s' % certificate[0])
                key = mywapt.private_key()
                print('Private key is %s' % key)

                for waptfile in all_args:
                    try:
                        waptfile = guess_package_root_dir(waptfile)
                        if os.path.isdir(os.path.expanduser(waptfile)) or os.path.isfile(os.path.expanduser(waptfile)):
                            print('Signing %s' % (waptfile,))
                            if options.maturity is not None:
                                print('Change maturity to %s' % (options.maturity,))
                            if options.increlease:
                                print('Incrementing package revision')

                            signature = mywapt.sign_package(waptfile, certificate=certificate, private_key=key,
                                                            set_maturity=options.maturity,
                                                            inc_package_release=options.increlease,
                                                            keep_signature_date=options.keep_signature_date)
                            print("   OK: Package %s signed : signature : %s...%s" % (waptfile, signature[0:10], signature[-10:-1]))
                        else:
                            logger.critical('Package %s not found' % waptfile)
                    except Exception as e:
                        print('   ERROR: %s: %s' % (waptfile, e))
                sys.exit(0)

            elif action == 'upload-package':
                if len(args) < 2:
                    print("You must provide a package to upload")
                    sys.exit(1)
                waptfiles = []
                for a in args[1:]:
                    waptfiles += glob.glob(a)
                print('Uploading packages to %s' % mywapt.waptserver.server_url)
                result = mywapt.upload_package(waptfiles)

                if not result['success']:
                    raise Exception('Error uploading packages : %s' % result['msg'])
                else:
                    print('OK : %s' % result['msg'])

                if mywapt.after_upload:
                    print('Run "after upload" script...')
                    # can include %(filenames)s
                    print(setuphelpers.run(mywapt.after_upload %
                                           {'filenames': ' '.join(['"%s"' % f for f in waptfiles])}))

            elif action == 'search':
                if options.update_packages:
                    do_update(mywapt, options)
                result = mywapt.search([ensure_unicode(w) for w in args[1:]],
                                       section_filter=options.section_filter,
                                       newest_only=options.newest_only)
                if options.json_output:
                    jsonresult['result'] = result
                elif result:
                    package_len = max([len(p['package']) for p in result])
                    version_len = max([len(p['version']) for p in result])
                    print(ppdicttable(result, (
                        ('status', 10),
                        ('package', package_len),
                        ('version', version_len),
                        ('target_os', 15),
                        ('architecture', 4),
                        ('maturity', 5),
                        ('locale', 3),
                        ('package_uuid', 36),
                        ('description', 50),
                        ('repo', 10))))
                else:
                    print('No result')

            elif action in ('clean', 'cleanup'):
                result = mywapt.cleanup(obsolete_only=not options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Removed files : \n%s" % "\n".join(["  %s" % (p,) for p in result]))

            elif action == 'register':
                reload_needed = False
                result = {}
                if options.set_waptrepo_url is not None and (
                        not mywapt.config.has_option('global', 'repo_url') or mywapt.config.get('global', 'repo_url') != guess_waptrepo_url(options.set_waptrepo_url)):
                    if mywapt.config.has_section('wapt'):
                        mywapt.config.set('wapt', 'repo_url', guess_waptrepo_url(options.set_waptserver_url))
                        result['repo_url'] = mywapt.config.get('wapt', 'repo_url')
                    else:
                        mywapt.config.set('global', 'repo_url', guess_waptrepo_url(options.set_waptrepo_url))
                        result['repo_url'] = mywapt.config.get('global', 'repo_url')
                    reload_needed = True

                if options.set_waptserver_url is not None and (
                        not mywapt.config.has_option('global', 'wapt_server') or mywapt.config.get('global', 'wapt_server') != guess_waptserver_url(options.set_waptserver_url)):
                    mywapt.config.set('global', 'wapt_server', guess_waptserver_url(options.set_waptserver_url))
                    result['wapt_server'] = mywapt.config.get('global', 'wapt_server')
                    # use server name to set repo url
                    if options.set_waptrepo_url is None and not mywapt.config.has_option('global', 'repo_url') and (not mywapt.config.has_section('wapt') or not mywapt.config.has_option('wapt', 'repo_url')):
                        if mywapt.config.has_section('wapt'):
                            mywapt.config.set('wapt', 'repo_url', guess_waptrepo_url(options.set_waptserver_url))
                            result['repo_url'] = mywapt.config.get('wapt', 'repo_url')
                        else:
                            mywapt.config.set('global', 'repo_url', guess_waptrepo_url(options.set_waptserver_url))
                            result['repo_url'] = mywapt.config.get('global', 'repo_url')
                    reload_needed = True

                # be sure newly defined waptserver is instanciated
                if reload_needed:
                    mywapt.write_config()

                if options.set_verify_cert:
                    (verify_cert, sha1_fingerprint) = do_enable_check_certificate(mywapt, options)
                    result['verify_cert'] = verify_cert
                    result['server_certificate_sha1'] = sha1_fingerprint

                    reload_needed = True

                if reload_needed:
                    mywapt.load_config(merge_config_packages=True)

                if mywapt.waptserver:
                    if mywapt.waptserver.use_kerberos and sys.platform == 'win32' and not setuphelpers.running_as_system():
                        logger.warning('Kerberos can not be enabled, "register" must be launched under system account to use kerberos machine account auth. Use --service switch or "psexec -s wapt-get register"')
                        mywapt.waptserver.use_kerberos = False

                    print("Registering host against server: %s" % mywapt.waptserver.server_url)
                    result['register'] = mywapt.register_computer(
                        description=(" ".join(args[1:])),
                        retry_with_password = options.use_gui_helper and ((sys.platform == 'win32' and (not setuphelpers.running_as_system())) or sys.platform != 'win32')
                    )
                    if not options.json_output:
                        if not result['register']['success']:
                            print("Error when registering host against server %s: %s" % (mywapt.waptserver.server_url, result['register']['msg']))
                            sys.exit(1)
                        else:
                            print("Host correctly registered against server %s." % (mywapt.waptserver.server_url,))

                    # update after register new server / repo
                    if options.update_packages:
                        result['update'] = do_update(mywapt, options)

                    if options.json_output:
                        jsonresult['result'] = result

                else:
                    print("No waptserver defined. Register unavailable")
                    sys.exit(1)

            elif action == 'unregister':
                if mywapt.waptserver:
                    print("Unregistering host from server: %s" % mywapt.waptserver.server_url)
                    result = {}
                    result['unregister'] = mywapt.unregister_computer()
                    if not options.json_output:
                        if not result['unregister']['success']:
                            print("Error when unregistering host against server %s: %s" % (mywapt.waptserver.server_url, result['unregister']['msg']))
                            sys.exit(1)
                        else:
                            print("Host correctly unregistered against server %s." % (mywapt.waptserver.server_url,))

                    if options.json_output:
                        jsonresult['result'] = result

                else:
                    print("No waptserver defined. Unregister unavailable")
                    sys.exit(1)

            elif action == 'setlocalpassword':
                if len(args) >= 2:
                    pwd = ' '.join(args[1:])
                else:
                    pwd1 = getpass.getpass('Local password: ')
                    pwd = getpass.getpass('Confirm password: ')
                    if pwd1 != pwd:
                        print('ERROR: Passwords not matching')
                        sys.exit(1)
                mywapt.set_local_password(
                    user='admin',
                    pwd=pwd)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("Local auth password set successfully")

            elif action == 'generate-uuid':
                result = mywapt.generate_host_uuid()

                if options.update_server_status and mywapt.waptserver:
                    mywapt.update_server_status(force=options.force)
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    logger.debug("Registering host info against server: %s", result)
                    print("New UUID: %s" % (mywapt.host_uuid,))

            elif action == 'reset-uuid':
                new_uuid = None
                if len(args) >= 2:
                    new_uuid = args[1]
                result = mywapt.reset_host_uuid(new_uuid=new_uuid)

                if options.update_server_status and mywapt.waptserver:
                    mywapt.update_server_status()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print("New UUID: %s" % (mywapt.host_uuid,))

            elif action == 'update-status':
                if mywapt.waptserver:
                    result = mywapt.update_server_status(force=options.force)
                    if result:
                        if options.json_output:
                            jsonresult['result'] = result
                        else:
                            logger.debug("Inventory sent to server: %s", result)
                            if result['success']:
                                print("Updated host status correctly sent to server %s. %s" % (mywapt.waptserver.server_url, result))
                            else:
                                print("Failed to store properly inventory to server %s: %s" % (mywapt.waptserver.server_url, result['msg']))

                    else:
                        print("waptserver is not available or error in inventory. Update of status not properly sent")
                        sys.exit(3)
                else:
                    print("No waptserver defined. Update of status unavailable")
                    sys.exit(3)

            elif action == 'inventory':
                result = mywapt.inventory()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print(jsondump(result, indent=True))

            elif action == 'add-upgrade-shutdown':
                result = mywapt.add_upgrade_shutdown_policy()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print(result)

            elif action == 'remove-upgrade-shutdown':
                result = mywapt.remove_upgrade_shutdown_policy()
                if options.json_output:
                    jsonresult['result'] = result
                else:
                    print(result)

            elif action == 'waptwua-scan':
                if not mywapt.is_enterprise():
                    raise Exception('waptwua is not available on this computer. Enterprise feature only')
                if not sys.platform == 'win32':
                    raise Exception('waptwua is not available on this computer. Windows feature only')
                with WaptWUA(mywapt) as wc:
                    result = wc.scan_updates_status(force=options.force)
                    print(pprint.pprint(result))

            elif action == 'waptwua-download':
                if not mywapt.is_enterprise():
                    raise Exception('waptwua is not available on this computer. Enterprise feature only')
                if not sys.platform == 'win32':
                    raise Exception('waptwua is not available on this computer. Windows feature only')
                with WaptWUA(mywapt) as wc:
                    result = wc.download_updates(force=options.force)
                    print(pprint.pprint(result))

            elif action == 'waptwua-install':
                if not mywapt.is_enterprise():
                    raise Exception('waptwua is not available on this computer. Enterprise feature only')
                if not sys.platform == 'win32':
                    raise Exception('waptwua is not available on this computer. Windows feature only')
                with WaptWUA(mywapt) as wc:
                    result = wc.install_updates(force=options.force)
                    print(pprint.pprint(result))

            elif action == 'waptwua-status':
                if not mywapt.is_enterprise():
                    raise Exception('waptwua is not available on this computer. Enterprise feature only')
                if not sys.platform == 'win32':
                    raise Exception('waptwua is not available on this computer. Windows feature only')
                wc = WaptWUA(mywapt)
                result = wc.stored_waptwua_status()
                print(pprint.pprint(result))

            elif action == 'propose-upgrade':
                if mywapt.is_enterprise() and start_waptexit:
                    print(start_waptexit(None, {}, ''))

            elif action == 'list':
                def cb(fieldname, value,width):
                    if value is None:
                        return ''
                    if value and fieldname == 'install_date':
                        return value[0:16]
                    if width<10:
                        placeholder=''
                    else:
                        placeholder='*'
                    return textwrap.shorten('%s' % value,width,placeholder=placeholder)

                result = mywapt.list(expand_args(args[1:], expand_file_wildcards=False))
                if options.json_output:
                    jsonresult['result'] = result
                elif result:
                    package_len = max([len(p['package']) for p in result])
                    version_len = max([len(p['version']) for p in result])
                    print(ppdicttable(result, (
                        ('package', package_len),
                        ('version', version_len),
                        ('install_status', 10),
                        ('install_date', 16),
                        ('description', 80),
                        ('package_uuid', 36),
                        ),
                        callback=cb))
                else:
                    print('No result')


            elif action == 'get-server-certificate':
                mywapt.waptserver.verify_cert = False
                if mywapt.waptserver and mywapt.waptserver_available():
                    result = mywapt.waptserver.save_server_certificate(os.path.join(mywapt.wapt_base_dir, 'ssl', 'server'))
                    if options.json_output:
                        jsonresult['result'] = result
                    else:
                        print('Server certificate written to %s' % result)
                else:
                    print('Server not available')

            elif action == 'enable-check-certificate':
                if mywapt.waptserver:
                    jsonresult['result'] = do_enable_check_certificate(mywapt, options)
                else:
                    print('No Wapt Server defined')

            elif action == "restart-waptservice":
                if sys.platform == 'win32':
                    if setuphelpers.service_is_running('waptservice'):
                        setuphelpers.service_stop("waptservice")
                    setuphelpers.service_start("waptservice")
                elif sys.platform.startswith('linux'):
                    setuphelpers.systemd_restart_service("waptservice")
                elif sys.platform.startswith('darwin'):
                    setuphelpers.run("launchctl kickstart -k system/it.tranquil.waptservice")

            elif action == 'list-config':
                print('\nconfig files are located in %s\n' % mywapt.configs_dir)
                for fn in glob.glob(setuphelpers.makepath(mywapt.configs_dir,'*.json')):
                    print("* %s" % os.path.basename(fn).split('.')[0])


            elif action == 'remove-config':
                if len(args) == 1:
                    needed_arg = 'Config name'
                    print('ERROR : You must provide the configuration %s' % (needed_arg))
                    sys.exit(1)
                mywapt.remove_json_config(args[1])
                update_ini_from_json_config(config_file,mywapt.configs_dir)

            elif action in ('add-config-from-file', 'add-config-from-base64', 'add-config-from-url'):
                if len(args) == 1:
                    needed_arg = 'file path'
                    if action == 'add-config-from-base64':
                        needed_arg = 'encoded in base64'
                    elif action == 'add-config-from-url':
                        needed_arg = 'download url, and sha256 hash to verify it'
                    print('ERROR : You must provide the configuration %s' % (needed_arg,))
                    sys.exit(1)

                if not os.path.isdir(os.path.expanduser(os.path.join(mywapt.wapt_base_dir, 'conf.d'))):
                    os.makedirs(os.path.join(mywapt.wapt_base_dir, 'conf.d'))

                res = [False]
                if action == 'add-config-from-file':
                    res = mywapt.install_json_config_file(args[1], config_name=options.json_config_name, priority=options.json_config_priority)
                    if res[0]:
                        print("Installed configuration file %s as %s" % (args[1], res[1]))
                elif action == 'add-config-from-base64':
                    res = mywapt.install_json_configb64(args[1], config_name=options.json_config_name, priority=options.json_config_priority)
                    if res[0]:
                        print("Decoded and installed configuration file as %s" % (res[1],))
                elif action == 'add-config-from-url':
                    hash = args[2] if len(args) > 2 else None
                    if not hash and '_' in args[1]:
                        # try to get hash from URL touvet_5ce7a163679eceb1a22115bc3104c15ff188f73432b2fcadec55f72c10cb85f9.json
                        fn = urllib.parse.urlparse(args[1]).path
                        hashes = re.findall('_([0-9,a-z]*)\.json',fn)
                        if hashes:
                            hash = hashes[0]
                    if not hash:
                        print("Please provide the expected sha256 hash of config file")
                        sys.exit(1)
                    res = mywapt.install_json_config_from_url(args[1], hash, config_name=options.json_config_name, priority=options.json_config_priority)
                    if res[0]:
                        print("Downloaded and installed configuration file as %s" % (res[1],))
                if not res[0]:
                    print('ERROR : Couldn\'t install the configuration')
                    sys.exit(1)
                update_ini_from_json_config(config_file,mywapt.configs_dir)

            else:
                print('Unknown action %s' % action)
                sys.exit(1)

        except Exception as e:
            print("FATAL ERROR : %s" % (ensure_unicode(e),))
            if logger.level == logging.DEBUG:
                raise
            sys.exit(3)

    except SystemExit as e:
        # catch exit code for json output
        if options.json_output:
            jsonresult['exit_code'] = e.code
        raise

    except Exception as e:
        # catch exceptions for json output
        if options.json_output:
            jsonresult['error'] = ensure_unicode(e)
        raise

    finally:
        if options.json_output:
            # restore stdin/stdout
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            # print final result
            print(jsondump(jsonresult, indent=True))


if __name__ == "__main__":
    logger.debug('Caller: %s' % sys.argv)
    logger.debug('Python path %s' % sys.path)
    main()
