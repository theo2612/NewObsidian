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

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

#from waptutils import __version__, setloglevel
from waptpackage import update_packages, WaptLocalRepo
#from waptserver.model import *
from waptserver.model import load_db_config, Packages
from waptutils import setloglevel
from waptserver.common import update_all_crls

import waptserver.config

from optparse import OptionParser
import logging
import subprocess

logger = logging.getLogger()

__doc__ = """\
%prog <wapt_directory>

Build a "Packages" file from all wapt file in the specified directory
"""


def update_packages_table(conf, wapt_path):
    load_db_config(conf)
    repo = WaptLocalRepo(wapt_path)
    return Packages.update_from_repo(repo)


def main():
    parser = OptionParser(usage=__doc__)
    parser.add_option("-f", "--force",    dest="force",    default=False, action='store_true', help="Force (default: %default)")
    parser.add_option("-r", "--canonical-filenames", dest="canonical_filenames",  default=False, action='store_true', help="Rename package filenames to comply with latest canonical naming (default: %default)")
    parser.add_option("-l", "--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug', 'warning', 'info', 'error', 'critical'], metavar='LOGLEVEL', help="Loglevel (default: warning)")
    parser.add_option("-p", "--proxy",    dest="proxy",    default=None, help="http proxy (default: %default)")
    parser.add_option("-b", "--update-db",    dest="update_db",   default=True, action='store_true', help="Update the Packages database table (default: %default)")
    parser.add_option("-d", "--disable-update-db",    dest="disable_update_db",   default=False, action='store_true', help="Disable update of the Packages database table (default: %default)")
    parser.add_option("--reload-nginx-if-needed",    dest="reload_nginx_if_needed",   default=False, action='store_true', help="Launch a reload of nginx process if CRLs have been updated (default: %default)")

    parser.add_option(
        '-c',
        '--config',
        dest='configfile',
        default=waptserver.config.DEFAULT_CONFIG_FILE,
        help='Config file full path (default: %default)')
    (options, args) = parser.parse_args()

    conf = waptserver.config.load_config(options.configfile)

    loglevel = options.loglevel

    if len(logger.handlers) < 1:
        hdlr = logging.StreamHandler(sys.stderr)
        hdlr.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(message)s'))
        logger.addHandler(hdlr)

    if loglevel:
        setloglevel(logger, loglevel)
    else:
        setloglevel(logger, 'warning')

    if args:
        wapt_path = args[0]
    else:
        wapt_path = conf['wapt_folder']

    if os.path.exists(wapt_path) == False:
        logger.error("Directory does not exist: %s", wapt_path)
        sys.exit(1)
    if os.path.isdir(wapt_path) == False:
        logger.error("%s is not a directory", wapt_path)
        sys.exit(1)

    res = update_packages(wapt_path, force=options.force,
                          proxies={'http': options.proxy, 'https': options.proxy},
                          canonical_filenames=options.canonical_filenames)
    if options.update_db and not options.disable_update_db:
        logger.info('Updating the Packages database table from local repo packages index')
        res2 = len(update_packages_table(conf, wapt_path))
        logger.info('Database records updated: %s' % res2)

    if res and os.name == 'posix':
        logger.info('Set Packages file ownership to wapt')
        import pwd
        pwd_entry = pwd.getpwnam('wapt')
        uid, gid = pwd_entry.pw_uid, pwd_entry.pw_gid
        os.chown(res['packages_filename'], uid, gid)  # pylint: disable=no-member
        os.chmod(res['packages_filename'],0o0640)

    crls_updated = update_all_crls(conf,force=options.force)
    if crls_updated and os.name == 'posix':
        logger.info('Set CRLs file ownership to wapt')
        import pwd
        pwd_entry = pwd.getpwnam('wapt')
        uid, gid = pwd_entry.pw_uid, pwd_entry.pw_gid
        if conf['clients_signing_crl'] and os.path.isfile(conf['clients_signing_crl']):
            os.chown(conf['clients_signing_crl'], uid, gid)  # pylint: disable=no-member
        if conf['ssl_client_crls'] and os.path.isfile(conf['ssl_client_crls']):
            os.chown(conf['ssl_client_crls'], uid, gid)  # pylint: disable=no-member

    if options.reload_nginx_if_needed:
        if crls_updated and conf['ssl_client_crls'] and os.path.isfile(conf['ssl_client_crls']):
            if os.name == 'posix':
                ret_code = subprocess.call(['sudo','/bin/systemctl','reload','nginx'])
            else:
                nginx_fn = os.path.join(wapt_root_dir,'waptserver','nginx','nginx.exe')
                ret_code = subprocess.call([nginx_fn,'-s','reload'])

            if ret_code == 0:
                logger.info('Nginx configuration reloaded')
            else:
                logger.critical('Unable to reload Nginx configuration. error code: %s' % ret_code)

        else:
            logger.info('CRLS did not change, Nginx not reloaded.')

if __name__ == "__main__":
    main()

