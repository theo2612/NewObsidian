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
import glob
import shutil

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

try:
    wapt_root_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
except:
    wapt_root_dir = 'c:/tranquilit/wapt'

#from waptutils import __version__
from waptutils import _hash_file

from waptutils import setloglevel, ensure_list, ensure_unicode
from waptcrypto import SSLCABundle, SSLPrivateKey, SSLCertificate
from waptpackage import PackageEntry, WaptLocalRepo

from optparse import OptionParser
import logging
import hashlib

logger = logging.getLogger()

__doc__ = """\
wapt-signpackages -c crtfile package1 package2

Resign a list of packages
"""


def main():
    parser = OptionParser(usage=__doc__, prog='wapt-signpackage')
    parser.add_option("-d", "--directory", dest="repodir", default='', help="Repo path to re-sign all wapt packages present in this folder")
    parser.add_option("-c", "--certificate", dest="public_key", default='', help="Path to the PEM RSA certificate to embed identitiy in control. (default: %default)")
    parser.add_option("-t", "--trusted", dest="trusted_certs", default='', help="Path to the trusted PEM RSA certificates directory to check control signature. (default: %default)")
    parser.add_option("-k", "--private-key", dest="private_key", default='', help="Path to the PEM RSA private key to sign packages.  (default: %default)")
    #parser.add_option("-w","--private-key-passwd", dest="private_key_passwd", default='', help="Path to the password of the private key. (default: %default)")
    parser.add_option("-l", "--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug', 'warning', 'info', 'error', 'critical'], metavar='LOGLEVEL', help="Loglevel (default: warning)")
    parser.add_option("-s", "--scan-packages", dest="doscan", default=False, action='store_true', help="Rescan packages and update local Packages index after signing.  (default: %default)")
    parser.add_option("-r", "--remove-setup", dest="removesetup", default=False, action='store_true', help="Remove setup.py.  (default: %default)")
    parser.add_option("-i", "--inc-release",    dest="increlease",    default=False, action='store_true', help="Increase release number when building package (default: %default)")
    parser.add_option("--maturity", dest="set_maturity", default=None, help="Set/change package maturity when signing package. (default: None)")
    parser.add_option("--target-os", dest="set_target_os", default=None, help="Set target_os attribute if empty when signing package. (default: None)")
    parser.add_option("--keep-signature-date", dest="keep_signature_date", default=False, action='store_true', help="Keep the current package signature date, and file changetime (default: %default)")
    parser.add_option("--if-needed", dest="if_needed", default=False, action='store_true', help="Re-sign package only if needed (default: warning)")
    (options, args) = parser.parse_args()

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

    if len(args) < 1:
        if options.repodir == '':
            print(parser.usage)
            sys.exit(1)

    if not options.public_key and not options.private_key:
        print('ERROR: No certificate found or specified')
        sys.exit(1)

    if options.private_key and os.path.isfile(options.private_key):
        key = SSLPrivateKey(options.private_key)
    else:
        cert = SSLCertificate(options.public_key or options.private_key)
        key = cert.matching_key_in_dirs()

    if not key:
        print('ERROR: No private key found or specified')
        sys.exit(1)

    if options.repodir :
        args = glob.glob('%s/*.wapt' % options.repodir)
    else:
        args = ensure_list(args)

    signers_bundle = SSLCABundle()
    signers_bundle.add_certificates_from_pem(pem_filename=options.public_key)

    trusted_bundle = SSLCABundle()
    trusted_bundle.add_certificates_from_pem(pem_filename=options.public_key)
    if options.trusted_certs:
        trusted_bundle.add_pems(options.trusted_certs, trust_first=True)

    waptpackages = []
    for arg in args:
        waptpackages.extend(glob.glob(arg))

    errors = []
    package_dirs = []
    for waptpackage in waptpackages:
        package_dir = os.path.abspath(os.path.dirname(waptpackage))
        if not package_dir in package_dirs:
            package_dirs.append(package_dir)

        print('Processing %s' % waptpackage)
        try:
            sign_needed = False
            pe = PackageEntry(waptfile=waptpackage)
            #do not re-sign the waptupgrade package
            if pe.package.endswith('-waptupgrade'):
                continue
            if options.removesetup:
                if pe.has_file('setup.py'):
                    with pe.as_zipfile(mode='a') as waptfile:
                        waptfile.remove('setup.py')
                    sign_needed = True

            if not sign_needed and options.if_needed:
                try:
                    pe.check_control_signature(trusted_bundle=trusted_bundle, signers_bundle=signers_bundle)
                    if not pe.has_file(pe.get_signature_filename()):
                        raise Exception('Missing signature')
                    logger.info('%s metadata already signed properly' % pe.asrequirement())
                    sign_needed = False
                except Exception as e:
                    logger.info('Sign is needed for %s because %s' % (pe.asrequirement(), e))
                    sign_needed = True

            if options.increlease:
                pe.inc_build()
                sign_needed = True

            if options.set_maturity is not None and pe.maturity != options.set_maturity:
                pe.maturity = options.set_maturity
                logger.info('Setting maturity to %s' % options.set_maturity)
                sign_needed = True

            if options.set_target_os is not None and not pe.target_os:
                pe.target_os = options.set_target_os
                logger.info('Setting target_os to %s' % options.set_target_os)
                sign_needed = True

            if not options.if_needed or sign_needed:
                pe.sign_package(private_key=key, certificate=signers_bundle.certificates(), keep_signature_date=options.keep_signature_date)
                pe.md5sum = _hash_file(os.path.join(package_dir, pe.filename), hash_func=hashlib.md5)

                newfn = pe.make_package_filename()
                if newfn != pe.filename:
                    newfn_path = os.path.join(package_dir, newfn)
                    if not os.path.isfile(newfn_path):
                        print("Renaming file from %s to %s to match new package's properties" % (pe.filename, newfn))
                        shutil.move(os.path.join(package_dir, pe.filename), newfn_path)
                    else:
                        print('WARNING: unable to rename file from %s to %s because target already exists' % (pe.filename, newfn))

            print('Done')
        except Exception as e:
            print('Error: %s' % ensure_unicode(e))
            errors.append([waptpackage, repr(e)])

    if options.doscan:
        for package_dir in package_dirs:
            if os.path.isfile(os.path.join(package_dir, 'Packages')):
                print('Launching the update of Packages index in %s ...' % ensure_unicode(package_dir))
                repo = WaptLocalRepo(package_dir)
                repo.update_packages_index(canonical_filenames=True)
                print('Done')
    else:
        print("Don't forget to rescan your repository with wapt-scanpackages -r -f %s" % os.path.dirname(waptpackages[0]))

    if errors:
        print('Package not processed properly: ')
        for fn, error in errors:
            print('%s : %s' % (fn, error))

        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
