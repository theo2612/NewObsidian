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

import os
import json
import datetime
from waptutils import datetime2isodate, isodate2datetime

from waptcrypto import SSLCertificate, SSLCABundle, get_cert_chain_from_pem

from collections import MutableMapping as DictMixin

import logging
logger = logging.getLogger()


class EWaptBadlicence(Exception):
    pass


class WaptLicence(DictMixin):
    # pylint: disable=no-member,access-member-before-definition
    _attributes = ['licence_nr', 'product', 'features', 'licenced_to', 'domain', 'contact_email', 'count', 'valid_from', 'valid_until', 'renewal_url', 'informations']
    _signature_attributes = ['signed_attributes', 'signer', 'signature_date', 'signer_certificate', 'signature']

    def __init__(self, licence_data=None, filename=None, licence_data_dict=None, **args):
        self.filename = filename
        self.licence_data = licence_data

        for a in self:
            setattr(self, a, None)

        if filename and os.path.isfile(filename):
            self.load_from_file(filename)
        elif licence_data:
            self.load_from_data(licence_data)

        if licence_data_dict:
            for (k, v) in licence_data_dict.items():
                if k in self._attributes+self._signature_attributes:
                    setattr(self, k, v)
                else:
                    raise Exception('Bad attribute "%s" for class %s' % (k, self.__class__))

        for (k, v) in args.items():
            if k in self._attributes+self._signature_attributes:
                setattr(self, k, v)
            else:
                raise Exception('Bad attribute %s for class %s' % (k, self.__class__))

        if self.domain is None:
            self.domain = ''

        if self.valid_from is None:
            self.valid_from = datetime2isodate(datetime.datetime.utcnow())[0:19]
        if self.valid_until is None:
            self.valid_until = datetime2isodate(isodate2datetime(self.valid_from) + datetime.timedelta(days=365))

    def load_from_data(self, licence_data):
        """Load a licence from json string"""
        licence_data_dict = json.loads(licence_data)
        for (k, v) in licence_data_dict.items():
            if k in self:
                setattr(self, k, v)
            else:
                raise Exception('Bad attribute %s for class %s' % (k, self.__class__))

    def load_from_file(self, filename):
        """Loads a licence form a file"""
        with open(filename, 'rb') as f:
            licence_data = f.read()
        self.load_from_data(licence_data)
        self.filename = filename

    def check_licence(self, cacert):
        """Check that the current licence object signature can be verified by signer and that signer is trusted
            ie signer's cert is signed by an trusted authority

        Args:
            cacert (str or list or SSLCABundle or SSLCertificate): trusted certificates as PEM data or list of certificates

        Returns:
            dict: signature_date,signer,verified_by(cn) result of waptcrypto verify_claim func
        """
        if not self.licence_nr or not self.licenced_to:
            raise EWaptBadlicence('Licence file has not licence_nr or no licenced_to')

        if not self.signature or not self.signer_certificate:
            raise EWaptBadlicence('Licence file is not signed')

        if isinstance(cacert, str):
            trusted_ca = SSLCABundle()
            trusted_ca.add_certificates_from_pem(pem_data=cacert,trusted=True)
        elif isinstance(cacert, SSLCABundle):
            trusted_ca = cacert
        elif isinstance(cacert, SSLCertificate):
            trusted_ca = SSLCABundle(certificates=[cacert],trust_all=True)
        elif isinstance(cacert, list):
            trusted_ca = SSLCABundle(certificates=cacert,trust_all=True)

        logger.debug('Checking licence with %s' % trusted_ca)
        # check signature
        signer_chain = get_cert_chain_from_pem(self.signer_certificate.encode('utf8'))
        trusted_chain = trusted_ca.check_certificates_chain(signer_chain)
        result = trusted_chain[0].verify_claim(self, required_attributes= [x for x in self._attributes if x != 'informations'])
        logger.debug('Licence verified %s' % result)
        return result

    def is_valid_until_from(self):
        try:
            valid_until = datetime.datetime.strptime(self.valid_until, '%Y-%m-%dT%H:%M:%S')
        except:
            try:
                valid_until = datetime.datetime.isoformat(self.valid_until)
            except:
                valid_until = datetime.datetime.strptime(self.valid_until, '%Y-%m-%dT%H:%M:%S.%f')

        try:
            valid_from = datetime.datetime.strptime(self.valid_from, '%Y-%m-%dT%H:%M:%S')
        except:
            try:
                valid_from = datetime.datetime.isoformat(self.valid_from)
            except:
                valid_from = datetime.datetime.strptime(self.valid_from, '%Y-%m-%dT%H:%M:%S.%f')

        return valid_from<datetime.datetime.utcnow() and valid_until>datetime.datetime.utcnow()

    def sign(self, signer_certificate_chain, privatekey):
        """Sign a licence with a private key and personal certificate chain
        This fills in the attributes 'signed_attributes','signer','signature_date','signer_certificate','signature'

        Returns:
            dict: with licence attributes and additional signature attributes
                    'signed_attributes','signer','signature_date','signer_certificate'
        """
        if not self.licence_nr or not self.licenced_to:
            raise EWaptBadlicence('Licence file must have a licence_nr and a licenced_to')

        signed_data = privatekey.sign_claim(self, signer_certificate_chain=signer_certificate_chain, attributes=self._attributes)
        for (k, v) in signed_data.items():
            if k in self:
                setattr(self, k, v)
            else:
                raise Exception('Bad attribute %s for class %s' % (k, self.__class__))
        return signed_data

    def save_to_file(self, filename=None):
        if filename is None:
            filename = self.filename
        if not self.signature:
            raise EWaptBadlicence('Licence data is not signed')
        data = json.dumps(dict(self), indent=True)
        with open(filename, 'w') as f:
            f.write(data)
        self.filename = filename

    def keys(self):
        return self._attributes+self._signature_attributes

    def __getitem__(self, key):
        return getattr(self, key)

    def __delitem__(self, key):
        pass

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self.keys())

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __str__(self):
        attribs = ['licence_nr', 'product', 'licenced_to', 'domain', 'count', 'valid_from', 'valid_until']
        return "Licence %s" % (' '.join(['%s:%s' % (attrib, getattr(self, attrib)) for attrib in attribs]))

    def __repr__(self):
        return self.__str__()

    def as_dict(self):
        return dict(self)


class WaptActivatedLicence(WaptLicence):
    _attributes = WaptLicence._attributes + ['server_uuid']


if __name__ == '__main__':
    pass
