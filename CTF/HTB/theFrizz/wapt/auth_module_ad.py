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
import logging

from ldap3 import Server, Connection, Tls
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from ldap3.utils.conv import escape_filter_chars
import ssl

logger = logging.getLogger()
from certifi import core

def check_credentials_ad(conf, username, password, list_dn=[], list_group=[],use_service_account=False):
    """Authenticate against ldap with username and password

    Returns:
        list of groups
    """

    primary_group_manage = conf.get("ldap_primary_group_ad_support",True)
    nesting_group_manage = conf.get("ldap_nesting_group_support",True)
    dc_name = conf['ldap_auth_server']

    if not dc_name:
        return {'success': False, 'groups': [], 'error': True, 'msg': 'dc_name not provided'}

    logger.debug('Using %s as authentication ldap server' % dc_name)
    dc_base_dn = conf.get('ldap_auth_base_dn')
    default_user_kerberos_realm = dc_base_dn.lower().split('dc=', 1)[-1].replace('dc=', '.').replace(',', '')

    logger.debug('Using %s as base DN' % dc_base_dn)

    dc_ssl_enabled = conf['ldap_auth_ssl_enabled']

    if ':' in dc_name:
        logger.error("DC_NAME must be a DNS server name or ip, not a ldap url")
        raise Exception("DC_NAME must be a DNS server name or ip, not a ldap url")

    auth_ok = {'success': False, 'groups': [], 'error': False, 'msg': ''}

    # append a REALM if not provided.
    if not '@' in username:
        full_username = '%s@%s' % (username, default_user_kerberos_realm)
    else:
        full_username = username

    if use_service_account:
        bind_username = conf['ldap_account_service_login']
        password = conf['ldap_account_service_password']
    else:
        bind_username = full_username

    logger.debug('using dc %s for authentication, with base DN %s and bind username %s ' % (dc_name, dc_base_dn, bind_username))

    try:
        if dc_ssl_enabled:
            logger.debug('Using ldaps for authentication')
            verify_cert_ldap = conf['verify_cert_ldap']
            if verify_cert_ldap:
                ldapssl = ssl.CERT_REQUIRED
            else:
                ldapssl = ssl.CERT_NONE
            ca_certs_file = core.where()
            tls = Tls(validate=ldapssl, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=ca_certs_file)
            server = Server(dc_name, use_ssl=True, tls=tls)
        else:
            server = Server(dc_name, use_ssl=False, tls=False)

        c = Connection(server, user=bind_username, password=password.encode('utf-8'), raise_exceptions=True,check_names=primary_group_manage)
        c.bind()
        auth_ok['success'] = True
        dict_dn_groupename = {}
        real_list_dn = {}

        attrneed = ["distinguishedName"]
        if primary_group_manage:
            attrneed.append("objectSID")

        #search sid for list_dn
        for group_name in list_dn:
            ldap_filter = '(distinguishedName=%s)' % escape_filter_chars(group_name)
            c.search(dc_base_dn, search_filter=ldap_filter, attributes=attrneed)
            if c.response and ('attributes' in c.response[0]):
                dn = c.response[0]['attributes']['distinguishedName']
                if type(dn) == list:
                    dn = dn[0]
                if primary_group_manage:
                    minisid= c.response[0]['attributes']['objectSid'].rsplit('-')[-1]
                else:
                    minisid= None
                real_list_dn[dn] = minisid
                dict_dn_groupename[dn] = group_name

        #search sid and dn for list_group
        for group_name in list(list_group):
            ldap_filter = '(sAMAccountName=%s)' % escape_filter_chars(group_name)
            c.search(dc_base_dn, search_filter=ldap_filter, attributes=attrneed)
            if c.response and ('attributes' in c.response[0]):
                dn = c.response[0]['attributes']['distinguishedName']
                if type(dn) == list:
                    dn = dn[0]
                if primary_group_manage:
                    minisid= c.response[0]['attributes']['objectSid'].rsplit('-')[-1]
                else:
                    minisid= None
                real_list_dn[dn] = minisid
                dict_dn_groupename[dn] = group_name

        #For real_list_dn search if user member of group
        for dn in real_list_dn:
            filtergroup = "memberof"
            if nesting_group_manage:
                filtergroup = 'memberof:1.2.840.113556.1.4.1941:'
            if real_list_dn[dn]:
                ldap_filter = '(&(|(sAMAccountName=%s)(userPrincipalName=%s))(|(%s=%s)(primaryGroupID=%s)))' % (escape_filter_chars(username),escape_filter_chars(username),filtergroup,escape_filter_chars(dn),real_list_dn[dn])
            else:
                ldap_filter = '(&(|(sAMAccountName=%s)(userPrincipalName=%s))(%s=%s))' % (escape_filter_chars(username),escape_filter_chars(username),filtergroup,escape_filter_chars(dn))
            c.search(dc_base_dn, search_filter=ldap_filter)
            if c.response and ('dn' in c.response[0]):
                if dn in dict_dn_groupename:
                    auth_ok['groups'].append(dict_dn_groupename[dn])
                else:
                    auth_ok['groups'].append(dn)

    except LDAPInvalidCredentialsResult:
        auth_ok['success'] = False
        auth_ok['groups'] = []
        auth_ok['error'] = True
        auth_ok['msg'] = 'WRONG_PASSWORD_USERNAME'
        logger.debug('WRONG_PASSWORD_USERNAME')
    except Exception as e:
        auth_ok['success'] = False
        auth_ok['groups'] = []
        auth_ok['error'] = True
        auth_ok['msg'] = str(e)
    finally:
        try:
            c.unbind()
        except:
            pass
        return auth_ok
