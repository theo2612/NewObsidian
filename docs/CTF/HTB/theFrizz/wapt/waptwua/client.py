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

"""waptpython waptwua.py <action>

    Script which scans the computer for Windows Update based on wsusscn2 cab
    Stores the result of scan in waptdb
    Can download and apply Windows Updates from wapt server
    based on allowed_classifications, forbidden_updates, allowed_updates, allowed_severities list

    An update is allowed if :
      not in forbidden and
        (
          (in allowed_classifications if specified and in allowed_severities if specified)
          or
          in allowed_updates if specified
        )

    <action> can be :
        scan : updates wsusscn2.cab, and checks current computer againt allowed KB
        download : download necessary updates from wapt server and push them in cache
        install : install allowed cached updates
"""

import re
import datetime
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
import glob
import string

import pythoncom
from win32com.server.policy import MappedWrapPolicy, DesignatedWrapPolicy, EventHandlerPolicy
from win32com.client import CastTo

import random

from optparse import OptionParser
from urllib.parse import urlparse
from setuphelpers import ensure_list,system32,get_file_properties,registry_readstring,HKEY_LOCAL_MACHINE,service_is_running,REG_DWORD,registry_set
from setuphelpers import run, disable_file_system_redirection, ensure_unicode, Version, EnsureWUAUServRunning, wua_agent_version
from setuphelpers import task_exists, create_daily_task, delete_task, run_task, win32com_ensure_dispatch_patch, httpdatetime2isodate, error
from setuphelpers import registry_deletekey,WindowsVersions,get_kb_dism_name,windows_version

from waptutils import jsondump, get_time_delta, sha1_for_file, makepath, datetime2isodate, isfile, wget, wgets

from waptwua.utils import EWUABadSystem, EWUARebootNeeded, authorized_url_wsus, installed_windows_updates, get_sha1_from_filename, datetime_for_reg, waiting_for_reboot
from waptwua.constants import Products, UpdateType, InstallationImpact, InstallationRebootBehavior, OperationResultCode, UpdateClassifications

from iniparse import RawConfigParser

logger = logging.getLogger('waptwua')

try:
    import wmi
except:
    logger.warning('WMI is not available, some WaptWUA features will not work')
    wmi = None


def jsondump_sorted(o, **kwargs):
    return jsondump(o, sort_keys=True, separators=(',', ':'), **kwargs)


def get_product_id(expr):
    """Find product ids matching expr"""
    result = []
    match = re.compile(expr, re.IGNORECASE)
    for key, value in Products.items():
        if match.match(value) or expr == key:
            result.append(key)
    return result


Severities = {
    None: 'None',
    0: 'Critical',
    1: 'Important',
    2: 'Moderate',
    3: 'Low',
}

InstallResult = {
    0: 'NotStarted',
    1: 'InProgress',
    2: 'Succeeded',
    3: 'SucceededWithErrors',
    4: 'Failed',
    5: 'Aborted',
}

dict_wua_error = {
    "0x80243fff": "There was a user interface error not covered by another WU_E_AUCLIENT_* error code.",
    "0x8024a000": "Automatic Updates was unable to service incoming requests.",
    "0x8024a002": "The old version of the Automatic Updates client has stopped because the WSUS server has been upgraded.",
    "0x8024a003": "The old version of the Automatic Updates client was disabled.",
    "0x8024a004": "Automatic Updates was unable to process incoming requests because it was paused.",
    "0x8024a005": "No unmanaged service is registered with AU.",
    "0x8024afff": "An Automatic Updates error not covered by another WU_E_AU* code.",
    "0x80243001": "The results of download and installation couldn't be read from the registry due to an unrecognized data format version.",
    "0x80243002": "The results of download and installation couldn't be read from the registry due to an invalid data format.",
    "0x80243003": "\"The results of download and installation aren't available",
    "0x80243004": "A failure occurred when trying to create an icon in the taskbar notification area.",
    "0x80243ffd": "\"Unable to show UI when in non-UI mode",
    "0x80243ffe": "Unsupported version of Windows Update client UI exported functions.",
    "0x8024043d": "The requested service property isn't available.",
    "0x80249001": "Parsing of the rule file failed.",
    "0x80249002": "Failed to get the requested inventory type from the server.",
    "0x80249003": "Failed to upload inventory result to the server.",
    "0x80249004": "There was an inventory error not covered by another error code.",
    "0x80249005": "A WMI error occurred when enumerating the instances for a particular class.",
    "0x8024e001": "An expression evaluator operation couldn't be completed because an expression was unrecognized.",
    "0x8024e002": "An expression evaluator operation couldn't be completed because an expression was invalid.",
    "0x8024e003": "An expression evaluator operation couldn't be completed because an expression contains an incorrect number of metadata nodes.",
    "0x8024e004": "An expression evaluator operation couldn't be completed because the version of the serialized expression data is invalid.",
    "0x8024e005": "The expression evaluator couldn't be initialized.",
    "0x8024e006": "An expression evaluator operation couldn't be completed because there was an invalid attribute.",
    "0x8024e007": "An expression evaluator operation couldn't be completed because the cluster state of the computer couldn't be determined.",
    "0x8024efff": "There was an expression evaluator error not covered by another WU_E_EE_* error code.",
    "0x80247001": "An operation couldn't be completed because the scan package was invalid.",
    "0x80247002": "An operation couldn't be completed because the scan package requires a greater version of the Windows Update Agent.",
    "0x80247fff": "Search using the scan package failed.",
    "0x8024f001": "The event cache file was defective.",
    "0x8024f002": "The XML in the event namespace descriptor couldn't be parsed.",
    "0x8024f003": "The XML in the event namespace descriptor couldn't be parsed.",
    "0x8024f004": "The server rejected an event because the server was too busy.",
    "0x8024ffff": "There was a reporter error not covered by another error code.",
    "0x80245001": "The redirector XML document couldn't be loaded into the DOM class.",
    "0x80245002": "The redirector XML document is missing some required information.",
    "0x80245003": "The redirectorId in the downloaded redirector cab is less than in the cached cab.",
    "0x80245fff": "The redirector failed for reasons not covered by another WU_E_REDIRECTOR_* error code.",
    "0x80244000": "WU_E_PT_SOAPCLIENT_* error codes map to the SOAPCLIENT_ERROR enum of the ATL Server Library.",
    "0x80244001": "Same as SOAPCLIENT_INITIALIZE_ERROR - initialization of the SOAP client failed possibly because of an MSXML installation failure.",
    "0x80244002": "Same as SOAPCLIENT_OUTOFMEMORY - SOAP client failed because it ran out of memory.",
    "0x80244003": "Same as SOAPCLIENT_GENERATE_ERROR - SOAP client failed to generate the request.",
    "0x80244004": "Same as SOAPCLIENT_CONNECT_ERROR - SOAP client failed to connect to the server.",
    "0x80244005": "Same as SOAPCLIENT_SEND_ERROR - SOAP client failed to send a message for reasons of WU_E_WINHTTP_* error codes.",
    "0x80244006": "Same as SOAPCLIENT_SERVER_ERROR - SOAP client failed because there was a server error.",
    "0x80244007": "Same as SOAPCLIENT_SOAPFAULT - SOAP client failed because there was a SOAP fault for reasons of WU_E_PT_SOAP_* error codes.",
    "0x80244008": "Same as SOAPCLIENT_PARSEFAULT_ERROR - SOAP client failed to parse a SOAP fault.",
    "0x80244009": "Same as SOAPCLIENT_READ_ERROR - SOAP client failed while reading the response from the server.",
    "0x8024400a": "Same as SOAPCLIENT_PARSE_ERROR - SOAP client failed to parse the response from the server.",
    "0x8024400b": "Same as SOAP_E_VERSION_MISMATCH - SOAP client found an unrecognizable namespace for the SOAP envelope.",
    "0x8024400c": "Same as SOAP_E_MUST_UNDERSTAND - SOAP client was unable to understand a header.",
    "0x8024400d": "\"Same as SOAP_E_CLIENT - SOAP client found the message was malformed",
    "0x8024400e": "\"Same as SOAP_E_SERVER - The SOAP message couldn't be processed due to a server error",
    "0x8024400f": "There was an unspecified Windows Management Instrumentation (WMI) error.",
    "0x80244010": "The number of round trips to the server exceeded the maximum limit.",
    "0x80244011": "WUServer policy value is missing in the registry.",
    "0x80244012": "Initialization failed because the object was already initialized.",
    "0x80244013": "The computer name couldn't be determined.",
    "0x80244015": "\"The reply from the server indicates that the server was changed or the cookie was invalid",
    "0x80244016": "Same as HTTP status 400 - the server couldn't process the request due to invalid syntax.",
    "0x80244017": "Same as HTTP status 401 - the requested resource requires user authentication.",
    "0x80244018": "Same as HTTP status 403 - server understood the request but declined to fulfill it.",
    "0x80244019": "Same as HTTP status 404 - the server can't find the requested URI (Uniform Resource Identifier).",
    "0x8024401a": "Same as HTTP status 405 - the HTTP method isn't allowed.",
    "0x8024401b": "Same as HTTP status 407 - proxy authentication is required.",
    "0x8024401c": "Same as HTTP status 408 - the server timed out waiting for the request.",
    "0x8024401d": "Same as HTTP status 409 - the request wasn't completed due to a conflict with the current state of the resource.",
    "0x8024401e": "Same as HTTP status 410 - requested resource is no longer available at the server.",
    "0x8024401f": "Same as HTTP status 500 - an error internal to the server prevented fulfilling the request.",
    "0x80244020": "Same as HTTP status 500 - server doesn't support the functionality required to fulfill the request.",
    "0x80244021": "Same as HTTP status 502 - the server while acting as a gateway or a proxy received an invalid response from the upstream server it accessed in attempting to fulfill the request.",
    "0x80244022": "Same as HTTP status 503 - the service is temporarily overloaded.",
    "0x80244023": "Same as HTTP status 503 - the request was timed out waiting for a gateway.",
    "0x80244024": "Same as HTTP status 505 - the server doesn't support the HTTP protocol version used for the request.",
    "0x80244025": "\"Operation failed due to a changed file location",
    "0x80244026": "Operation failed because Windows Update Agent doesn't support registration with a non-WSUS server.",
    "0x80244027": "The server returned an empty authentication information list.",
    "0x80244028": "Windows Update Agent was unable to create any valid authentication cookies.",
    "0x80244029": "A configuration property value was wrong.",
    "0x8024402a": "A configuration property value was missing.",
    "0x8024402b": "The HTTP request couldn't be completed and the reason didn't correspond to any of the WU_E_PT_HTTP_* error codes.",
    "0x8024402c": "Same as ERROR_WINHTTP_NAME_NOT_RESOLVED - the proxy server or target server name can't be resolved.",
    "0x8024402f": "External cab file processing completed with some errors.",
    "0x80244030": "The external cab processor initialization didn't complete.",
    "0x80244031": "The format of a metadata file was invalid.",
    "0x80244032": "External cab processor found invalid metadata.",
    "0x80244033": "The file digest couldn't be extracted from an external cab file.",
    "0x80244034": "An external cab file couldn't be decompressed.",
    "0x80244035": "External cab processor was unable to get file locations.",
    "0x80244fff": "A communication error not covered by another WU_E_PT_* error code.",
    "0x8024502d": "Windows Update Agent failed to download a redirector cabinet file with a new redirectorId value from the server during the recovery.",
    "0x8024502e": "A redirector recovery action didn't complete because the server is managed.",
    "0x80246001": "A download manager operation couldn't be completed because the requested file doesn't have a URL.",
    "0x80246002": "A download manager operation couldn't be completed because the file digest wasn't recognized.",
    "0x80246003": "A download manager operation couldn't be completed because the file metadata requested an unrecognized hash algorithm.",
    "0x80246004": "An operation couldn't be completed because a download request is required from the download handler.",
    "0x80246005": "A download manager operation couldn't be completed because the network connection was unavailable.",
    "0x80246006": "A download manager operation couldn't be completed because the version of Background Intelligent Transfer Service (BITS) is incompatible.",
    "0x80246007": "The update hasn't been downloaded.",
    "0x80246008": "A download manager operation failed because the download manager was unable to connect the Background Intelligent Transfer Service (BITS).",
    "0x80246009": "A download manager operation failed because there was an unspecified Background Intelligent Transfer Service (BITS) transfer error.",
    "0x8024600a": "A download must be restarted because the location of the source of the download has changed.",
    "0x8024600b": "A download must be restarted because the update content changed in a new revision.",
    "0x80246fff": "There was a download manager error not covered by another WU_E_DM_* error code.",
    "0x80242000": "A request for a remote update handler couldn't be completed because no remote process is available.",
    "0x80242001": "A request for a remote update handler couldn't be completed because the handler is local only.",
    "0x80242002": "A request for an update handler couldn't be completed because the handler couldn't be recognized.",
    "0x80242003": "A remote update handler couldn't be created because one already exists.",
    "0x80242004": "A request for the handler to install (uninstall) an update couldn't be completed because the update doesn't support install (uninstall).",
    "0x80242005": "An operation didn't complete because the wrong handler was specified.",
    "0x80242006": "A handler operation couldn't be completed because the update contains invalid metadata.",
    "0x80242007": "An operation couldn't be completed because the installer exceeded the time limit.",
    "0x80242008": "An operation being done by the update handler was canceled.",
    "0x80242009": "An operation couldn't be completed because the handler-specific metadata is invalid.",
    "0x8024200a": "A request to the handler to install an update couldn't be completed because the update requires user input.",
    "0x8024200b": "The installer failed to install (uninstall) one or more updates.",
    "0x8024200c": "The update handler should download self-contained content rather than delta-compressed content for the update.",
    "0x8024200d": "The update handler didn't install the update because it needs to be downloaded again.",
    "0x8024200e": "The update handler failed to send notification of the status of the install (uninstall) operation.",
    "0x8024200f": "The file names contained in the update metadata and in the update package are inconsistent.",
    "0x80242010": "The update handler failed to fall back to the self-contained content.",
    "0x80242011": "The update handler has exceeded the maximum number of download requests.",
    "0x80242012": "The update handler has received an unexpected response from CBS.",
    "0x80242013": "The update metadata contains an invalid CBS package identifier.",
    "0x80242014": "The post-reboot operation for the update is still in progress.",
    "0x80242015": "The result of the post-reboot operation for the update couldn't be determined.",
    "0x80242016": "The state of the update after its post-reboot operation has completed is unexpected.",
    "0x80242017": "The OS servicing stack must be updated before this update is downloaded or installed.",
    "0x80242fff": "An update handler error not covered by another WU_E_UH_* code.",
    "0x80248000": "An operation failed because Windows Update Agent is shutting down.",
    "0x80248001": "An operation failed because the data store was in use.",
    "0x80248002": "The current and expected states of the data store don't match.",
    "0x80248003": "The data store is missing a table.",
    "0x80248004": "The data store contains a table with unexpected columns.",
    "0x80248005": "A table couldn't be opened because the table isn't in the data store.",
    "0x80248006": "The current and expected versions of the data store don't match.",
    "0x80248007": "The information requested isn't in the data store.",
    "0x80248008": "The data store is missing required information or has a NULL in a table column that requires a non-null value.",
    "0x80248009": "The data store is missing required information or has a reference to missing license terms file localized property or linked row.",
    "0x8024800a": "The update wasn't processed because its update handler couldn't be recognized.",
    "0x8024800b": "The update wasn't deleted because it's still referenced by one or more services.",
    "0x8024800c": "The data store section couldn't be locked within the allotted time.",
    "0x8024800d": "The category wasn't added because it contains no parent categories and isn't a top-level category itself.",
    "0x8024800e": "The row wasn't added because an existing row has the same primary key.",
    "0x8024800f": "The data store couldn't be initialized because it was locked by another process.",
    "0x80248010": "The data store isn't allowed to be registered with COM in the current process.",
    "0x80248011": "Couldn't create a data store object in another process.",
    "0x80248013": "The server sent the same update to the client with two different revision IDs.",
    "0x80248014": "An operation didn't complete because the service isn't in the data store.",
    "0x80248015": "An operation didn't complete because the registration of the service has expired.",
    "0x80248016": "A request to hide an update was declined because it's a mandatory update or because it was deployed with a deadline.",
    "0x80248017": "A table wasn't closed because it isn't associated with the session.",
    "0x80248018": "A table wasn't closed because it isn't associated with the session.",
    "0x80248019": "A request to remove the Windows Update service or to unregister it with Automatic Updates was declined because it's a built-in service and/or Automatic Updates can't fall back to another service.",
    "0x8024801a": "A request was declined because the operation isn't allowed.",
    "0x8024801b": "The schema of the current data store and the schema of a table in a backup XML document don't match.",
    "0x8024801c": "\"The data store requires a session reset",
    "0x8024801d": "A data store operation didn't complete because it was requested with an impersonated identity.",
    "0x80248fff": "A data store error not covered by another WU_E_DS_* code.",
    "0x8024c001": "A driver was skipped.",
    "0x8024c002": "A property for the driver couldn't be found. It may not conform with required specifications.",
    "0x8024c003": "The registry type read for the driver doesn't match the expected type.",
    "0x8024c004": "The driver update is missing metadata.",
    "0x8024c005": "The driver update is missing a required attribute.",
    "0x8024c006": "Driver synchronization failed.",
    "0x8024c007": "Information required for the synchronization of applicable printers is missing.",
    "0x8024cfff": "A driver error not covered by another WU_E_DRV_* code.",
    "0x80240001": "Windows Update Agent was unable to provide the service.",
    "0x80240002": "The maximum capacity of the service was exceeded.",
    "0x80240003": "An ID can't be found.",
    "0x80240004": "The object couldn't be initialized.",
    "0x80240005": "The update handler requested a byte range overlapping a previously requested range.",
    "0x80240006": "The requested number of byte ranges exceeds the maximum number (2^31 - 1).",
    "0x80240007": "The index to a collection was invalid.",
    "0x80240008": "The key for the item queried couldn't be found.",
    "0x80240009": "Another conflicting operation was in progress. Some operations such as installation can't be performed twice simultaneously.",
    "0x8024000a": "Cancellation of the operation wasn't allowed.",
    "0x8024000b": "Operation was canceled.",
    "0x8024000c": "No operation was required.",
    "0x8024000d": "Windows Update Agent couldn't find required information in the update's XML data.",
    "0x8024000e": "Windows Update Agent found invalid information in the update's XML data.",
    "0x8024000f": "Circular update relationships were detected in the metadata.",
    "0x80240010": "Update relationships too deep to evaluate were evaluated.",
    "0x80240011": "An invalid update relationship was detected.",
    "0x80240012": "An invalid registry value was read.",
    "0x80240013": "Operation tried to add a duplicate item to a list.",
    "0x80240016": "Operation tried to install while another installation was in progress or the system was pending a mandatory restart.",
    "0x80240017": "Operation wasn't performed because there are no applicable updates.",
    "0x80240018": "Operation failed because a required user token is missing.",
    "0x80240019": "An exclusive update can't be installed with other updates at the same time.",
    "0x8024001a": "A policy value wasn't set.",
    "0x8024001b": "The operation couldn't be performed because the Windows Update Agent is self-updating.",
    "0x8024001d": "An update contains invalid metadata.",
    "0x8024001e": "Operation didn't complete because the service or system was being shut down.",
    "0x8024001f": "Operation didn't complete because the network connection was unavailable.",
    "0x80240020": "Operation didn't complete because there's no logged-on interactive user.",
    "0x80240021": "Operation didn't complete because it timed out.",
    "0x80240022": "Operation failed for all the updates.",
    "0x80240023": "The license terms for all updates were declined.",
    "0x80240024": "There are no updates.",
    "0x80240025": "Group Policy settings prevented access to Windows Update.",
    "0x80240026": "The type of update is invalid.",
    "0x80240027": "The URL exceeded the maximum length.",
    "0x80240028": "The update couldn't be uninstalled because the request didn't originate from a WSUS server.",
    "0x80240029": "Search may have missed some updates before there's an unlicensed application on the system.",
    "0x8024002a": "A component required to detect applicable updates was missing.",
    "0x8024002b": "An operation didn't complete because it requires a newer version of server.",
    "0x8024002c": "A delta-compressed update couldn't be installed because it required the source.",
    "0x8024002d": "A full-file update couldn't be installed because it required the source.",
    "0x8024002e": "Access to an unmanaged server isn't allowed.",
    "0x8024002f": "Operation didn't complete because the DisableWindowsUpdateAccess policy was set.",
    "0x80240030": "The format of the proxy list was invalid.",
    "0x80240031": "The file is in the wrong format.",
    "0x80240032": "The search criteria string was invalid.",
    "0x80240033": "License terms couldn't be downloaded.",
    "0x80240034": "Update failed to download.",
    "0x80240035": "The update wasn't processed.",
    "0x80240036": "The object's current state didn't allow the operation.",
    "0x80240037": "The functionality for the operation isn't supported.",
    "0x80240038": "The downloaded file has an unexpected content type.",
    "0x80240039": "Agent is asked by server to resync too many times.",
    "0x80240040": "WUA API method doesn't run on Server Core installation.",
    "0x80240041": "Service isn't available while sysprep is running.",
    "0x80240042": "The update service is no longer registered with AU.",
    "0x80240043": "There's no support for WUA UI.",
    "0x80240fff": "An operation failed due to reasons not covered by another error code.",
    "0x80070422": "Windows Update service stopped working or isn't running.",
    "0x00240001": "Windows Update Agent was stopped successfully.",
    "0x00240002": "Windows Update Agent updated itself.",
    "0x00240003": "Operation completed successfully but there were errors applying the updates.",
    "0x00240004": "A callback was marked to be disconnected later because the request to disconnect the operation came while a callback was executing.",
    "0x00240005": "The system must be restarted to complete installation of the update.",
    "0x00240006": "The update to be installed is already installed on the system.",
    "0x00240007": "The update to be removed isn't installed on the system.",
    "0x00240008": "The update to be downloaded has already been downloaded.",
    "0x80241001": "Search may have missed some updates because the Windows Installer is less than version 3.1.",
    "0x80241002": "Search may have missed some updates because the Windows Installer isn't configured.",
    "0x80241003": "Search may have missed some updates because policy has disabled Windows Installer patching.",
    "0x80241004": "An update couldn't be applied because the application is installed per-user.",
    "0x80241fff": "Search may have missed some updates because there was a failure of the Windows Installer.",
    "0x8024d001": "Windows Update Agent couldn't be updated because an INF file contains invalid information.",
    "0x8024d002": "Windows Update Agent couldn't be updated because the wuident.cab file contains invalid information.",
    "0x8024d003": "Windows Update Agent couldn't be updated because of an internal error that caused setup initialization to be performed twice.",
    "0x8024d004": "Windows Update Agent couldn't be updated because setup initialization never completed successfully.",
    "0x8024d005": "Windows Update Agent couldn't be updated because the versions specified in the INF don't match the actual source file versions.",
    "0x8024d006": "Windows Update Agent couldn't be updated because a WUA file on the target system is newer than the corresponding source file.",
    "0x8024d007": "Windows Update Agent couldn't be updated because regsvr32.exe returned an error.",
    "0x8024d009": "An update to the Windows Update Agent was skipped due to a directive in the wuident.cab file.",
    "0x8024d00a": "Windows Update Agent couldn't be updated because the current system configuration isn't supported.",
    "0x8024d00b": "Windows Update Agent couldn't be updated because the system is configured to block the update.",
    "0x8024d00c": "Windows Update Agent couldn't be updated because a restart of the system is required.",
    "0x8024d00d": "Windows Update Agent setup is already running.",
    "0x8024d00e": "Windows Update Agent setup package requires a reboot to complete installation.",
    "0x8024d00f": "Windows Update Agent couldn't be updated because the setup handler failed during execution.",
    "0x8024d010": "Windows Update Agent couldn't be updated because the registry contains invalid information.",
    "0x8024d013": "Windows Update Agent couldn't be updated because the server doesn't contain update information for this version.",
    "0x8024dfff": "Windows Update Agent couldn't be updated because of an error not covered by another WU_E_SETUP_* error code.",
    "0x80070bc9": "The requested operation failed. Restart the system to roll back changes made.",
    "0x80072efd": "The operation timed out",
    "0x80d02002": "The operation timed out",
    "0x8007000d": "Indicates data that isn't valid was downloaded or corruption occurred.",
    "0x8024a10a": "Indicates that the Windows Update Service is shutting down.",
    "0x80246017": "The download failed because the local user was denied authorization to download the content.",
    "0x800f0821": "CBS transaction timeout exceeded.",
    "0x800f0825": "Typically this error is due component store corruption caused when a component is in a partially installed state.",
    "0x800f0920": "Subsequent error logged after getting 0x800f0821",
    "0x800f081f": "Component Store corruption ",
    "0x800f0831": "Corruption in the Windows Component  Store.",
    "0x80070005": "File system or registry key permissions have been changed and the servicing stack doesn't have the required level of access.",
    "0x80070570": "Component Store corruption ",
    "0x80070003": "The servicing stack can't access a specific path.",
    "0x80070020": "Numerous causes. CBS log analysis required.",
    "0x80073701": "Typically, a component store corruption caused when a component is in a partially installed state.",
    "0x8007371b": "Component Store corruption.",
    "0x80072efe": "BITS is unable to transfer the file successfully.",
    "0x80072f8f": "TLS 1.2 isn't configured correctly on the client.",
    "0x80072ee2": "Unable to scan for updates due to a connectivity issue to Windows Update, Configuration Manager, or WSUS.",
    "0x80070490": "This error occurs during driver installation as part of the update.",
    "0x800f0922": "The July cumulative update failed to be installed on Windows Server 2016",
    "0x800706be": "Windows Server 2016 Std failed to install cumulative packages by using the .msu package. No error is returned. When installing the packages with dism.exe, it returned the error 0x800706be."
}

def convert_wua_error(msg):
    for entry in dict_wua_error:
        if entry.lower() in str(msg).lower():
            return entry + ' : ' + dict_wua_error[entry]
    return msg


WUA_MAJOR_VERSION = 7
WUA_MINOR_VERSION = 6

_startupinfo_hide = subprocess.STARTUPINFO()
_startupinfo_hide.wShowWindow = subprocess.SW_HIDE


def create_waptwua_tasks(wapt, default_categories=['CriticalUpdates', 'SecurityUpdates', 'DefinitionUpdates', 'UpdateRollups']):
    """Create periodic tasks for :
    - download of wsuscn2.scn and scan of pending update tasks
    - install of updates
    """
    waptpython_path = makepath(wapt.wapt_base_dir, 'wapt-get.exe')
    waptwua_path = makepath(wapt.wapt_base_dir, 'waptwua')

    if task_exists('waptwua'):
        delete_task('waptwua')
    if task_exists('waptwua-scan'):
        delete_task('waptwua-scan')
    if task_exists('waptwua-install'):
        delete_task('waptwua-install')

     # randowmize a little the scan
    dt = datetime.datetime.utcnow()+datetime.timedelta(hours=random.randrange(0, 5), minutes=random.randrange(0, 59))
    create_daily_task('waptwua-scan', waptpython_path, '"%s" download -C %s' % (makepath(waptwua_path, 'waptwua.py'), ','.join(default_categories)), start_hour=dt.hour, start_minute=dt.minute)
    create_daily_task('waptwua-install', waptpython_path, '"%s" install -C %s' % (makepath(waptwua_path, 'waptwua.py'), ','.join(default_categories)), start_hour=3, start_minute=0)


def remove_waptwua_tasks():
    if task_exists('waptwua-scan'):
        run_task
        delete_task('waptwua-scan')
    if task_exists('waptwua-install'):
        delete_task('waptwua-install')


class WAPTDiskSpaceException(Exception):
    def __init__(self, message, free_space):
        self.message = message
        self.free_space = free_space

    def __str__(self):
        return str(self.message) + '; free space: ' + str(self.free_space / 2**20) + 'MB'


class WaptJSonSettings(object):
    CRITERIA_LIST = []
    CRITERIA_BOOL = []
    CRITERIA_STR = []

    _class_key = 'waptsettings'

    def __init__(self, **kwargs):
        for (k, v) in kwargs.items():
            if k in self.CRITERIA_LIST+self.CRITERIA_BOOL+self.CRITERIA_STR:
                setattr(self, k, v)
            else:
                raise Exception('Unknown %s parameter %s' % (self.__class__.__name__, k))

    def load_from_options(self, options_parser):
        for key in self.CRITERIA_LIST:
            fqkey = '%s.%s' % (self._class_key, key)
            if getattr(options_parser, fqkey, None) is not None:
                setattr(self, key, ensure_list(getattr(options_parser, fqkey, None)))
        for key in self.CRITERIA_BOOL+self.CRITERIA_STR:
            fqkey = '%s.%s' % (self._class_key, key)
            if getattr(options_parser, fqkey, None) is not None:
                setattr(self, key, getattr(options_parser, fqkey, None))
        return self

    def load_from_ini(self, config_filename=None, config=None, section=None):
        if section is None:
            section = self._class_key
        if config is None:
            config = RawConfigParser()
            config.read(config_filename)
        if config.has_section(section):
            for key in self.CRITERIA_BOOL:
                if config.has_option(section, key):
                    setattr(self, key, config.getboolean(section, key))
            for key in self.CRITERIA_LIST:
                if config.has_option(section, key):
                    setattr(self, key, ensure_list(config.get(section, key)))
            for key in self.CRITERIA_STR:
                if config.has_option(section, key):
                    setattr(self, key, config.get(section, key))
        return self

    def merge_rules(self, rules_dict, ignore_unknown_keys=False):
        """Merge lists with same key name as mine from rules_dict
        Other item are just overwritten.
        Keys of rules_dict must

        Args:
            rules_dict (dict) : {key: (None or list or str or bool..)}

        Returns:
            None

        """

        for (k, v) in rules_dict.items():
            if k in self.CRITERIA_LIST+self.CRITERIA_BOOL+self.CRITERIA_STR:
                old_value = getattr(self, k)
                if old_value is None or not isinstance(old_value, list):
                    # overrides value even if already set ...
                    setattr(self, k, v)
                elif v is not None:
                    # append to lists
                    for item in v:
                        if not item in old_value:
                            old_value.append(item)
            elif not ignore_unknown_keys:
                raise Exception('Unknown parameter %s for %s' % (k, self.__class__.__name__))

    def merge_rules_from_files(self, json_filenames_glob=None):
        """Merge all json files matching glob.glob(json_filenames_glob)
        """
        for json_fn in glob.glob(json_filenames_glob):
            try:
                with open(json_fn, 'r') as f:
                    rules = json.load(f)
                self.merge_rules(rules)
            except Exception as e:
                logger.critical('Unable to load rules from file %s, rules ignored. %s' % (json_fn,e))
        return self

    def save_to_ini(self, config_filename=None, config=None, section='waptwua'):
        updated = False
        if config is None:
            config = RawConfigParser()
            config.read(config_filename)
            temp_ini = True

        def _encode_ini_value(value, key=None):
            if isinstance(value, list):
                return ','.join(value)
            elif value is None:
                return ''
            else:
                return value

        for key in self.CRITERIA_LIST+self.CRITERIA_BOOL+self.CRITERIA_STR:
            value = getattr(self, key, None)
            ini_key = key
            if value is None:
                if config.has_option(section, ini_key):
                    config.remove_option(section, ini_key)
                    updated = True
            else:
                if config.has_section(section) and config.has_option(section, ini_key):
                    if key in self.CRITERIA_LIST:
                        old_value = ensure_list(config.get(section, ini_key))
                    elif key in self.CRITERIA_BOOL:
                        old_value = config.getboolean(section, ini_key)
                    else:
                        old_value = config.get(section, ini_key)
                else:
                    old_value = None

                if old_value != value:
                    if not config.has_section(section):
                        config.add_section(section)
                    if key in self.CRITERIA_LIST:
                        config.set(section, ini_key, ','.join(value))
                    else:
                        config.set(section, ini_key, value)
                    updated = True

        if temp_ini and updated:
            with open(config_filename, 'wb') as f:
                config.write(f)
        return updated

    def load_from_waptdb(self, wapt):
        rules = wapt.read_param(self._class_key, ptype='json')
        if rules:
            for key in self.CRITERIA_LIST+self.CRITERIA_BOOL+self.CRITERIA_STR:
                if getattr(self, key, None) is None:
                    setattr(self, key, rules.get(key))
        return self

    def save_to_waptdb(self, wapt):
        wapt.write_param(self._class_key, self.as_dict())

    def as_dict(self):
        return {key: getattr(self, key) for key in self.CRITERIA_LIST+self.CRITERIA_BOOL+self.CRITERIA_STR}

    def __repr__(self):
        return repr(self.as_dict())


class WaptWUARules(WaptJSonSettings):
    CRITERIA_LIST = ['allowed_products', 'allowed_classifications', 'allowed_severities',
                     'allowed_updates', 'forbidden_updates', 'allowed_kbs', 'forbidden_kbs']
    CRITERIA_BOOL = ['default_allow','include_potentially_superseded_updates']
    CRITERIA_STR = []

    _class_key = 'waptwua_rules'

    def __init__(self, **kwargs):
        self.allowed_products = None
        self.allowed_classifications = None
        self.allowed_severities = None
        self.allowed_updates = None
        self.forbidden_updates = None
        self.allowed_kbs = None
        self.forbidden_kbs = None
        self.default_allow = None
        self.include_potentially_superseded_updates = False

        super(WaptWUARules, self).__init__(**kwargs)

    def is_allowed(self, update):
        """Check if an update is allowed
            allowed if not explicitly forbidden and in allowed classifications, products and criticities or list of update ids

        Args:
            update (IUpdate)

        Returns:
            bool
        """
        update_id = "%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber)

        if self.forbidden_updates is not None and update_id in self.forbidden_updates:
            return False

        # check by KB list as well as by updateId list
        kbs = ["KB%s" % kb for kb in update.KBArticleIDs]

        if self.forbidden_kbs is not None:
            for kb in kbs:
                if kb in self.forbidden_kbs:
                    return False

        # individual update_id_revision allowance
        if self.allowed_updates is not None and update_id in self.allowed_updates:
            return True

        # individual KB allowance
        if self.allowed_kbs is not None:
            for kb in kbs:
                if kb in self.allowed_kbs:
                    return True

        # product filter
        if self.allowed_products is not None:
            products = [c.Name for c in update.Categories if c.Type == 'Product']
            if products:
                product = products[0]
            else:
                product = ''

            if product in self.allowed_products:
                return True

        # severities filter
        if self.allowed_severities is not None:
            if update.MsrcSeverity in self.allowed_severities:
                return True

        # classification filter
        if self.allowed_classifications is not None:
            # get updateClassification list of this update
            update_class = [c.Name for c in update.Categories if c.Type == 'UpdateClassification']
            for cat in update_class:
                if cat in self.allowed_classifications:
                    return True

        return self.default_allow


class WaptWUAParams(WaptJSonSettings):
    CRITERIA_LIST = []
    CRITERIA_BOOL = ['direct_download', 'default_allow','include_potentially_superseded_updates']
    CRITERIA_STR = ['filter', 'download_scheduling', 'install_scheduling', 'install_delay', 'postboot_delay','user_locale']

    _class_key = 'waptwua_params'

    def __init__(self, **kwargs):
        self._filter = None

        #en us
        self.user_locale= 1033

        self.direct_download = False
        self.default_allow = False
        self.download_scheduling = None
        self.install_scheduling = None
        self.install_delay = None
        self.include_potentially_superseded_updates = False
        self.postboot_delay = '10m' # delay the download / install task after boot

        super(WaptWUAParams, self).__init__(**kwargs)

    @property
    def filter(self):
        if self._filter is not None:
            return self._filter
        else:
            return "Type='Software' or Type='Driver'"

    @filter.setter
    def filter(self, value):
        self._filter = value

    def is_delayed(self, update):
        # don't install before install_delay after publishing date
        if self.install_delay:
            try:
                delay_delta = get_time_delta(self.install_delay, 'd')
            except Exception as e:
                logger.critical('Bad time install_delay: %s %s' % (self.install_delay, repr(e)))
                return True
            changetime = datetime.datetime.fromtimestamp(timestamp=update.LastDeploymentChangeTime.timestamp())
            delayed = datetime.datetime.utcnow() < (changetime + delay_delta)
        else:
            delayed = False
        return delayed


class WaptWUA(EnsureWUAUServRunning):
    def __init__(self, wapt, params=None, windows_updates_rules=None):
        """Initialize a waptwua client

        Args:
            windows_updates_rules (WaptWUARules):  {'allowed_products','forbidden_updates','allowed_updates','allowed_severities','allowed_classifications'}

        """
        self.wapt = wapt
        self.cache_path = wapt.packages_cache_dir
        self.wsusscn2 = makepath(self.cache_path, 'wsusscn2.cab')
        self._update_session = None
        self._update_service_manager = None
        self._update_searcher = None
        self._offline_update_searcher = None
        self._update_service = None
        self.wapttask = None
        self.rules_packages = None

        #
        self._updates = None
        # to store successful changes in read only properties of _updates after initial scan
        self._cached_updates = {}

        self._installed_updates = None

        if not params:
            params = WaptWUAParams()
            if self.wapt:
                if self.wapt.config and self.wapt.config.has_section('waptwua'):
                    params.load_from_ini(config=self.wapt.config, section='waptwua')
                # else:
                #    windows_updates_rules.load_from_waptdb(self.wapt)
        self.params = params

        if windows_updates_rules:
            self.windows_updates_rules = windows_updates_rules
        else:
            self.load_windows_updates_rules_from_packages()

        self.windows_updates_rules.default_allow = self.params.default_allow

    def load_windows_updates_rules_from_packages(self):
        """Load list of wsus installed packages and load asociated json windows_rules files

        """
        self.windows_updates_rules = WaptWUARules()
        self.windows_updates_rules.load_from_ini(config=self.wapt.config, section='waptwua')
        self.rules_packages = self.wapt.waptdb.query("""select package_uuid,package,version,persistent_dir from wapt_localstatus where section='wsus' and install_status='OK' order by install_date""")
        for p in self.rules_packages:
            if p.get('persistent_dir') and os.path.isdir(p.get('persistent_dir')):
                self.windows_updates_rules.merge_rules_from_files(makepath(p['persistent_dir'], 'waptwua_rules.json'))
            else:
                logger.critical('Bad persistent dir for package %s' % p.get('package'))

    def apply_waptwua_settings_to_host(self):
        """Apply waptwua service specific settings
        """
        try:
            # check waptwua
            if self.wapt.waptwua_enabled:
                print('Disabling Windows auto update service, using WaptWUA instead')
                self.disable_ms_windows_update_service()
            elif self.wapt.waptwua_enabled is not None and not self.wapt.waptwua_enabled:
                print('Enabling Windows update service')
                self.enable_ms_windows_update_service()
        except Exception as e:
            logger.critical('Unable to set waptwua policies : %s' % e)

    def wuarepo(self):
        return self.wapt.wua_repository

    def ensure_minimum_wua_version(self):
        if wua_agent_version() < Version('7.6.7601.23435'):
            raise EWUABadSystem("first use fixwua before standard updating method")
        return True

    def is_allowed(self, update):
        return self.windows_updates_rules.is_allowed(update)

    def cached_update_property(self, update, key, safe=False):
        try:
            if hasattr(update, key):
                update_id = "%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber)
                if update_id in self._cached_updates and key in self._cached_updates[update_id]:
                    return self._cached_updates[update_id][key]
                else:
                    return getattr(update, key, None)
            else:
                return getattr(update, key, None)
        except Exception as e:
            if safe:
                return '???'
            else:
                raise e

    def store_cached_update_property(self, update, key, value):
        update_id = "%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber)
        if not update_id in self._cached_updates:
            self._cached_updates[update_id] = {}
        cached = self._cached_updates[update_id]
        cached[key] = value

    def update_as_dict(self, update):
        """Convert a IUpdate instance into a dict

        Args:
            update (IUpdate)

        Returns:
            dict
        """
        if hasattr(update, 'Categories'):
            products = [c.Name for c in update.Categories if c.Type == 'Product']
            classifications = [c.Name for c in update.Categories if c.Type == 'UpdateClassification']
            # https://docs.microsoft.com/en-us/windows/desktop/api/wuapi/nn-wuapi-iupdate
            result = dict(
                update_id="%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber),
                languages=["%s" % l for l in update.Languages],
                title=update.Title,
                update_type=UpdateType.get(update.Type, update.Type),
                kbids=["%s" % kb for kb in update.KBArticleIDs],
                severity=update.MsrcSeverity,
                changetime=datetime2isodate(datetime.datetime.fromtimestamp(timestamp=update.LastDeploymentChangeTime.timestamp(), tz=update.LastDeploymentChangeTime.tzinfo)),
                product=(products and products[0]) or "",
                classification=(classifications and classifications[0] or ""),
                download_urls=self.get_downloads_for_update(update),
                min_download_size=int(update.MinDownloadSize),
                max_download_size=int(update.MaxDownloadSize),
                superseded_update_ids=["%s" % id for id in update.SupersededUpdateIDs],
                security_bulletin_ids=["%s" % id for id in update.SecurityBulletinIDs],
                cve_ids = ["%s" % id for id in update.CveIDs],
                is_mandatory=update.IsMandatory,
                reboot_behaviour=InstallationRebootBehavior.get(update.InstallationBehavior.RebootBehavior, update.InstallationBehavior.RebootBehavior),
                installation_impact=InstallationImpact.get(update.InstallationBehavior and update.InstallationBehavior.Impact, update.InstallationBehavior and update.InstallationBehavior.Impact),
                uninstallation_impact=InstallationImpact.get(update.UninstallationBehavior and update.UninstallationBehavior.Impact, update.UninstallationBehavior and update.UninstallationBehavior.Impact),
                can_request_user_input=update.InstallationBehavior.CanRequestUserInput,
                requires_network_connectivity=update.InstallationBehavior and update.InstallationBehavior.RequiresNetworkConnectivity,
                is_beta=update.IsBeta,
                is_uninstallable=update.IsUninstallable,
                uninstallation_notes=update.UninstallationNotes,
                support_url=update.SupportUrl,
                release_notes=update.ReleaseNotes,
            )

        else:
            result = dict(
                update_id="%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber),
                languages=None,
                title=update.Title,
                update_type="",
                kbids=[],
                severity="",
                changetime=datetime2isodate(datetime.datetime.fromtimestamp(int(bytes(update.Date)))),
                product="",
                classification="",
                download_urls=None,
                min_download_size=None,
                max_download_size=None,
                superseded_update_ids=None,
                security_bulletin_ids=None,
                is_mandatory=None,
                reboot_behaviour=None,
                can_request_user_input=None,
                requires_network_connectivity=None,
                is_beta=None,
                is_uninstallable=None,
                installation_impact=None,
                uninstallation_impact=None,
                uninstallation_notes=None,
                support_url=None,
                release_notes=None,
            )

        return result

    def update_local_status_as_dict(self, update, updates_history=None,wmi_installed_windows_updates_result=[]):
        """Convert a IUpdate instance into a dict

        Args:
            update (IUpdate)

        Returns:
            dict
        """
        result = dict(
            update_id="%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber),
            installed=self.cached_update_property(update, 'IsInstalled', True),
            present=self.cached_update_property(update, 'IsPresent', True),
            hidden=self.cached_update_property(update, 'IsHidden', True),
            downloaded=self.cached_update_property(update, 'IsDownloaded', True),
            allowed=self.windows_updates_rules.is_allowed(update),
            history=[],
        )

        if updates_history:
            for e in sorted(updates_history, key=lambda h: h['date']):
                if e['update_id'] == result['update_id']:
                    result['history'].append(e)

        status = None
        install_date = None


        delayed = self.params.is_delayed(update)

        if self.cached_update_property(update, 'IsInstalled', True):
            status = 'OK'

            if result['history']:
                e = result['history'][-1]
                if e.get('operation') == 1 and e['result_code'] == 'Succeeded' and e.get('date'):
                    install_date = e.get('date')  # install
            if not install_date:
                for kbw in wmi_installed_windows_updates_result :
                    if 'KB' + ["%s" % kb for kb in update.KBArticleIDs][0] == kbw['HotFixID']:
                        if kbw.get('InstalledOn'):
                            try:
                                install_date = str(datetime.datetime.strptime(kbw['InstalledOn'], '%d/%m/%Y'))
                            except:
                                try:
                                    install_date = str(datetime.datetime.strptime(kbw['InstalledOn'], '%m/%d/%Y'))
                                except:
                                    pass

        elif not self.cached_update_property(update, 'IsInstalled', True) and not update.IsHidden:
            status = 'PENDING'

            if result['history']:
                e = result['history'][-1]
                if e['result_code'] == 'Failed':
                    status = 'ERROR'

        else:
            status = 'DISCARDED'

        result['delayed'] = delayed
        result['status'] = status
        result['install_date'] = install_date

        return result

    def update_history(self):
        """Returns Windows updates installs history

        Args:

        Returns:
            list of dict

        """
        searcher = self.update_searcher()
        history_count = searcher.GetTotalHistoryCount()

        result = None

        if history_count > 0:
            result = []
            for entry in searcher.QueryHistory(0, history_count):
                entry2 = CastTo(entry, 'IUpdateHistoryEntry2')
                result.append(dict(
                    operation=entry2.Operation,
                    update_id="%s_%s" % (entry2.UpdateIdentity.UpdateID, entry2.UpdateIdentity.RevisionNumber),
                    date=datetime2isodate(datetime.datetime.fromtimestamp(timestamp=entry2.Date.timestamp(), tz=entry2.Date.tzinfo)),
                    title=entry2.Title,
                    result_code=OperationResultCode.get(entry2.ResultCode, entry2.ResultCode),
                    application_id=entry2.ClientApplicationID,
                    description=entry2.Description,
                    categories=[c.Name for c in entry2.Categories],
                ))

            result.sort(key=lambda a: a['update_id'])
        return result

    def update_session(self):
        """https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa386854(v=vs.85).aspx

        Returns:
            IUpdateSession
        """
        if self._update_session is None:
            self._update_session = CastTo(win32com_ensure_dispatch_patch("Microsoft.Update.Session"), 'IUpdateSession3')
            self._update_session.UserLocale = int(self.params.user_locale)

        return self._update_session

    def update_service_manager(self):
        """https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa386819(v=vs.85).aspx

        Returns:
            IUpdateServiceManager
        """
        if self._update_service_manager is None:
            self._update_service_manager = CastTo(self.update_session().CreateUpdateServiceManager(), 'IUpdateServiceManager2')
        return self._update_service_manager

    def get_url_wsusscn2cab(self,repo):
        if self.params.direct_download or (repo.repo_url and 'download.windowsupdate.com' in repo.repo_url):
            cab_location = 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab'
        elif repo.repo_url:
            cab_location = '%swua/wsusscn2.cab' % (repo.repo_url.rstrip('/'))
        else:
            return None
        return cab_location


    def get_wsusscn2cab_date_from_server(self, repo, session):
        url = self.get_url_wsusscn2cab(repo)
        if url:
            try:
                r = session.head(
                    url,
                    timeout=self.wuarepo().timeout,
                    allow_redirects=True,
                )
                r.raise_for_status()
                cab_new_date = httpdatetime2isodate(r.headers['last-modified'])
                logger.debug('New wsusscn2cab.cab date : %s' % cab_new_date)
                return cab_new_date
            except Exception as e:
                logger.warning('Unable to get wsusscn2cab.cab date : %s' % e)
                return None
        else:
            return None

    def download_wsusscan_cab(self):
        """Download from wapt server the last version of wsusscn2.cab database for offline update scan.
        """
        repo = self.wuarepo()
        if repo:
            with repo.get_requests_session() as session:
                try:
                    cab_new_date = self.get_wsusscn2cab_date_from_server(repo, session)
                    cab_current_date = ensure_unicode(self.wapt.read_param('waptwua.wsusscn2cab_date'))
                    cab_target = self.wsusscn2
                    if not cab_current_date or not isfile(cab_target) or (cab_new_date > cab_current_date):
                        cab_location = self.get_url_wsusscn2cab(repo)
                        print('Downloading wsusscn2.cab file from %s' % cab_location)
                        if self.params.direct_download or ('download.windowsupdate.com' in repo.repo_url):
                            wget('http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab', cab_target, connect_timeout=self.wuarepo().timeout, requests_session=session, limit_bandwidth=self.wapt.limit_bandwidth)
                        else:
                            sumwsusscn2 = wgets('%s.sha1' % cab_location, requests_session=session).decode('utf8').strip()
                            allowed_sha1_chars = set(string.ascii_letters+ string.digits)
                            if not (set(sumwsusscn2) <= allowed_sha1_chars):
                                error('%s.sha1 is not sha1' % cab_location)
                            wget(cab_location, cab_target, connect_timeout=self.wuarepo().timeout, requests_session=session, sha1=sumwsusscn2, limit_bandwidth=self.wapt.limit_bandwidth)
                        if isfile(makepath(self.wapt.wapt_base_dir, 'utils', 'signtool.exe')):
                            subprocess.check_output(r'"%s" verify /pa "%s"' % (makepath(self.wapt.wapt_base_dir, 'utils', 'signtool.exe'), cab_target))
                        self.wapt.write_param('waptwua.wsusscn2cab_date', cab_new_date)
                        logger.debug('New wusscn2.cab date : %s' % cab_new_date)
                    return cab_new_date
                except Exception as e:
                    self.wapt.write_param('waptwua.status', 'ERROR DOWNLOADING WSUSSCAN')
                    raise e

    def update_wsusscan_cab(self):
        try:
            return self.download_wsusscan_cab()
        except Exception as e:
            if isfile(self.wsusscn2):
                logger.error('Unable to refresh wsusscan cab, using old one. (error: %s)' % ensure_unicode(e))
            else:
                logger.error('Unable to get wsusscan cab, aborting.')
                raise

    def update_searcher(self):
        """Instantiate a updateSearcher instance
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa386515(v=vs.85).aspx

        Returns:
            IUpdateSearcher

        """
        # use wsus offline updates index cab
        if not self._offline_update_searcher:
            print('   Connecting to local update searcher using offline wsusscn2 file...')
            if not os.path.isfile(self.wsusscn2):
                self.download_wsusscan_cab()
            self._update_service = self.update_service_manager().AddScanPackageService("Offline Sync Service", self.wsusscn2)
            self._offline_update_searcher = CastTo(self.update_session().CreateUpdateSearcher(), 'IUpdateSearcher3')
            # use offline only
            self._offline_update_searcher.ServerSelection = 3  # other
            self._offline_update_searcher.IncludePotentiallySupersededUpdates = self.params.include_potentially_superseded_updates
            self._offline_update_searcher.ServiceID = self._update_service.ServiceID
            print('   Offline Update searcher ready...')
        return self._offline_update_searcher

    def updates(self):
        """List of current updates scanned againts wsusscn2 cab and computer
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx

        Returns:
            list of IUpdate
        """
        if self._updates is None:
            self.wapt.write_param('waptwua.status', 'SCANNING')
            try:
                print('Looking for updates with filter: %s' % self.params.filter)
                IID_ISearchCompletedCallback = '{88AEE058-D4B0-4725-A2F1-814A67AE964C}'

                class SearchCallback(MappedWrapPolicy):
                    _com_interfaces_ = [IID_ISearchCompletedCallback]
                    _reg_clsid_ = '{41B032DA-86B5-4907-A7F7-128E59333101}'
                    _reg_progid_ = "wapt.waptwua"

                    #_dispid_to_func_ = {0:'Invoke'}

                    def __init__(self):
                        self._wrap_(self)

                    def _invokeex_(self, dispid, lcid, wFlags, args, kwargs, serviceProvider):
                        print('WUA Search completed !')
                        return 0

                scb = SearchCallback()
                scb_interface = pythoncom.WrapObject(scb)
                search_job = self.update_searcher().BeginSearch(self.params.filter, scb_interface, None)

                estimated_time = float(self.wapt.read_param('waptwua.last_scan_duration', 300.0))
                if estimated_time < 60.0:
                    estimated_time = 300.0
                tick_every = 1.0
                progress_step = 100.0 * tick_every / estimated_time
                start_time = time.time()
                if self.wapttask:
                    self.wapttask.progress = 0.0
                try:
                    print('Waiting for WUA search to complete')
                    if self.wapttask:
                        self.wapttask.runstatus = 'Waiting for WUA search to complete'
                    while True:
                        if search_job.IsCompleted:
                            break
                        if self.wapttask and self.wapttask.wapt:
                            self.wapttask.wapt.check_cancelled()
                        if self.wapttask:
                            self.wapttask.progress += progress_step
                            self.wapttask.runstatus = 'Searching %0.0ds' % (time.time() - start_time,)
                        time.sleep(tick_every)
                    print('Done searching')
                    self.wapt.write_param('waptwua.last_scan_duration', time.time() - start_time)
                finally:
                    search_job.CleanUp()
                    search_result = self.update_searcher().EndSearch(search_job)

                if self.wapttask:
                    self.wapttask.runstatus = 'Done searching'
                    self.wapttask.progress = 100.0

                self._updates = []
                self._cached_updates = {}
                for update in search_result.Updates:
                    update5 = CastTo(update, 'IUpdate5')
                    self._updates.append(update5)
                self.wapt.write_param('waptwua.status', 'READY')
                print('Updates scan done.')
                self.wapt.write_param('waptwua.error_msg', '')
            except Exception as e:
                if self.wapttask:
                    self.wapttask.runstatus = 'Error scanning updates: %s' % ensure_unicode(e)
                    self.wapttask.progress = 100.0
                self.wapt.write_param('waptwua.status', 'ERROR SCANNING UPDATES')
                logger.error('Error scanning updates: %s ' % ensure_unicode(e))
                self.wapt.write_param('waptwua.error_msg',convert_wua_error(ensure_unicode(e)))
                raise

        return self._updates

    def installed_updates(self):
        """Calculate list of installed Update objects.
        Keep it in cache for current session.

        Returns:
            list of IUpdate
        """
        if self._installed_updates is None:
            print('Looking for installed updates')
            self._installed_updates = []
            searcher = self.update_searcher()
            update_count = searcher.GetTotalHistoryCount()
            if update_count > 1:
                for update in searcher.QueryHistory(0, update_count-1):
                    self._installed_updates.append(CastTo(update, 'IUpdateHistoryEntry2'))

        return self._installed_updates

    def scan_updates_status(self, force=False, update_ids=None):
        """Check all updates and filter out which one should be installed

        """
        print('Scanning with windows updates rules:\n%s' % jsondump(self.params, indent=True))
        installed, pending, discarded = 0, 0, 0

        self.update_wsusscan_cab()

        # XXX There are no clear heuristics to tell whether we can bypass scanning or not.
        # Fail safe until we find better.
        if not force and not self.rescan_needed():
            print('Bypassing scan, no change since last successful scan')
            full_stats = self.stored_updates_localstatus()
            if isinstance(full_stats, dict):
                installed = len([u for u in full_stats['updates'] if u['status'] == 'OK'])
                pending = len([u for u in full_stats['updates'] if u['status'] == 'PENDING'])
                discarded = len([u for u in full_stats['updates'] if u['status'] == 'DISCARDED'])
                self.wapt.update_server_status(force=force)
                return (installed, pending, discarded)

        logger.debug('Scanning installed / not installed Updates')
        for update in self.updates():
            self.store_cached_update_property(update, 'IsDownloaded', update.IsDownloaded)

            if not self.cached_update_property(update, 'IsInstalled'):

                if not self.wapt.waptwua_enabled:
                    update.IsHidden = False
                    continue

                if not self.params.is_delayed(update) and self.is_allowed(update) and (update_ids is None or [u for u in update_ids if u.startswith(update.Identity.UpdateID)]):
                    # IUpdate : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386099(v=vs.85).aspx
                    # IUpdate2 : https://msdn.microsoft.com/en-us/library/windows/desktop/aa386100(v=vs.85).aspx
                    if update.IsHidden:
                        print('Enable %s : %s' % (update.Identity.UpdateID, update.Title))
                        update.IsHidden = False
                    pending += 1
                else:
                    if not update.IsHidden:
                        print('Disable %s : %s' % (update.Identity.UpdateID, update.Title))
                        update.IsHidden = True
                    discarded += 1
            else:
                logger.debug('Already installed %s : %s' % (update.Identity.UpdateID, update.Title))
                installed += 1

        self.wapt.write_param('waptwua.rules_packages', self.rules_packages)

        try:
            _update_history = self.update_history()
            if _update_history is not None:
                self.wapt.write_param('waptwua.update_history', _update_history)
            else:
                _update_history = self.wapt.read_param('waptwua.update_history')
        except Exception as e:
            logger.warning('WARNING: Unable to get windows update history: %s' % ensure_unicode(e))
            # better don't store this than nothing at all.
            # can get com_error when scanning this. ( -2145120257 )
            # self.wapt.delete_param('waptwua.update_history')
            _update_history = self.wapt.read_param('waptwua.update_history')

        dict_all_updates = {}
        for u in self.updates():
            dict_all_updates[self.update_as_dict(u)["update_id"]] = self.update_as_dict(u)

        wmi_installed_windows_updates_result = installed_windows_updates()
        dict_update_status = {}
        for u in self.updates():
            dict_update_status[self.update_local_status_as_dict(u, _update_history,wmi_installed_windows_updates_result=wmi_installed_windows_updates_result)['update_id']] = self.update_local_status_as_dict(u, _update_history,wmi_installed_windows_updates_result=wmi_installed_windows_updates_result)

        if self.params.include_potentially_superseded_updates :

            def set_status_supersed(uid,data,force):
                for entry in data:
                    if entry.split('_')[0] == uid:

                        if (not data[entry]['installed']) or force or (data[entry]['status'] == 'DISCARDED') :
                            data[entry]['status'] = 'SUPERSEDED'

                        if data[entry]['installed']:
                            force = True

                        for nuid in dict_all_updates[entry]["superseded_update_ids"]:
                            set_status_supersed(nuid,data,force)

            for entry in dict_update_status:
                if dict_update_status[entry]['status'] == "PENDING" or dict_update_status[entry]['installed']:
                    for uid in dict_all_updates[entry]["superseded_update_ids"]:
                        force = dict_update_status[entry]['installed']
                        set_status_supersed(uid,dict_update_status,force)

        error_status = False
        pending = False
        for update in self.updates():
            upid = '%s_%s' % (update.Identity.UpdateID, update.Identity.RevisionNumber)
            if dict_update_status[upid]['status'] in ['SUPERSEDED','DISCARDED']:
                update.IsHidden = True
                dict_update_status[upid]['allowed'] = False
            else:
                update.IsHidden = False
                if dict_update_status[upid]['status'] == "PENDING":
                    pending = True
                if dict_update_status[upid]['status'] == "ERROR":
                    error_status=True


        print('Writing status in local wapt DB')
        self.wapt.write_param('waptwua.last_scan_date', datetime2isodate())
        if error_status:
            self.wapt.write_param('waptwua.status', 'ERROR')
        else:
            if pending :
                self.wapt.write_param('waptwua.status', 'PENDING_UPDATES')
            else:
                self.wapt.write_param('waptwua.status', 'OK')

        self.wapt.write_param('waptwua.updates_localstatus', [dict_update_status[u] for u in dict_update_status])

        self.wapt.write_param('waptwua.updates', [self.update_as_dict(u) for u in self.updates()])
        self.write_last_successful_scan_signature()

        # send status to wapt server
        logger.debug('Updating workstation status on remote wapt server')

        dict_id_description = {}
        # Dict kb description with wua
        list_update_ids_installed = []
        wmi_installed_windows_updates_result = installed_windows_updates()
        for u in self.updates():
            if self.update_local_status_as_dict(u,wmi_installed_windows_updates_result = wmi_installed_windows_updates_result)['installed']:
                list_update_ids_installed.append(self.update_local_status_as_dict(u,wmi_installed_windows_updates_result = wmi_installed_windows_updates_result)['update_id'])

        for u in self.updates():
            if self.update_as_dict(u)['update_id'] in list_update_ids_installed:
                dict_id_description['KB%s' % self.update_as_dict(u)['kbids'][0]] = self.update_as_dict(u)['title']

        # update with wmi liste
        for u in installed_windows_updates():
            if not u['HotFixID'] in dict_id_description:
                dict_id_description[u['HotFixID']] = u['Description']

        self.wapt.write_param('waptwua.simple.list', dict_id_description)

        self.wapt.update_server_status(force=force)
        return (installed, pending, discarded)

    def rescan_needed(self):
        """Check if a rescan of Windows updates status is needed.
        * rules have changed
        * wsuscan2 file has been updated
        * updates installation history has changed

        Returns:
            bool: True if rule or updates index or installed updates
        """


        lastscan_params_cksum = self.wapt.read_param('waptwua.params_cksum')

        if lastscan_params_cksum != hashlib.sha1(bytes(jsondump_sorted(self.windows_updates_rules)+jsondump_sorted(self.params), 'utf-8')).hexdigest():
            print('Windows updates rules have been changed')
            return True
        # check if some other tools have installed / uninstalled some QFE
        try:
            update_history = self.update_history()
            update_history_checksum = hashlib.sha1(bytes(jsondump_sorted(update_history), 'utf8')).hexdigest()
            old_cksum = self.wapt.read_param('waptwua.update_history_checksum')
            if update_history_checksum != old_cksum:
                print('Some windows updates have been installed/uninstalled since last scan')
                return True
        except:
            logger.error('Unable to get update_history')
            return True

        # check if MS updates scan file have changed

        if not os.path.exists(self.wsusscn2):
            raise Exception('Unexpected: missing scan file %s' % self.wsusscn2)
        new_hash = sha1_for_file(self.wsusscn2)
        old_hash = self.wapt.read_param('waptwua.wsusscn2_checksum')
        if old_hash != new_hash:
            print('WSUSscan2.cab file has changed since last scan')
        return old_hash != new_hash

    def write_last_successful_scan_signature(self):
        """Write in local db a signature which should change
        if rules or needed updates or installed updates have changed
        """
        cksum = sha1_for_file(self.wsusscn2)

        self.wapt.write_param('waptwua.wsusscn2_checksum', cksum)
        update_history = self.wapt.read_param('waptwua.update_history', ptype='json')
        if not update_history:
            try:
                update_history = self.update_history()
                self.wapt.write_param('waptwua.update_history', update_history)
            except Exception:
                logger.error('Unable to get update_history')
        if update_history:
            cksum = hashlib.sha1(bytes(jsondump_sorted(update_history), 'utf8')).hexdigest()
            self.wapt.write_param('waptwua.update_history_checksum', cksum)

        self.windows_updates_rules.save_to_waptdb(self.wapt)
        self.params.save_to_waptdb(self.wapt)
        self.wapt.write_param('waptwua.params_cksum', hashlib.sha1(bytes(jsondump_sorted(self.windows_updates_rules)+jsondump_sorted(self.params), 'utf8')).hexdigest())

    def wget_update(self, url):
        # try using specialized proxy
        url_parts = urlparse(url)
        target = makepath(self.cache_path, os.path.split(url)[1])
        filename = os.path.split(url)[1]
        repo = self.wuarepo()
        if repo:
            repo_parts = urlparse(repo.repo_url)
        else:
            repo_parts = None

        if repo:
            with repo.get_requests_session() as session:
                # direct download of prefetched cab

                if self.params.direct_download or ('download.windowsupdate.com' in repo.repo_url):
                    print("Downloading %s" % url)
                    wget(url, target,
                         verify_cert=True,
                         resume=True,
                         connect_timeout=self.wuarepo().timeout,
                         sha1=get_sha1_from_filename(url_parts.path),  # MS Cabs have sometime the sha1 in the filename, just before the extension : pciclearstalecache_1d566f78af356cc09c83cf173dc734c66659e0d2.exe
                         proxies=repo.proxies,
                         cache_dir=self.cache_path,
                         limit_bandwidth=self.wapt.limit_bandwidth
                         )

                else:
                    patch_url = '%s://%s%swua/%s' % (repo_parts.scheme, repo_parts.netloc, repo_parts.path.rstrip('/'), filename)
                    print("Downloading %s" % patch_url)
                    wget(patch_url, target,
                         resume=True,
                         connect_timeout=repo.timeout,
                         sha1=get_sha1_from_filename(url_parts.path),  # MS Cabs have sometime the sha1 in the filename, just before the extension : pciclearstalecache_1d566f78af356cc09c83cf173dc734c66659e0d2.exe
                         cache_dir=self.cache_path,
                         requests_session=session,
                         limit_bandwidth=self.wapt.limit_bandwidth
                         )

        return target

    def _check_disk_space(self):
        if wmi:
            for d in wmi.WMI().Win32_LogicalDisk():
                device = d.Name
                if device == os.environ['SystemDrive'] and int(d.FreeSpace) < 2 ** 30:
                    raise WAPTDiskSpaceException('Not enough space left on device ' + device, d.FreeSpace)

    def get_downloads_for_update(self, update):
        """Returns all the URL to download for the upadte

        Returns:
            list
        """
        result = []
        for dc in update.DownloadContents:
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
            if authorized_url_wsus(dc.DownloadUrl):
                result.append(dc.DownloadUrl)

        for bu in update.BundledUpdates:
            win32com_ensure_dispatch_patch('Microsoft.Update.StringColl')
            for dc in bu.DownloadContents:
                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                if authorized_url_wsus(dc.DownloadUrl):
                    result.append(dc.DownloadUrl)
        return result

    def missing_files_in_cache(self, update):
        """Returns the list of URL

        Returns:
            list of str (url)
        """
        result = []
        downloads = self.get_downloads_for_update(update)
        for url in downloads:
            target = makepath(self.cache_path, os.path.split(url)[1])
            if not os.path.isfile(target):
                result.append(url)
        return result

    def download_single(self, update):
        """Download the files associated to an IUpdate instance
        Direct content
        Bundled content

        Args:
            update (IUpdate): update

        Returns:
            dict(downloaded=result,missing=missing_urls)

        """

        def purge_waptwua_cache(files):
            """Removes files from wapt\cache\waptwua"""
            for fn in list(files):
                try:
                    os.remove(fn)
                except Exception:
                    logger.error('Unable to delete cached file %s' % fn)

        result = []
        missing_urls = []

        self._check_disk_space()

        update = CastTo(update, 'IUpdate5')

        for dc in update.DownloadContents:
            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
            files = win32com_ensure_dispatch_patch('Microsoft.Update.StringColl')
            try:
                print("Downloading %s" % dc.DownloadUrl)
                target = self.wget_update(dc.DownloadUrl)
            except Exception as e:
                missing_urls.append(dc.DownloadUrl)
                logger.error("ERROR: skipping download %s, reason: %s" % (dc.DownloadUrl, ensure_unicode(e)))
                continue

            result.append(dc.DownloadUrl)
            if isfile(target):
                files.Add(target)

            for fn in files:
                print("%s will be put to local WUA cache for update" % (fn,))
                # if isfile(fn):
                #    remove_file(fn)

            if len(list(files)) > 0:
                try:
                    print('Copying %s downloaded files to MS Wua cache' % files.Count)
                    update.CopyToCache(files)
                    purge_waptwua_cache(files)
                except Exception as e:
                    logger.error("ERROR: unable to push some update files in Windows cache reason: %s" % (ensure_unicode(e),))

        for bu in update.BundledUpdates:
            bu = CastTo(bu, 'IUpdate5')
            files = win32com_ensure_dispatch_patch('Microsoft.Update.StringColl')
            for dc in bu.DownloadContents:
                # https://msdn.microsoft.com/en-us/library/windows/desktop/aa386120(v=vs.85).aspx
                try:
                    target = self.wget_update(dc.DownloadUrl)
                    result.append(dc.DownloadUrl)
                except Exception as e:
                    logger.error("ERROR: skipping download %s, reason: %s" % (dc.DownloadUrl, ensure_unicode(e)))
                    missing_urls.append(dc.DownloadUrl)
                    continue
                if isfile(target):
                    files.Add(target)

            for fn in files:
                print("%s put to local WUA cache for update" % (fn,))

            if len(list(files)) > 0:
                try:
                    print('Copying %s downloaded files to MS Wua cache' % files.Count)
                    bu.CopyToCache(files)
                    purge_waptwua_cache(files)
                except Exception as e:
                    logger.error("ERROR: unable to push update files in Windows cache, reason: %s" % (ensure_unicode(e),))

        if missing_urls:
            self.store_cached_update_property(update, 'IsDownloaded', False)
        else:
            self.store_cached_update_property(update, 'IsDownloaded', True)

        return dict(downloaded=result, missing=missing_urls)

    def missing_downloads(self):
        to_install = [u['update_id'] for u in self.stored_updates_localstatus() if not u['installed'] and not u['downloaded'] and u['allowed']]
        if to_install:
            updates_urls = {u['update_id']: u['download_urls'] for u in self.stored_updates()}
            result = []
            for u in to_install:
                urls = updates_urls[u]
                for url in urls:
                    if not url in result:
                        result.append(url)
            return result
        else:
            return None

    def download_updates(self, force=False, uuids=None):
        """Download all pending updates and put them in Windows Update cache

        Args:
            force (bool) : download update even if update is tagged as donwloaded.
            uuids (list of str) : list of update_id for which to download files.
                                  if None, download all missing files for allowed not installed updates.

        Returns:
            dict (downloaded=[], missing=[])

        """
        self.scan_updates_status()
        result = dict(downloaded=[], missing=[])
        if not self.wapt.waptwua_enabled:
            print('Scan only Waptwua is not activated')
            return result
        try:
            missing = self.missing_downloads()
            if missing is not None:
                # download only in wapt cache
                missing_urls = []
                for url in missing:
                    try:
                        print("Downloading %s" % url)
                        self.wget_update(url)
                    except Exception as e:
                        missing_urls.append(url)
                        logger.error("ERROR: skipping download %s, reason: %s" % (url, ensure_unicode(e)))
                        continue
                result["missing"] = missing_urls
            self.wapt.write_param('waptwua.missing_downloads', result['missing'])
            self.wapt.write_param('waptwua.error_msg', '')
        except WAPTDiskSpaceException:
            logger.error('Disk Space Error')
            self.wapt.write_param('waptwua.last_error_msg', 'Disk Space Error')
            self.wapt.write_param('waptwua.status', 'DISK_SPACE_ERROR')
        except Exception as e:
            logger.error('Unexpected error: %s' % convert_wua_error( ensure_unicode(e)))
            self.wapt.write_param('waptwua.last_error_msg',convert_wua_error( ensure_unicode(e)))
            self.wapt.write_param('waptwua.status', 'ERROR')
            self.wapt.write_param('waptwua.error_msg',convert_wua_error(ensure_unicode(e)))
        self.wapt.update_server_status()
        return result

    def install_updates(self, force=False, uuids=None):
        """Install all pending allowded updates or updates specified in uuids arg.
        If update is not yet downloaded, a downloaded is triggered.
        Results are stored in local db and sent to server database.

        Args:
            force (bool) : install update even if update is tagged as installed.
            uuids (list of str) : list of update_id to install.
                                  if None, all allowed not installed updates are installed.

        Returns:
            list of str: list of UpdateId of triggered installed updates

        """
        result = []
        if not self.wapt.waptwua_enabled:
            print('Forbiden : Waptwua is not activated')
            return result
        self.scan_updates_status()

        if uuids is not None:
            print('Start of Windows updates install for: %s' % uuids)
        else:
            print('Start of install for all pending Windows updates')
        print('Scanning with params:\n%s' % jsondump(self.params, indent=True))
        print('Scanning with windows updates rules:\n%s' % jsondump(self.windows_updates_rules, indent=True))


        try:
            self.wapt.write_param('waptwua.status', 'INSTALL')
            updates_to_install = win32com_ensure_dispatch_patch("Microsoft.Update.UpdateColl")
            updates_to_install_list = []
            # apply the updates
            for update in self.updates():
                if (not update.IsHidden) and (uuids is None or [u for u in uuids if u.startswith(update.Identity.UpdateID)]) and not update.IsInstalled:
                    if not update.IsDownloaded:
                        res = self.download_single(update)
                        if res['missing']:
                            logger.warning('Missing update packages: %s' % res['missing'])
                            continue
                    print('Adding %s to the list of updates to install...' % update.Identity.UpdateID)
                    update.AcceptEula()
                    update.IsHidden = False
                    updates_to_install.Add(update)
                    updates_to_install_list.append(update)
                    result.append("%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber))
                elif not update.IsInstalled and update.IsHidden and self.wapt.waptwua_enabled:
                    print('Denied %s : %s' % (update.Identity.UpdateID, update.Title))
                else:
                    update.IsHidden = True
                    print('Skipped %s : %s' % (update.Identity.UpdateID, update.Title))

            if result:
                start_install_time = time.time()
                installer = self.update_session().CreateUpdateInstaller()
                installer.Updates = updates_to_install
                if installer.RebootRequiredBeforeInstallation:
                    raise EWUARebootNeeded('Reboot is needed before installing Windows updates')
                installer.AllowSourcePrompts = False
                installer.IsForced = force
                print('Launching the install of %s updates' % len(result))

                IID_IInstallationProgressChangedCallback = '{E01402D5-F8DA-43BA-A012-38894BD048F1}'
                IID_IInstallationCompletedCallback = '{45F4F6F3-D602-4F98-9A8A-3EFA152AD2D3}'

                class InstallationProgressChangedCallback(EventHandlerPolicy):
                    _public_methods_ = []
                    _com_interfaces_ = [IID_IInstallationProgressChangedCallback]

                    _reg_clsid_ = '{41B032DA-86B5-4907-A7F7-128E59333011}'
                    _reg_progid_ = "wapt.waptwua"

                    def __init__(self, wapt):
                        self._wrap_(self)
                        self.wapt = wapt

                    def _invokeex_(self, dispid, lcid, wFlags, args, kwargs, serviceProvider):
                        try:
                            installJob = win32com_ensure_dispatch_patch(args[0])
                            callbackArgs = win32com_ensure_dispatch_patch(args[1])
                            local_progress = callbackArgs.Progress
                            current_progress = local_progress.CurrentUpdateIndex+1
                            max_progress = len(result)

                            msg = 'Installing update %s / %s %s%% completed' % (current_progress, max_progress, local_progress.PercentComplete)

                            if self.wapttask and max_progress:
                                self.wapttask.progress = current_progress * 100.0 / max_progress
                                self.wapttask.runstatus = msg

                            if self.wapt.progress_hook is None:
                                print(msg)
                            else:
                                cancel_request = self.wapt.progress_hook(True, msg, current_progress, max_progress)
                                if cancel_request:
                                    print('Cancel Windows updates install requested')
                                    installJob.RequestAbort()

                        except:
                            pass

                        return 0

                class InstallationCompletedCallback(DesignatedWrapPolicy):
                    _public_methods_ = []
                    _com_interfaces_ = [IID_IInstallationCompletedCallback]

                    _reg_clsid_ = '{41B032DA-86B5-4907-A7F7-128E59333013}'
                    _reg_progid_ = "wapt.waptwua"

                    def __init__(self):
                        self._wrap_(self)

                    # dispid, lcid, wFlags, args
                    def _invokeex_(self, dispid, lcid, wFlags, args, kwargs, serviceProvider):
                        print('Install completed !')
                        return 0

                scb = InstallationProgressChangedCallback(self.wapt)
                scb_com = pythoncom.WrapObject(scb)

                dcb = InstallationCompletedCallback()
                dcb_com = pythoncom.WrapObject(dcb)

                # TODO: calculate estimated time
                estimated_time = float(self.wapt.read_param('waptwua.last_install_duration', 600.0))
                if estimated_time < 60.0:
                    estimated_time = 600.0
                tick_every = 1.0
                progress_step = 100.0 * tick_every / estimated_time
                start_time = time.time()

                install_job = installer.BeginInstall(scb_com, dcb_com, None)
                try:
                    print('Waiting for install to complete', end='')
                    while True:
                        if install_job.IsCompleted:
                            break
                        if self.wapttask and self.wapttask.wapt:
                            self.wapttask.wapt.check_cancelled()
                        if self.wapttask:
                            self.wapttask.progress += progress_step
                            self.wapttask.runstatus = 'Installing %0.0ds' % (time.time() - start_time,)
                        time.sleep(tick_every)

                    print('Done installing')
                finally:
                    install_job.CleanUp()
                    installation_result = installer.EndInstall(install_job)

                print("Install result: %s" % InstallResult.get(installation_result.ResultCode, installation_result.ResultCode))
                print("Reboot required: %s" % installation_result.RebootRequired)
                self.write_install_status_for_windows(installation_result.ResultCode)
                self.wapt.write_param('waptwua.last_install_duration', time.time() - start_install_time)
                self.wapt.write_param('waptwua.last_install_reboot_required', installation_result.RebootRequired)
                self.wapt.write_param('waptwua.last_install_result', InstallResult[installation_result.ResultCode])
                if installation_result.ResultCode in [3, 4, 5]:
                    self.wapt.write_param('waptwua.status', 'ERROR')
                else:
                    # assume all is installed for the next report...
                    for update in updates_to_install_list:
                        self.store_cached_update_property(update, 'IsInstalled', True)

            else:
                self.wapt.write_param('waptwua.last_install_reboot_required', False)
                self.wapt.write_param('waptwua.last_install_result', None)

            self.wapt.write_param('waptwua.last_install_batch', result)
            self.wapt.write_param('waptwua.last_install_date', datetime2isodate())
            self.wapt.write_param('waptwua.error_msg', '')
            self.scan_updates_status()
        except WAPTDiskSpaceException:
            self.wapt.write_param('waptwua.status', 'DISK_SPACE_ERROR')
            self.wapt.write_param('waptwua.error_msg', 'Not enough free disk space')
            logger.error('Disk Space Error')
        except Exception as e:
            self.wapt.write_param('waptwua.status', 'ERROR')
            self.wapt.write_param('waptwua.error_msg',convert_wua_error( ensure_unicode(e)))
            logger.error("ERROR installing update: %s" % convert_wua_error(ensure_unicode(e)))
        self.wapt.update_server_status()
        return result

    def uninstall_updates(self, force=False, uuids=[]):
        """Uninstall a liste of updates specified by its uuids arg.

        Args:
            force (bool) : install update even if update is tagged as installed.
            uuids (list of str) : list of update_id to uninstall.

        Returns:
            list of str: list of UpdateId of triggered installed updates

        """
        result = []
        self.update_wsusscan_cab()

        print('Start of Windows updates uninstall for: %s' % uuids)

        print('Scanning with params:\n%s' % jsondump(self.params, indent=True))
        print('Scanning with windows updates rules:\n%s' % jsondump(self.windows_updates_rules, indent=True))

        try:
            self.wapt.write_param('waptwua.status', 'INSTALL')
            win32com_ensure_dispatch_patch("Microsoft.Update.UpdateColl")
            updates_to_uninstall_list = []

            # apply the updates
            for update in self.updates():
                if [u for u in uuids if u.startswith(update.Identity.UpdateID)] and update.IsInstalled:
                    print('Adding %s to the list of updates to uninstall...' % update.Identity.UpdateID)
                    update.IsHidden = True
                    # updates_to_uninstall.Add(update)
                    updates_to_uninstall_list.append(update)
                    result.append("%s_%s" % (update.Identity.UpdateID, update.Identity.RevisionNumber))

            if result:
                #start_install_time = time.time()
                errors = []

                for update in updates_to_uninstall_list:
                    with disable_file_system_redirection():
                        try:
                            kbids = ["%s" % kb for kb in update.KBArticleIDs]
                            if windows_version() > WindowsVersions.Windows7:
                                dism_data = get_kb_dism_name()
                                for kb in kbids:
                                    if 'kb' + kb.lower() in dism_data:
                                        run("'%s' /Online /Remove-Package /PackageName:%s /Quiet /NoRestart" % (makepath(system32(), 'Dism.exe'), dism_data['kb' + kb.lower()]), timeout=900)
                                        self.store_cached_update_property(update, 'IsInstalled', False)
                                    else:
                                        error = "%s is not available for uninstallation" % ("kb" + kb)
                                        errors.append(error)
                                        logger.warning('Unable to uninstall %s' % error)
                            else:
                                for kb in kbids:
                                    run('"%s" /kb:%s /uninstall /quiet /norestart' % (makepath(system32(), 'wusa.exe'), kb))
                                    self.store_cached_update_property(update, 'IsInstalled', False)
                        except Exception as e:
                            error = '%s / %s : %s' % (update.Identity.UpdateID, kbids,convert_wua_error( ensure_unicode(e)))
                            errors.append(error)
                            logger.warning('Unable to uninstall %s' % error)

                    if errors:
                        self.wapt.write_param('waptwua.status', 'ERROR')
                        self.wapt.write_param('waptwua.error_msg', errors)

        except WAPTDiskSpaceException:
            self.wapt.write_param('waptwua.status', 'DISK_SPACE_ERROR')
            self.wapt.write_param('waptwua.error_msg', 'Not enough free disk space')
            logger.error('Disk Space Error')
        except Exception as e:
            self.wapt.write_param('waptwua.status', 'ERROR')
            self.wapt.write_param('waptwua.error_msg',convert_wua_error( ensure_unicode(e)))
            logger.error("ERROR uninstalling update: %s" % convert_wua_error(ensure_unicode(e)))
        finally:
            self.scan_updates_status()
        self.wapt.update_server_status()
        return result

    def stored_waptwua_status(self):
        """Returns the status of Wapt WUA agent as reported in local WaptDB by the last scan operation

        Returns:
            dict
        """
        return {
            'enabled': self.wapt.waptwua_enabled,
            'status': self.wapt.read_param('waptwua.status', None),
            'wsusscn2cab_date': self.wapt.read_param('waptwua.wsusscn2cab_date', None),
            'last_scan_date': self.wapt.read_param('waptwua.last_scan_date', None),
            'last_scan_duration': self.wapt.read_param('waptwua.last_scan_duration', None),
            'last_install_batch': self.wapt.read_param('waptwua.last_install_batch', [], ptype='json'),
            'last_install_date': self.wapt.read_param('waptwua.last_install_date', None),
            'last_install_result': self.wapt.read_param('waptwua.last_install_result', None),
            'last_install_reboot_required': self.wapt.read_param('waptwua.last_install_rebootrequired', None),
            'missing_downloads': self.wapt.read_param('waptwua.missing_downloads', None, ptype='json'),
            'rules_packages': self.wapt.read_param('waptwua.rules_packages', None, ptype='json'),
            'last_error': self.wapt.read_param('waptwua.error_msg')
        }

    def stored_waptwua_rules(self):
        """Returns the status of Wapt WUA agent as reported in local WaptDB by the last scan operation

        Returns:
            dict
        """
        return {
            'windows_updates_rules': WaptWUARules().load_from_waptdb(self.wapt).as_dict(),
            'params': WaptWUAParams().load_from_waptdb(self.wapt).as_dict(),
        }

    def stored_updates_localstatus(self):
        """Returns the list of Windows updates with their status for this computer
        as reported in local DB by the last scan/download/install operation.

        Returns:
            list
        """
        return self.wapt.read_param('waptwua.updates_localstatus', [], ptype='json')

    def stored_updates(self):
        """Returns the list of potentially applicable Windows updates for this computer
        with details extracted from Wsusscan2 cab file by the IUpdateSearcher
        Windows process.

        Returns:
            list
        """
        return self.wapt.read_param('waptwua.updates', [], ptype='json')

    def write_scan_status_for_windows(self, last_error_code=0,):
        """Update windows configuration panel registry with update result

        [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect]
        "LastSuccessTime"="2016-12-23 15:59:32"
        "LastError"=dword:00000000
        """
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect', "LastError", last_error_code, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect', "LastSuccessTime", datetime_for_reg())

    def write_download_status_for_windows(self, last_error_code=0,):
        """Update windows configuration panel registry with update result
        [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download]
        "LastSuccessTime"="2016-11-10 16:24:29"
        "LastError"=dword:00000000
        """
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download', "LastError", last_error_code, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download', "LastSuccessTime", datetime_for_reg())

    def write_install_status_for_windows(self, last_error_code=0,):
        """Update windows configuration panel registry with update result
        [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install]
        "LastSuccessTime"="2016-11-11 02:00:43"
        "LastError"=dword:00000000
        """
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install', "LastError", last_error_code, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install', "LastSuccessTime", datetime_for_reg())

    def disable_ms_windows_update_service(self):
        """Set windows update service in disabled state and disable external Windows Update source"""
        """
        [HKEY_LOCAL_MACHINE\SYSTEM\Internet Communication Management\Internet Communication]
        "DisableWindowsUpdateAccess"=dword:00000001

        [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
            "DeferUpgrade"=dword:00000001
            "DeferUpgradePeriod"=dword:00000001
            "DeferUpdatePeriod"=dword:00000000
            "ExcludeWUDriversInQualityUpdate"=dword:00000001
            "DisableOSUpgrade"=dword:00000001
            "DisableWindowsUpdateAccess"=dword:00000001
            "WUServer"="http://127.0.0.1:8088"
            "WUStatusServer"="http://127.0.0.1:8088"
            "UpdateServiceUrlAlternate"="http://127.0.0.1:8088"
            "FillEmptyContentUrls"=dword:00000001
            "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection"=dword:00000001
            "SetProxyBehaviorForUpdateDetection"=dword:00000000
            "DoNotConnectToWindowsUpdateInternetLocations"=dword:00000001

        [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
            "NoAutoUpdate"=dword:00000001
            "AUOptions"=dword:00000002
            "ScheduledInstallDay"=dword:00000000
            "ScheduledInstallTime"=dword:00000003
            "UseWUServer"=dword:00000001
        """

        registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Gwx', 'DisableGwx', 1, REG_DWORD)

        registry_set(HKEY_LOCAL_MACHINE, r'SYSTEM\Internet Communication Management\Internet Communication', 'DisableWindowsUpdateAccess'              , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'DisableWindowsUpdateAccess'             , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'UseWUServer'                            , 1, REG_DWORD)


        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DeferUpdatePeriod"                                     , 0, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "SetProxyBehaviorForUpdateDetection"                    , 0, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DoNotConnectToWindowsUpdateInternetLocations"          , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DeferUpgrade"                                          , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DeferUpgradePeriod"                                    , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ExcludeWUDriversInQualityUpdate"                       , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DisableWindowsUpdateAccess"                            , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection", 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "DisableOSUpgrade"                                      , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "FillEmptyContentUrls"                                  , 1, REG_DWORD)
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer"                                              , "http://127.0.0.1:8088")
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUStatusServer"                                        , "http://127.0.0.1:8088")
        registry_set(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "UpdateServiceUrlAlternate"                             , "http://127.0.0.1:8088")


        if wmi:
            c = wmi.WMI()
            for service in c.Win32_Service(Name='wuauserv'):
                # https://msdn.microsoft.com/en-us/library/aa384896(v=vs.85).aspx
                service.ChangeStartMode(StartMode="Disabled")
                # don't stop if in contextual EnsureWUAUServRunning
                if service.Started and (not hasattr(self, 'old_au_options') or self.old_au_options is None):
                    service.StopService()

    def enable_ms_windows_update_service(self):

        if registry_readstring(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "UpdateServiceUrlAlternate") == 'http://127.0.0.1:8088':
            registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Gwx', 'DisableGwx', 0, REG_DWORD)

            registry_set(HKEY_LOCAL_MACHINE, r'SYSTEM\Internet Communication Management\Internet Communication', 'DisableWindowsUpdateAccess'              , 0, REG_DWORD)
            registry_set(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'DisableWindowsUpdateAccess'             , 0, REG_DWORD)
            registry_set(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'UseWUServer'                            , 0, REG_DWORD)

            registry_deletekey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")
            registry_deletekey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate")
            registry_set(HKEY_LOCAL_MACHINE, r'SYSTEM\Internet Communication Management\Internet Communication', 'DisableWindowsUpdateAccess', 0, REG_DWORD)
            registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'DisableOSUpgrade', 0, REG_DWORD)
            registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'DisableWindowsUpdateAccess', 0, REG_DWORD)
            registry_set(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions', 2, REG_DWORD)

        if wmi:
            c = wmi.WMI()
            for service in c.Win32_Service(Name='wuauserv'):
                # https://msdn.microsoft.com/en-us/library/aa384896(v=vs.85).aspx
                service.ChangeStartMode(StartMode="Automatic")
                # don't restart if in contextual EnsureWUAUServRunning
                if not service.Started and (not hasattr(self, 'old_au_options') or self.old_au_options is None):
                    service.StartService()

    # nom_params_serveur = ['WUServer','WUStatusServer']
    # tableau des variables de config et de la valeur attribuee
    # nom_params_config = [('NoAutoRebootWithLoggedOnUsers',1),('UseWUServer',1),('RescheduleWaitTime',5),('NoAutoUpdate',0),('AUOptions',4),('ScheduledInstallDay',0),('ScheduledInstallTime',wsusheure)]

    def get_wuauserv_status(self):
        return dict(
            start_mode=registry_readstring(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\services\wuauserv', 'Start', None),
            running=service_is_running('wuauserv'),
            auto_update=registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update', 'AUOptions'),
            use_wuserver=registry_readstring(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'UseWUServer', None),
            disable_os_upgrade=registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'DisableOSUpgrade', None),
            disable_access=registry_readstring(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', 'DisableWindowsUpdateAccess', None),
            policy_disable_access=registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'DisableWindowsUpdateAccess', None),
            gwx_disable=registry_readstring(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Gwx', 'DisableGwx', None),
            reboot_needed=waiting_for_reboot(),
            agent_version=get_file_properties(makepath(system32(), 'wuapi.dll'))['ProductVersion'],
        )

    def summary_status(self):
        stat = self.stored_waptwua_status()
        updates_localstatus = self.stored_updates_localstatus()

        stat['installed'] = len([u for u in updates_localstatus if u['status'] == 'OK'])
        stat['pending'] = len([u for u in updates_localstatus if u['status'] == 'PENDING'])
        stat['discarded'] = len([u for u in updates_localstatus if u['status'] == 'DISCARDED'])
        if stat['pending'] > 0:
            stat['status'] = stat['status']+', %s pending' % stat['pending']
        if stat['discarded'] > 0:
            stat['status'] = stat['status']+', %s discarded' % stat['discarded']

        return """\
Status:            %(status)s

Installed updates: %(installed)s
Pending updates:   %(pending)s
Discarded updates: %(discarded)s
Reboot required:   %(last_install_reboot_required)s

Last install date:   %(last_install_date)s
Last install result: %(last_install_result)s

WSUSScan cab date: %(wsusscn2cab_date)s
        """ % stat


def summary_waptwua_status(wapt):
    wua = WaptWUA(wapt)
    return wua.summary_status()


if __name__ == '__main__':
    # we import only if called as a command line utility.
    # else circular reference.
    from common import Wapt

    def_allowed_updates = None
    def_forbidden_updates = None
    def_allowed_severities = None
    def_allowed_classifications = None

    parser = OptionParser(usage=__doc__)
    parser.add_option("-S", "--severities", dest="allowed_severities", default=def_allowed_severities, help="Allow updates by severity. csv list of Critical,Important,Moderate,Low. If empty : allow all. (default: %default)")
    parser.add_option("-C", "--classifications", dest="allowed_classifications", default=def_allowed_classifications, help="Allow updates by claffication. csv list of "+','.join(list(UpdateClassifications.values()))+". If empty : allow all. (default: %default)")
    parser.add_option("-a", "--allowed", dest="allowed_updates", default=def_allowed_updates, help="Allow updates by update-id or KB. csv list of id to allow (default: %default)")
    parser.add_option("-b", "--forbidden", dest="forbidden_updates", default=def_forbidden_updates, help="Forbid updates by update-id or KB. csv list (default: %default)")
    parser.add_option("-c", "--config", dest="config", default=None, help="Config file full path (default: %default)")
    parser.add_option("-l", "--loglevel", dest="loglevel", default=None, type='choice',  choices=['debug', 'warning', 'info', 'error', 'critical'], metavar='LOGLEVEL', help="Loglevel (default: warning)")
    parser.add_option("-f", "--force", dest="force", default=False, action='store_true', help="Force scan even if last scan signature has not changed (default: %default)")

    (options, args) = parser.parse_args()

    logging.basicConfig(format='%(asctime)s [%(name)-15s] %(levelname)s %(message)s')

    def setloglevel(logger, loglevel):
        """set loglevel as string"""
        if loglevel in ('debug', 'warning', 'info', 'error', 'critical'):
            numeric_level = getattr(logging, loglevel.upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError('Invalid log level: {}'.format(loglevel))
            logger.setLevel(numeric_level)

    # force loglevel
    if options.loglevel is not None:
        setloglevel(logger, options.loglevel)

    wapt = Wapt(config_filename=options.config)

    allowed_updates = ensure_list(options.allowed_updates, allow_none=True)
    forbidden_updates = ensure_list(options.forbidden_updates, allow_none=True)
    allowed_severities = ensure_list(options.allowed_severities, allow_none=True)
    allowed_classifications = ensure_list(options.allowed_classifications, allow_none=True)

    windows_updates_rules = WaptWUARules()
    windows_updates_rules.load_from_ini(config=wapt.config)
    windows_updates_rules.load_from_options(options)

    if len(args) < 1:
        print(parser.usage)
        sys.exit(1)

    action = args[0]

    with WaptWUA(wapt, windows_updates_rules=windows_updates_rules) as wua:
        wua.ensure_minimum_wua_version()
        if action == 'scan':
            installed, pending, discarded = wua.scan_updates_status(force=options.force)
            print(summary_waptwua_status(wapt))
        elif action == 'download':
            print(wua.download_updates(force=options.force))
            print(summary_waptwua_status(wapt))
        elif action == 'install':
            print(wua.install_updates(force=options.force))
            print(summary_waptwua_status(wapt))
        elif action == 'status':
            print(summary_waptwua_status(wapt))
        else:
            print(parser.usage)
