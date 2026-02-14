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

import sys
import os
import glob
import subprocess
from common import Wapt, WaptPackageInstallLogger
from waptutils import sha256_for_file, run, run_notfatal, remove_file, makepath, Version, isfile, wget, currentdatetime, get_disk_free_space
from setuphelpers import remove_tree, service_is_stopped, windows_version, iswin64, system32, get_loggedinusers, EnsureWUAUServRunning, wua_agent_version
from setuphelpers import disable_file_system_redirection, install_location
from waptwua.utils import EWUAFixException, EWUABadSystem, EWUARebootNeeded, EWUAPendingWaptTasks
from waptwua.utils import is_kb_installed, waiting_for_reboot, get_service_pack_version
from waptwua.utils import wait_wapt_pending_tasks, ensure_wuauserv_in_own_svchost, DisableWUAAgent
from waptwua.utils import schtasks_remove
import logging
uninstallkey = []

logger = logging.getLogger('fixwua')

def cleanwua():
    """This function can take some time for wuauserv et trustedinstaller services to stop"""

    print('Cleaning up wuauserv and trustedinstaller files')

    run("net stop wuauserv", accept_returncodes=[0, 2])
    for entryname in glob.glob(r'C:\Windows\SoftwareDistribution\Download\*'):
        print("deleting %s " % entryname)
        if os.path.isfile(entryname):
            remove_file(entryname)
        else:
            remove_tree(entryname)

    try:
        remove_file(r'C:\Windows\SoftwareDistribution\DataStore\Datastore.edb')
        remove_tree(r'C:\Windows\SoftwareDistribution\DataStore\Logs')
    except Exception as e:
        logger.warning("couldn't remove files %s " % e)

    # In French trustedinstaller = Programme d'installation pour les modules Windows
    # for some reasons trustedinstaller may not want to stop
    run("net stop trustedinstaller", accept_returncodes=[0, 2])
    if service_is_stopped('trustedinstaller'):
        for entryname in glob.glob(r'C:\Windows\logs\cbs\*'):
            print("deleting %s " % entryname)
            if os.path.isfile(entryname):
                remove_file(entryname)
            else:
                remove_tree(entryname)


def win7_install_sp1(wapt=None):
    print('installing Win7 SP1')
    if windows_version(2) != '6.1':
        raise EWUAFixException('Only for Windows 7')

    if get_service_pack_version() == 1:
        print("INFO SP1 already installed           ")
        return 0

    if get_disk_free_space(r'c:\\') < 8000000000:
        raise EWUAFixException("Not enough space, need 8.5 GiB free space, only %s" % get_disk_free_space(r'c:\\'))

    # uppercase for ARCH
    exe = download_kb(wapt, 'windows6.1-KB976932-%(ARCH)s.exe')
    wapt.update_server_status()

    sha256sp1 = sha256_for_file(exe)
    if (iswin64() and sha256sp1 != 'f4d1d418d91b1619688a482680ee032ffd2b65e420c6d2eaecf8aa3762aa64c8') or \
            (not iswin64() and sha256sp1 != 'e5449839955a22fc4dd596291aff1433b998f9797e1c784232226aba1f8abd97'):
        remove_file(exe)
        raise EWUAFixException('The sha256 does not match for %s' % exe)
    try:
        run(r'"%s" /quiet /noreboot' % exe, timeout=7200)
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            raise EWUAFixException("error code 2 : il faut faire un check du systeme au prealable")
        if e.returncode == 3017:
            raise EWUAFixException("error code 3017: il y a eu un probleme mais c'est pas la faute a microsoft")
        raise

    # a la fin de l'install, l'etat de la machine est en attente de reboot, la valeur du service pack est toujours a 0, mais
    # la kb du sp1 est bien dans la liste des kb installe visible avec wmic qfe | find 976932
    if waiting_for_reboot():
        logger.warning('reboot needed before further windows update')


def win7_fix_wuagent(wapt):
    print('Installing wuau agent of march 2016')
    if get_service_pack_version() != 1:
        raise EWUABadSystem("ERROR : You need to first install sp1")

    ensure_wuauserv_in_own_svchost()

    # cleanup wuau client cache data

    # stop wuauserv
    # directory c:\windows\softwaredistribution\downloads
    # file c:\windows\softwaredistribution\datastore\datastore.edb
    # start wuauserv

    """after installing those updates, wua update check last about 5 to 10 minutes"""
    """writen according to http://wu.krelay.de/en/"""

    """SP1 :  Windows 7 et Windows Server 2008 R2 Service Pack 1 (KB976932)

    """

    kbs_list = {
        ('KB3185911', 'windows6.1-kb3185911-x64_0622382f0525ffd278d83779c249be2b03edb67a.msu',),
        ('KB3168965', 'windows6.1-kb3168965-x64_936c2cdb1a9d11deb25a2b28d98cd300eff933fb.msu',),
        ('KB3145739', 'windows6.1-kb3145739-x64_b9ae7ee29555dce4d1a225fd1324176a2538178a.msu',),
        ('KB3078601', 'windows6.1-kb3078601-x64_df86415b7464c74c360cc7d2f2d9a3e49509bcf1.msu',),
        ('KB3164033', 'windows6.1-kb3164033-x64_88ef597e01e7698390e5b805514f32b2e447012f.msu',),
        ('KB3109094', 'windows6.1-kb3109094-x64_229f0a31c680557039d084eb1a6249c17c921c8e.msu',),
        ('KB3153199', 'windows6.1-kb3153199-x64_4331d503c2bda3e2f75139f60feac9f4f331b85c.msu',),  # https://www.askwoody.com/2016/windows-7-update-scans-taking-forever-kb-3153199-may-solve-the-problem/comment-page-1/
        # it was the first kb to be installed on a non upated system from 2014 after installing all the other kb in this list
        ('KB3138612', 'windows6.1-kb3138612-x64_f7b1de8ea7cf8faf57b0138c4068d2e899e2b266.msu',),  # wuagent of March 2016
    }

    for (kb, filename) in kbs_list:
        if not is_kb_installed(kb):
            print('Installing %s' % kb)
            msu = download_kb(wapt, filename)
            wapt.update_server_status()

            run(r'"c:\windows\system32\wusa.exe" "%s"  /quiet /norestart' % msu,
                accept_returncodes=[0, 3010, 2359302, -2145124329, 2149842967], timeout=3600)
            # code 2359302: already installed
            # code 3010 : reboot needed
            # code  -2145124329 : does not apply to this computer...
            remove_file(msu)

    if waiting_for_reboot():
        logger.warning('reboot needed before further windows update' or 'WUAAgent successfully fixed')


def win7_install_cumul_april2016(wapt):
    print('installing tis-winupdate-april2016-cumulupdate')

    if get_disk_free_space(r'c:\\') < 4*1024 ^ 3:
        logger.error("not enough space, need 4 GiB free space")
        return 1

    # servicing stack update for win7 or april 2015, prereq for the cumulative uptate below
    # code 2359302 : already installed
    print("install dependency Windows6.1-KB3020369-%(arch)s.msu")
    msu = download_kb(wapt, 'windows6.1-kb3020369-x64_5393066469758e619f21731fc31ff2d109595445.msu')
    wapt.update_server_status()
    run(r'"c:\windows\system32\wusa.exe" "%s"  /quiet /norestart' % msu,
        accept_returncodes=[0, 3010, 2359302, -2145124329, 2149842967], timeout=3600)
    """Known issues for this update
        Restart stuck on "Stage 3 of 3"
            After you install update 3020369 together with other updates, a restart may be required to complete the installation. During this restart, you may find yourself stuck on "Stage 3 of 3."
        If you encounter this issue, press Ctrl+Alt+Delete to continue to log on. This should occur only one time and does not prevent updates from installing successfully.

        An update installation fails after you install update 3020369
            When you install update 3020369 together with other updates, you may encounter a timing issue that causes the update tried immediately after you install update 3020369 to fail.
        This issue only affects the update tried immediately after update 3020369. As soon as update 3020369 is installed, another try to install the failed update should be successful.
            Note In managed environments, such as by using Windows Server Update Services (WSUS), you can avoid either of these issues by deploying this update as a stand-alone update.
    """
    remove_file(msu)

    # cumulative update of april 2016
    # ce cumulative update contient la plupart des maj depuis le sp1 jusqu'à april 2016
    # cette install sature la ram d'une machine à 2Go

    # code retour 8: pas assez d'espace, probablement que ça fait référence à la RAM plus qu'au disque dur
    # error code 112 : not enoght disk space : 2Go d'espace libre ne suffit pas
    print("install april 2016 cumulative update windows6.1-kb3125574-v4")
    if iswin64():
        msu = download_kb(wapt, 'windows6.1-kb3125574-v4-x64_2dafb1d203c8964239af3048b5dd4b1264cd93b9.msu')
    else:
        msu = download_kb(wapt, 'windows6.1-kb3125574-v4-x86_ba1ff5537312561795cc04db0b02fbb0a74b2cbd.msu')
    wapt.update_server_status()

    run(r'"c:\windows\system32\wusa.exe" "%s"  /quiet /norestart' % msu,
        accept_returncodes=[0, 3010, 2359302, -2145124329, 2149842967], timeout=3600)
    r"""Known issue 1
    Symptoms
        A new Ethernet virtual Network Interface Card (vNIC) may be created with default settings in place of the previously existing vNIC, causing network issues. Any custom settings on the previous vNIC are still persisted in the registry but unused.
    Resolution
    To fix this issue, run the VBS script that's provided below. Copy and paste this in notepad and save with .vbs extension.
        # ce cumulative update passe le wuagent en versoin 7.6.7601.23435 du 22/04/2016. Il peut etre installe
        # meme apres le rollup de septembre
    Known issue 3
    Symptoms
    After you install this rollup, if outgoing NTLM traffic is blocked by using the following group policy setting:
    Policies\Windows Settings\Security Settings\Local Policies\SecurityOptions\Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers
    Group Policy object (GPO) backup operations will fail with both Group Policy Management Console (GPMC) as well as PowerShell with the following error message:
    A directory Service error has occurred
    Additionally, gpmgmt.log will log the following errors:
    [XXX.XXX] DateTime [WARNING] LdapConnectServer: ldap_bind_s failed with 0x80072095
    """
    remove_file(msu)


def install_rollup(wapt, kb_name, msu_file):
    if not is_kb_installed(kb_name):
        print("Installing rollup %s" % kb_name)
        wapt.update_server_status()
        msu = download_kb(wapt, msu_file)
        wapt.update_server_status()

        cmd = '"%s" "%s" /quiet /norestart' % (makepath(system32(), 'wusa.exe'), msu)

        cmd_run = run(cmd, accept_returncodes=[0, 3010, 2359302, -2145124329, 2149842967], timeout=3600)
        if not is_kb_installed(kb_name) and cmd_run.returncode != -2145124329:
            if not waiting_for_reboot():
                logger.error('MSU for %s installed properly but not in list of installed KB and no reboot is planned...' % kb_name)
            else:
                logger.warning('MSU for %s installed but reboot is needed' % kb_name)
        elif cmd_run.returncode == -2145124329:
            logger.warning("KB  %s is not applicable to this computer" % kb_name)
        else:
            print("[OK] KB  %s installed successfully" % kb_name)
        remove_file(msu)
        wapt.update_server_status()
    else:
        print('KB %s already installed' % kb_name)


def win7_install_rollups(wapt):
    print('installing tis-win7-update rollup 2016')

    if get_service_pack_version() != 1:
        raise EWUABadSystem("ERROR : You need to first install sp1")

    # error code 3010 : need reboot
    # error code 2359302 : already installed

    # apres le cumulativ update d'april 2016 qui contient toutes les maj importantes depuis le SP1,
    # le rollup suivant est celui de mai 2016

    # KB3156417 : May 2016 update rollup for Windows 7 SP1
    # install_rollup('KB3156417',"Windows6.1-KB3156417-%(arch)s.msu")

    # note : le rollup de juin 2016 (KB3161608) est superseded par celui de juillet, donc on ne l'install pas ici
    # KB3172605 : July 2016 update rollup for Windows 7 SP1"
    # install_rollup('KB3172605',"Windows6.1-KB3172605-%(arch)s.msu")

    # KB3179573 : August 2016 update rollup for Windows 7 SP1 ")
    # install_rollup('KB3179573',"Windows6.1-KB3179573-%(arch)s.msu")

    # KB3185278 : Sept 2016 update rollup for Windows 7 SP1 "
    # install_rollup('KB3185278',"Windows6.1-KB3185278-%(arch)s.msu")

    # KB3185330 : oct 2016 update rollup for Windows 7 SP1 "
    # install_rollup('KB3185330',"Windows6.1-KB3185330-%(arch)s.msu")

    # KB3197868 : nov 2016 update rollup for Windows 7 SP1 "
    # if iswin64():
    #    install_rollup('kb3197868',"windows6.1-kb3197868-x64_b07be176e165c11b9ccbcf03d014b2aef9a514b6.msu")
    # else:
    #    install_rollup('kb3197868',"windows6.1-kb3197868-x86_654e073e00c76a3a7dd01dee8fc2e4fb9a75c931.msu")

    # dec 2016 http://download.windowsupdate.com/d/msdownload/update/software/secu/2016/12/windows6.1-kb3207752-x64_ae76c47886acadcbe337b7b565f63f0991afc7be.msu
    # install_rollup('kb3207752','windows6.1-kb3207752-x64_ae76c47886acadcbe337b7b565f63f0991afc7be.msu')

    # janvier 2017   http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/01/windows6.1-kb3212646-x64_a94cf69326099fb121cdd7daf9dfc558f740afb8.msu
    # install_rollup('kb3212646','windows6.1-kb3212646-x64_a94cf69326099fb121cdd7daf9dfc558f740afb8.msu')
    # fevrier 2017 None

    # mars 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/03/windows6.1-kb4012215-x64_a777b8c251dcd8378ecdafa81aefbe7f9009c72b.msu
    # install_rollup('kb4012215','windows6.1-kb4012215-x64_a777b8c251dcd8378ecdafa81aefbe7f9009c72b.msu')

    # avril 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/04/windows6.1-kb4015549-x64_59cf25073f2e8615b01d9719a0a2e2a0a9a92937.msu
    # install_rollup('kb4015549','windows6.1-kb4015549-x64_59cf25073f2e8615b01d9719a0a2e2a0a9a92937.msu')

    # mai 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows6.1-kb4019264-x64_c2d1cef74d6cb2278e3b2234c124b207d0d0540f.msu
    # install_rollup('kb4019264','windows6.1-kb4019264-x64_c2d1cef74d6cb2278e3b2234c124b207d0d0540f.msu')

    # juin 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/06/windows6.1-kb4022719-x64_127dc7228b2d9278db81121a92471feda59461bb.msu
    # install_rollup('kb4022719','windows6.1-kb4022719-x64_127dc7228b2d9278db81121a92471feda59461bb.msu')

    # juillet 2017 http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/07/windows6.1-kb4025341-x64_e2518cc83b86902d20302f114a7ebe4249efbe9c.msu
    # install_rollup('kb4025341','windows6.1-kb4025341-x64_e2518cc83b86902d20302f114a7ebe4249efbe9c.msu')

    # aout 2017  http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/07/windows6.1-kb4034664-x64_e4daa48a7407d5921d004dd550d62d91bf25839e.msu
    # install_rollup('kb4034664','windows6.1-kb4034664-x64_e4daa48a7407d5921d004dd550d62d91bf25839e.msu')

    # sept 2017 http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/08/windows6.1-kb4038777-x64_193d527f3487640fc18f1f596c0434e64cd20c51.msu
    # install_rollup('kb4038777','windows6.1-kb4038777-x64_193d527f3487640fc18f1f596c0434e64cd20c51.msu')

    # oct 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/09/windows6.1-kb4041681-x64_6d9242a96d4f1bbea20b8d05ee07db2b91654d72.msu
    # install_rollup('kb4041681','windows6.1-kb4041681-x64_6d9242a96d4f1bbea20b8d05ee07db2b91654d72.msu')

    # nov 2017 http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/11/windows6.1-kb4048957-x64_83688ecf3a901fc494ee67b5c57e35f0a09dc455.msu
    # install_rollup('kb4048957','windows6.1-kb4048957-x64_83688ecf3a901fc494ee67b5c57e35f0a09dc455.msu')

    # dec 2017 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/11/windows6.1-kb4054518-x64_290d02e1edc77bd5e809f867fc683d2ff4bf6df8.msu
    # install_rollup('kb4054518','windows6.1-kb4054518-x64_290d02e1edc77bd5e809f867fc683d2ff4bf6df8.msu')

    # janv 2018 http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows6.1-kb4056894-x64_4ddb21dbf40b3a7c41e17b4bf04242d8b48a5ac3.msu
    #install_rollup(wapt, 'KB4056894', 'windows6.1-kb4056894-x64_4ddb21dbf40b3a7c41e17b4bf04242d8b48a5ac3.msu') # 2018-01 Security Monthly Quality Rollup for Windows 7

    # april 2018 http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/04/windows6.1-kb4015549-x64_59cf25073f2e8615b01d9719a0a2e2a0a9a92937.msu
    # install_rollup('kb4015549','windows6.1-kb4015549-x64_59cf25073f2e8615b01d9719a0a2e2a0a9a92937.msu')

    # see https://the1uploader.wordpress.com/2020/02/07/the-growing-list-of-cumulative-update-of-the-ended-life-support-of-windows-7/
    try:
        install_rollup(wapt,'KB4490628','windows6.1-kb4490628-x64_d3de52d6987f7c8bdc2c015dca69eac96047c76e.msu') # March 12, 2019 servicing stack update (SSU)
    except:
        pass
    try:
        install_rollup(wapt,'KB4536952','windows6.1-kb4536952-x64_87f81056110003107fa0e0ec35a3b600ef300a14.msu')  # latest servicing stack
    except:
        pass
    try:
        install_rollup(wapt,'KB4474419','windows6.1-kb4474419-v3-x64_b5614c6cea5cb4e198717789633dca16308ef79c.msu') # September 10, 2019 latest SHA-2 update
    except:
        pass
    #install_rollup(wapt,'KB4525251','windows6.1-kb4525251-x64_79d8803f97dab73d56708581ca4f561b403fd5c3.msu') # 2019-11 Preview of Monthly Quality Rollup
    try:
        install_rollup(wapt,'KB4534310','windows6.1-kb4534310-x64_4dc78a6eeb14e2eac1ede7381f4a93658c8e2cdc.msu') # 2020-01 Security Monthly Quality Rollup for Windows 7 for x64-based Systems (KB4534310)
    except:
        pass
    try:
        install_rollup(wapt,'KB4539602','windows6.1-kb4539602-x64_977d8a5421d03ba7ddd992ddf79175dddcfb90d4.msu')  #  Security-only updates , can fix ssh2 signature issue
    except:
        pass
    try:
        install_rollup(wapt,'KB2670838','windows6.1-kb2670838-x64_9f667ff60e80b64cbed2774681302baeaf0fc6a6.msu') # platform update
    except:
        pass

def fix_wua_win7(wapt, cleanupfirst=False):
    print("Starting WUA sanity check")
    with DisableWUAAgent():
        wapt.update_server_status()
        if cleanupfirst:
            cleanwua()

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)

        if get_service_pack_version() == 1:
            print("[OK] SP1 already installed")
        else:
            wapt.update_server_status()
            win7_install_sp1()
            wapt.update_server_status()

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)
        else:
            if cleanupfirst:
                cleanwua()

    with EnsureWUAUServRunning():
        if wua_agent_version() < Version('7.6.7601.1961'):
            win7_fix_wuagent(wapt)
        else:
            print("[OK] WUA equal or later to mars 2016")

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)

        if wua_agent_version() < Version('7.6.7601.23435') \
                and not is_kb_installed('KB3125574'):
            wapt.update_server_status()
            win7_install_cumul_april2016(wapt)
            wapt.update_server_status()
        else:
            print("[OK] Cumulative update of april 2016 already installed")

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)

        win7_install_rollups(wapt)

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)
        print("####### fixwua finished, fixwua task is going to be removed  #####")
        schtasks_remove('wsus_windows_upgrade')


def exit_and_reboot_if_possible(wapt):
    print('Testing if immediate reboot is possible...')
    connected_users = get_loggedinusers()
    print('Connected users : %s' % connected_users)
    if (not connected_users and not wapt.runstatus):
        wait_wapt_pending_tasks(wapt)
        print('Rebooting immediately, no one connected...')
        with disable_file_system_redirection():
            run_notfatal('msg * /SERVER:127.0.0.1 /time:15 "Redemarrage de l\'ordinateur pour installation des mises a jour windows"')
        run('shutdown /r /f /t 0')
    else:
        with disable_file_system_redirection():
            run_notfatal('msg * /SERVER:127.0.0.1 /time:15 "Redemarrage de l\'ordinateur necessaire pour l\'installation des mises a jour windows"')

    raise EWUARebootNeeded("Computer reboot is required to complete Windows OS  Updates.")


def download_kb(wapt, kb_filename):
    """a little bit too specific, could be improved
    """
    kb_filename = kb_filename.lower().split('/')[-1]
    target_fn = makepath(wapt.wapt_base_dir, 'cache', kb_filename)
    if not isfile(target_fn):
        repo_url = wapt.repositories[-1].repo_url
        url = '/'.join([repo_url.rsplit('/', 1)[0], 'waptwua', kb_filename])
        wget(url, target_fn, proxies=wapt.repositories[-1].proxies, limit_bandwidth=wapt.limit_bandwidth)
    return target_fn


if __name__ == '__main__':
    wapt = Wapt(config_filename=makepath(install_location('WAPT_is1'), 'wapt-get.ini'))
    if len(sys.argv) > 1:
        logpackage = sys.argv[1]
    else:
        logpackage = 'tis-waptwua'

    with WaptPackageInstallLogger(sys.stderr, wapt_context=wapt, install_id=wapt._get_package_status_rowid(package_name=logpackage)):
        print("######   %s : Lancement de waptwua fix #####" % currentdatetime())
        print("###### This is a fix, and it should be run only once on a given computer#####")
        # check  si des taches wapt sont en cours
        wait_wapt_pending_tasks(wapt)

        if waiting_for_reboot():
            exit_and_reboot_if_possible(wapt)

        try:
            # we have to check if we have the latest rollup. If we have it, then we don't need to run the fix
            # some rollup may be superseeded by KB that are not rollup (you get a "this kb is not compatible with your system" error message)
            if is_kb_installed('KB3197868') and wua_agent_version() == Version('7.6.7601.23453'):
                print("WUA does not need fixing")
                print("we should do the standard waptwua procedure")
                schtasks_remove('wsus_windows_upgrade')
                print("##### fixwua finished #####")
            else:
                fix_wua_win7(wapt)

        except (EWUAPendingWaptTasks, EWUAPendingWaptTasks, EWUARebootNeeded) as e:
            raise e
        except Exception as e:
            logger.error('An error has occured, we remove the scheduled task to avoid further issues. Remove and reinstall the package after fixing...')
            schtasks_remove('wsus_windows_upgrade')
            raise e
