# -*- coding: utf-8 -*-
from setuphelpers import *
import os
import tempfile
import codecs
import time

# registry key(s) where WAPT will find how to remove the application(s)
uninstallkey = []

TASK_TEMPLATE="""\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>%(created_on)s</Date>
    <Author>WAPT</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>%(run_on)s</StartBoundary>
      <EndBoundary>%(expired_on)s</EndBoundary>
      <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <BootTrigger>
      <StartBoundary>%(run_on)s</StartBoundary>
      <EndBoundary>%(expired_on)s</EndBoundary>
      <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%(cmd)s</Command>
      <Arguments>%(parameters)s</Arguments>
    </Exec>
  </Actions>
</Task>
"""

def create_onetime_task(name,cmd,parameters=None, delay_minutes=2,max_runtime=10, retry_count=3,retry_delay_minutes=1):
    """creates a one time Windows scheduled task and activate it.
    """
    run_time = time.localtime(time.time() + delay_minutes*60)
    # task

    if windows_version(2) <= Version('5.2',2):
        # for win XP
        system_account = r'"NT AUTHORITY\SYSTEM"'
        # windows xp doesn't support one time startup task /Z nor /F
        hour_min = time.strftime('%H:%M:%S', run_time)
        run_notfatal('schtasks /Delete /TN "%s" /F'%name)
        return run('schtasks /Create /SC ONCE /TN "%s" /TR  "%s %s" /ST %s /RU %s' % (name,cmd,parameters,hour_min,system_account))
    else:
        system_account = 'SYSTEM'
        xmlfile = tempfile.mktemp('.xml')
        created_on = time.strftime('%Y-%m-%dT%H:%M:%S',time.localtime(time.time()))
        run_on = time.strftime('%Y-%m-%dT%H:%M:%S',run_time)
        expired_on = time.strftime('%Y-%m-%dT%H:%M:%S',time.localtime(time.time() + 90*24*3600))
        codecs.open(xmlfile,'wb',encoding='utf8').write(TASK_TEMPLATE % locals())
        result = run('schtasks /Create /F /TN "%s" /XML "%s"' % (name,xmlfile))
        if isfile(xmlfile):
            remove_file(xmlfile)
        return result


def full_waptagent_install(min_version,packaged_wapt_version,at_startup=False):
    # get it from
    waptdeploy_path = makepath(tempfile.gettempdir(),'waptdeploy.exe')
    if isfile(waptdeploy_path):
        killalltasks('waptdeploy.exe')
        remove_file(waptdeploy_path)
    filecopyto(makepath('patchs','waptdeploy.exe'),waptdeploy_path)

    waptdeploy_version = get_file_properties(waptdeploy_path)['FileVersion']
    if waptdeploy_version != packaged_wapt_version:
        raise Exception('waptdeploy version %s does not match packaged wapt version %s . aborting' % (waptdeploy_path,packaged_wapt_version))

    # hash and setup filename is specified in first line of waptagent.sha256 file
    # <hash> <setup filename>
    with open('waptagent.sha256','r') as f:
      (expected_sha256,setup_filename) = f.read().strip().split(' ',1)
    waptagent_path = makepath(tempfile.gettempdir(),'waptagent.exe')
    if isfile(waptagent_path):
        killalltasks('waptagent.exe')
        remove_file(waptagent_path)
    if isfile(setup_filename):
        filecopyto(setup_filename,waptagent_path)

    if at_startup or isrunning('waptexit.exe'):
        cmd = '%s --hash=%s --waptsetupurl=%s --wait=15 --temporary --force --minversion=%s' % (waptdeploy_path,expected_sha256,waptagent_path,min_version)
        if not at_startup:
            print('waptexit is running, scheduling a one time task at system startup with command %s'%cmd)
        # task at system startup
        try:
            print(run('schtasks /Create /RU SYSTEM /SC ONSTART /TN fullwaptupgrade /TR "%s" /F /V1 /Z' % cmd))
        except:
            # windows xp doesn't support one time startup task /Z nor /F
            run_notfatal('schtasks /Delete /TN fullwaptupgrade /F')
            print(run('schtasks /Create /RU SYSTEM /SC ONSTART /TN fullwaptupgrade /TR "%s"' % cmd))
    else:
        # use embedded waptagent.exe, wait 15 minutes for other tasks to complete.
        print(create_onetime_task('fullwaptupgrade',waptdeploy_path,'--hash=%s --waptsetupurl=%s --wait=15 --temporary --force --minversion=%s' % (expected_sha256,waptagent_path,min_version),delay_minutes=1))
        time.sleep(2)
        run_notfatal('SCHTASKS /Run /TN "fullwaptupgrade"')


def install():
    # if you want to modify the keys depending on environment (win32/win64... params..)
    if installed_softwares('WAPT Server_is1'):
        print('Wapt server installed on this host. Aborting')
        return "OK"

    waptexe = os.path.join(WAPT.wapt_base_dir,'wapt-get.exe')
    if os.path.isfile(waptexe):
        installed_wapt_version = get_file_properties(waptexe)['FileVersion']
    else:
        installed_wapt_version = '0.0.0'

    # get upgrade package informations
    (package_wapt_version,package_packaging) = control.version.split('-',1)
    package_packaging = int(package_packaging)


    if not force and Version(installed_wapt_version,4) >= Version(package_wapt_version,4):
        print('Your current wapt (%s) is same or more recent than the upgrade package (%s). Skipping agent reinstall...'%(installed_wapt_version,control.version))
    else:
        print('Setting up upgrade from wapt version %s to %s. waptagent install planned for %s' % (installed_wapt_version,package_wapt_version,time.ctime(time.time() + 1*60)))
        full_waptagent_install(str(Version(package_wapt_version,4)),package_wapt_version)

def audit():
    # Comparing installed WAPT agent version and package version
    (package_wapt_version, package_packaging) = control.version.split('-',1)
    try:
        with open(os.path.join(WAPT.wapt_base_dir, 'version-full')) as fver:
            installed_wapt_version = fver.read().split('-',1)[0]
    except:
        installed_wapt_version = '0.0.0.0'

    if Version(installed_wapt_version) < Version(package_wapt_version):
        print("The installed version of the WAPT agent and the version of the package are not corresponding. The installation may have just finished. If this warning persists one day after installation, please take this into consideration.")
        return "WARNING"
    else:
        print("The installed version of the WAPT agent and the version of the package are corresponding.")
        return "OK"
