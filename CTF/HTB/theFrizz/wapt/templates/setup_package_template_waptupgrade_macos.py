# -*- coding: utf-8 -*-
from setuphelpers import *
import time
import subprocess

waptagent_package_file = "%(waptagent_file)s"
os_name = "%(os_name)s"


def installed_wapt_version():
    try:
        with open(os.path.join(WAPT.wapt_base_dir, "version-full")) as fver:
            installed_wapt_version = fver.read()
    except:
        installed_wapt_version = "0.0.0.0"

    return installed_wapt_version

def install():
    print("Install %s" % control.asrequirement())

    if isfile(makepath(WAPT.wapt_base_dir, "waptserver", "server.py")):
        print("Wapt server installed on this host. Aborting")
        return "OK"

    package_wapt_version = control.get_software_version()

    if force or Version(installed_wapt_version()) < package_wapt_version:
        print(f"Your operating system is based on {os_name} {control.min_os_version}, copy the corresponding waptagent.")
        filecopyto(waptagent_package_file,'/opt/wapt/waptsetup.pkg')
        subprocess.Popen("sleep 60 && installer -package /opt/wapt/waptsetup.pkg -target / && rm -f /opt/wapt/waptsetup.pkg && launchctl kickstart -k system/it.tranquil.waptservice",shell=True, executable='/bin/bash', start_new_session=True)
    else:
        print("Your current wapt (%s) is same or more recent than the upgrade package (%s). Skipping..." % (installed_wapt_version, package_wapt_version))

def audit():
    # Comparing installed WAPT agent version and package version
    (package_wapt_version, package_packaging) = control.version.split("-")

    if Version(installed_wapt_version()) < control.get_software_version():
        print(
            "The installed version of the WAPT agent and the version of the package are not corresponding. The installation may have just finished. If this warning persists one day after installation, please take this into consideration."
        )
        return "WARNING"
    else:
        print("The installed version of the WAPT agent and the version of the package are corresponding.")
        return "OK"
