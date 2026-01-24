# -*- coding: utf-8 -*-
from setuphelpers import *
import time

waptagent_package_file = "%(waptagent_file)s"
os_name = "%(os_name)s"
temp_dir = makepath("/tmp")


def create_systemd_onetime_task(name, user, cmd, delay_minutes=2):
    """
    Create cron task
    """
    run_time = time.localtime(time.time() + delay_minutes * 60)

    hour_min = time.strftime("%H:%M:%S", run_time)
    date = time.strftime("%Y-%m-%d", run_time)

    cmd = "systemd-run --on-calendar='%s %s' --description='%s' %s " % (date, hour_min, name, cmd)
    print("Create scheduled task with command : %s" % cmd)
    run(cmd)

def installed_wapt_version():
    try:
        with open(os.path.join(WAPT.wapt_base_dir, "version-full")) as fver:
            return fver.read()
    except:
        return "0.0.0.0"

def install():
    print("Install %s" % control.asrequirement())

    if isfile(makepath(WAPT.wapt_base_dir, "waptserver", "server.py")):
        print("Wapt server installed on this host. Aborting")
        return "OK"

    package_wapt_version = control.get_software_version()

    if force or Version(installed_wapt_version()) < package_wapt_version:
        print(f"Your operating system is based on {os_name} {control.min_os_version}, copy the corresponding waptagent.")
        filecopyto(waptagent_package_file, temp_dir)
        waptagent_file = makepath(temp_dir, waptagent_package_file)
        install_cmd = ""
        if is_redhat_based():
            install_cmd = "yum install %s -y" % waptagent_file
        elif is_debian_based():
            install_cmd = "/usr/bin/apt install -f -y %s" % waptagent_file
        create_systemd_onetime_task("waptupgrade", "root", install_cmd)
    else:
        print("Your current wapt (%s) is same or more recent than the upgrade package (%s). Skipping..." % (installed_wapt_version(), package_wapt_version))

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
