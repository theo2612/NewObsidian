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
## Please note that backward compatibility is not guaranteed.
## Functions imported from this file are more likely to break
## in future updates compared to setuphelpers functions.
##
import glob
import os
import sys
import platform
import requests
import json
from setuphelpers import *
from waptutils import (
    Version,
    __version__,
    makepath,
    isfile,
    isdir,
    remove_file,
    run,
    error,
)
import bs4 as BeautifulSoup
from shutil import rmtree
from urllib.parse import urlparse
from waptpackage import PackageEntry


def get_proxies_from_wapt_console():
    r"""Return proxy information from the current user WAPT console

    >>> get_proxies_from_wapt_console()
    {'http': 'http://srvproxy.ad.domain.lan:8080',
    'https': 'http://srvproxy.ad.domain.lan:8080'}

    """
    proxies = {}
    if platform.system() == "Windows":
        waptconsole_ini_path = makepath(user_local_appdata(), "waptconsole", "waptconsole.ini")
    else:
        waptconsole_ini_path = makepath(user_home_directory(), ".config", "waptconsole", "waptconsole.ini")
    if isfile(waptconsole_ini_path):
        proxy_wapt = inifile_readstring(waptconsole_ini_path, "global", "http_proxy")
        if proxy_wapt:
            proxies = {"http": proxy_wapt, "https": proxy_wapt}
    return proxies


def is_url(x):
    try:
        result = urlparse(x)
        return all([result.scheme, result.netloc])
    except:
        return False


def bs_find(url, element, attribute=None, value=None, user_agent=None, proxies=None, features="html.parser", **kwargs):
    """
    Parse an HTML or XML web page with BeautifulSoup and retrieve the first matching result.

    Args:
        url (str): URL of the web page or string to parse.
        element (str): Searched element.
        attribute (str): Selected attribute of the element.
        value (str): Value of the selected attribute.
        user_agent (str): Specify a user-agent if needed.
        proxies (dict): Specify proxies if needed.
        features (str): BeautifulSoup feature to use.
        **kwargs: Additional parameters for the requests library.

    Returns:
        bs4.element.Tag or None: The first matching element, or None if no match is found.

    Examples:
        >>> bs_find('https://www.w3.org/', 'a', 'title', 'Open Web Platform testing')['href']
        'https://web-platform-tests.org/'

        >>> bs_find('https://www.w3.org/', 'span', 'class', 'alt-logo').string
        'W3C'

    .. versionadded:: 2.0

    .. versionchanged:: 2.5
        Function can now parse string content of a page or reparse a "bs_result". It is now possible to parse a specific attribute.

    """
    url = str(url)
    if is_url(url):
        if user_agent:
            page = requests.get(url, proxies=proxies, headers={"User-Agent": user_agent}, **kwargs).text
        else:
            page = requests.get(url, proxies=proxies, **kwargs).text
    else:
        page = url
    soup = BeautifulSoup.BeautifulSoup(page, features=features)
    if value:
        return soup.find(element, {attribute: value})
    elif attribute:
        return soup.find(element, attrs={attribute: True})
    else:
        return soup.find(element)


def bs_find_all(url, element, attribute=None, value=None, user_agent=None, proxies=None, features="html.parser", **kwargs):
    """
    Parse an HTML or XML web page with BeautifulSoup and retrieve a list of all matching results.

    Args:
        url (str): URL of the web page or string to parse.
        element (str): Searched element.
        attribute (str): Selected attribute of the element.
        value (str): Value of the selected attribute.
        user_agent (str): Specify a user-agent if needed.
        proxies (dict): Specify proxies if needed.
        features (str): BeautifulSoup feature to use.
        **kwargs: Additional parameters for the requests library.

    Returns:
        list: List of bs4.element.Tag objects representing the matching elements.

    Examples:
        >>> bs_find_all('https://www.w3.org/', 'a', 'title', 'Open Web Platform testing')[0]['href']
        'https://web-platform-tests.org/'

        >>> bs_find_all('https://www.w3.org/', 'span', 'class', 'alt-logo')[0].string
        'W3C'

    .. versionadded:: 2.0

    .. versionchanged:: 2.5
        Function can now parse string content of a page or reparse a "bs_result". It is now possible to parse a specific attribute.

    """
    url = str(url)
    if is_url(url):
        if user_agent:
            page = requests.get(url, proxies=proxies, headers={"User-Agent": user_agent}, **kwargs).text
        else:
            page = requests.get(url, proxies=proxies, **kwargs).text
    else:
        page = url
    soup = BeautifulSoup.BeautifulSoup(page, features=features)
    if value:
        return soup.find_all(element, {attribute: value})
    elif attribute:
        return soup.find_all(element, attrs={attribute: True})
    else:
        return soup.find_all(element)


def remove_outdated_binaries(version, list_extensions=["exe", "msi", "deb", "rpm", "dmg", "pkg", "part"], filename_contains=None):
    r"""Remove files based on the version contained in his filename, failing over on file version on compatible OSes

    Args:
        version (str): version number of keeped files
        list_extensions (str or list of str): file extensions of compared files
        filename_contains (str or list of str): Part of the filename that must be contained (useful for distinguishing architecture and os)

    Returns:
        list: list of deleted files

    .. versionadded:: 2.0

    .. versionchanged:: 2.2
        Now returns removed files, now checking .exe and .msi file versions

    """
    files = []
    if type(list_extensions) != list:
        list_extensions = [list_extensions]
    if filename_contains:
        if type(filename_contains) != list:
            filename_contains = [filename_contains]
    list_extensions = ["." + ext for ext in list_extensions if ext[0] != "."]
    for file_ext in list_extensions:
        for bin_in_dir in glob.glob("*%s" % file_ext):
            if filename_contains:
                for filename_contain in filename_contains:
                    if not filename_contain in bin_in_dir:
                        remove_file(bin_in_dir)
                        files.append(bin_in_dir)
            if not version in bin_in_dir:
                if platform.system() == "Windows":
                    if file_ext == ".exe" or file_ext == ".msi":
                        if Version(version, 4) == Version(get_version_from_binary(bin_in_dir, "FileVersion"), 4) or Version(version, 4) == Version(
                            get_version_from_binary(bin_in_dir, "ProductVersion"), 4
                        ):
                            print("%s file or product version is correct (%s)" % (bin_in_dir, version))
                            continue
                remove_file(bin_in_dir)
                files.append(bin_in_dir)
    return print("\n".join(["Removed outdated binary: " + fn for fn in files]))


def unzip_with_7zip(filename, target=None, filenames=[], extract_with_full_paths=True, recursive=True):
    r"""Extract the files from an archive file with 7zip with patterns in filenames to target directory

    Args:
        filename (str): path to archive file. (can be relative to temporary unzip location of package)
        target (str): archive content to target dir location (dir will be created if needed). Default: dirname(archive file) + basename(archive file)
        filenames (str or list of str): list of filenames / glob patterns (path sep is normally a slash)
        extract_with_full_paths (bool): keeping or not the subfolders of the archive as is
        recursive (bool): looking or not for filenames recursively

    Returns:
        None

    .. versionadded:: 2.0

    .. versionchanged:: 2.2
        changed default target location to make it correspond with unzip()

    """
    if not target:
        target = makepath(os.path.dirname(os.path.abspath(filename)), os.path.splitext(os.path.basename(filename))[0])
    if not isinstance(filenames, list):
        filenames = [filenames]

    sevenzip_path = get_7z_path()

    if not filenames:
        if extract_with_full_paths:
            run(r'"%s" x "%s" %s %s -aoa' % (sevenzip_path, filename, "" if not target else '-o"%s"' % target, "" if not recursive else "-r"))
        else:
            run(r'"%s" e "%s" %s %s -aoa' % (sevenzip_path, filename, "" if not target else '-o"%s"' % target, "" if not recursive else "-r"))
    else:
        for extract in filenames:
            if extract_with_full_paths:
                run(
                    r'"%s" x "%s" %s "%s" %s -aoa'
                    % (sevenzip_path, filename, "" if not target else '-o"%s"' % target, extract, "" if not recursive else "-r")
                )
            else:
                run(
                    r'"%s" e "%s" %s "%s" %s -aoa'
                    % (sevenzip_path, filename, "" if not target else '-o"%s"' % target, extract, "" if not recursive else "-r")
                )


def get_7z_path():
    """Check if the 7zip binary path exists and returns it.

    Returns:
        str: path to the 7zip binary
    """

    if "Windows" in get_os_name():
        sevenzip_path = makepath(programfiles, "7-Zip", "7z.exe")
        if isfile(sevenzip_path):
            return sevenzip_path
        sevenzip_path = makepath(programfiles32, "7-Zip", "7z.exe")
        if isfile(sevenzip_path):
            return sevenzip_path
        error('Could not find path to 7zip binary, please install "tis-7zip"')
    else:
        sevenzip_path = makepath("/usr", "local", "bin", "7zz")
        if isfile(sevenzip_path):
            return sevenzip_path
        sevenzip_path = sevenzip_path.replace("7zz", "7z")
        if isfile(sevenzip_path):
            return sevenzip_path
        error('Could not find path to 7zip binary, please install "tis-7zip"')


def get_size(any_path):
    """
    Calculate the total size of files and directories in a path, including subdirectories.

    Args:
        any_path (str): The directory or file path to start calculating the size from.

    Returns:
        int: Total size in bytes.

    Raises:
        FileNotFoundError: If the specified path does not exist.
    """
    total_size = 0

    if os.path.exists(any_path):
        if os.path.isdir(any_path):
            for dirpath, dirnames, filenames in os.walk(any_path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    if not os.path.islink(file_path):
                        total_size += os.path.getsize(file_path)
        elif os.path.isfile(any_path):
            total_size += os.path.getsize(any_path)
        else:
            raise ValueError(f"The specified path '{any_path}' is neither a file nor a directory.")
    else:
        raise FileNotFoundError(f"The specified path '{any_path}' does not exist.")

    return total_size


def convert_control_path_to_dir(any_path):
    """Converts the control file path to a directory path by removing the 'WAPT/control' suffix.

    Args:
        any_path (str): The input file path.

    Returns:
        str: The converted directory path with the 'WAPT/control' suffix removed.

    Example:
        >>> convert_control_path_to_dir('/path/to/some_directory/WAPT/control')
        '/path/to/some_directory'
    """
    control_suffix = os.path.join("WAPT", "control")

    if any_path.endswith(control_suffix):
        any_path = any_path.rsplit(control_suffix)[0]
    return any_path


def get_control_dict(control):
    """
    Load the control information of a package as dict based on its PackageEntry, its control file, or its package dir.

    Args:
        control (PackageEntry or str): The PackageEntry, the control file path, or the package dir path.

    Returns:
        dict: A dictionary containing the control information of the package.
    """
    if isinstance(control, PackageEntry):
        control_dict = dict(control)
    else:
        pkg_dir = convert_control_path_to_dir(control)
        control_dict = PackageEntry().load_control_from_wapt(pkg_dir).as_dict()
    return control_dict


def complete_control_impacted_process(control, program_dir=""):  # , silent=False
    """Complete package `control.impacted_process`."""
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)
    impacted_process_dict = {}
    if control.impacted_process:
        control.impacted_process = [p.split(".exe")[0].split(".EXE")[0].strip() for p in ensure_list(control.impacted_process)]
        for p in ensure_list(control.impacted_process):
            impacted_process_dict.update({p: None})
    elif get_control_dict(control)["impacted_process"] == "" and program_dir is not None and get_os_name() == "Windows":
        exe_list = []
        exe_dict = {}
        for exe_path in glob.glob("%s/**/*.exe" % (program_dir), recursive=True) + glob.glob("%s/**/*.bin" % (program_dir), recursive=True):
            exe = exe_path.split(os.sep)[-1].split(".exe")[0].split(".EXE")[0]
            exe_list.append(exe)
            exe_dict.update({exe: exe_path})
        control.impacted_process = ask_grid(
            f'Select {get_control_dict(control)["package"]} application relative impacted processes',
            format_dict_to_grid(exe_dict, "process", "path"),
            1,
        )
        if control.impacted_process:
            control.impacted_process = [p["process"] for p in control.impacted_process]
            for p in ensure_list(control.impacted_process):
                impacted_process_dict.update({p: exe_dict[p]})
        else:
            control.impacted_process = ""

    control.save_control_to_wapt()
    return impacted_process_dict


def complete_control_min_wapt_version(control, min_wapt_version="2.3", silent=False):
    """Complete package `control.min_wapt_version`."""
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    if control.min_wapt_version == "" or Version(control.min_wapt_version) < Version(min_wapt_version):
        if not silent:
            control.min_wapt_version = ask_input(
                "min_wapt_version", f"min_wapt_version is EOL or not set, setting it to: {min_wapt_version}", min_wapt_version
            )
        else:
            control.min_wapt_version = min_wapt_version

    control.save_control_to_wapt()
    return control.min_wapt_version


def complete_control_version(control, version, inc_build=False):  # , silent=True
    """Complete package `control.version`. Return if the package have been updated"""
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    package_updated = False
    # Changing version of the package
    if Version(version, 4) > Version(control.get_software_version(), 4):
        print("Software version updated (from: %s to: %s)" % (control.get_software_version(), Version(version)))
        package_updated = True
    else:
        print("Software version up-to-date (%s)" % Version(version))
    control.set_software_version(version)

    if inc_build:
        control.inc_build()

    control.save_control_to_wapt()
    return package_updated


def complete_control_description(control, control_description="", silent=False, blank_str="", maximum_length=None):
    """Updates the control description field with the provided description.

    Args:
        control (str or waptpackage.PackageEntry): The path of control file or his PackageEntry call
        control_description (str): The description to be set for the control.description field.
        silent (bool): If True, no user input dialog will be displayed. (default: False)
        blank_str (str): If the description contains this string, it will be cleared. (default: "" => do not clear)
        maximum_length (int): If the description has more characters than the defined value, the function will try to reduce it.

    Returns:
        str: The updated control description.
    """
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    old_control_description = control.description
    if control_description:
        control.description = control_description

    # Replacing curvy quotes and blank characters
    control.description = (
        " ".join(control.description.splitlines()).replace("\u2019", "'").replace("\xa0", " ").replace("\u202f", " ").replace("\u00a0", " ")
    )

    if blank_str and blank_str in control.description:
        control.description = ""
    if maximum_length:
        if len(control.description) > maximum_length:
            for i in range(0, len(control.description.rsplit(". ")), 1):
                control.description = control.description.rsplit(". ", i)[0]
                if len(control.description) < maximum_length:
                    break

    # Retire dot in the end of the string
    if control.description.endswith("."):
        control.description = control.description.rsplit(".", 1)[0]

    if not silent:
        control.description = ask_input("control.description", "Please fill or change the description", control.description)
        if not control.description:
            control.description = old_control_description

    # Erase translations if description changed
    if old_control_description != control.description and old_control_description.strip() != control.description + ".":
        for d in control.all_attributes:
            if d.startswith("description_"):
                control[d] = ""

    control.save_control_to_wapt()
    return control.description


def complete_control_descriptions(
    control,
    control_descriptions_dict={
        "description": "",
        "description_fr": "",
        "description_pl": "",
        "description_de": "",
        "description_es": "",
        "description_pt": "",
        "description_it": "",
        "description_nl": "",
        "description_ru": "",
    },
    silent=False,
    blank_str="",
):
    """Updates the control description field with the provided description.

    Args:
        control_description (str): The description to be set for the control.description field.
        silent (bool): If True, no user input dialog will be displayed. (default: False)
        blank_str (str): If the description contains this string, it will be cleared. (default: "")

    Returns:
        str: The updated control description.
    """
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    old_control_descriptions_dict = control_descriptions_dict
    if not True in [d != "" for d in control_descriptions_dict.values()]:
        control_descriptions_dict = {}
        for control_attribute in [attribute for attribute in control.all_attributes if "description" in attribute]:
            control_descriptions_dict.update({control_attribute: control[control_attribute]})

    if not silent:
        response = ask_grid("control.descriptions", control_descriptions_dict, search_label="Please fill or change the descriptions")
        if response:
            control_descriptions_dict = response[0]

    for control_attribute in [attribute for attribute in control.all_attributes if "description" in attribute]:
        control_description = control_descriptions_dict.get(control_attribute)

        if blank_str and blank_str in control_description:
            control_description = ""

        # Retire dot in the end of the string
        if control_description.endswith("."):
            control_description = control_description.rsplit(".", 1)[0]
        # .replace("’", "'").replace(" ", " ")
        control[control_attribute] = control_description.replace("\u2019", "'").replace("\xa0", " ").replace("\u202f", " ").replace("\u00a0", " ")

    control.save_control_to_wapt()
    return control_descriptions_dict


def complete_control_categories(control):
    """Requesting that the user supply package categories for the control.categories field if empty or Template is selected
    Args:
        control (str or waptpackage.PackageEntry): The path of control file or his PackageEntry call
    """
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    old_control_categories = control.categories
    if control.categories == "" or "template".lower() in control.categories.lower():
        categories = ask_grid(
            "Select package categories",
            [
                "Internet",
                "Utilities",
                "Messaging",
                "Security",
                "System and network",
                "Media",
                "Development",
                "Office",
                "Drivers",
                "Education",
                "Configuration",
                "CAD",
                "Template",
                "Dependency",
                "Extension",
            ],
            "GRT_SELECTED",
        )
        if categories:
            control.categories = ",".join([c["unknown"] for c in categories])
        else:
            control.categories = ""
        control.save_control_to_wapt()
    return control.categories


def complete_control_package(control, control_package="", silent=False, remove_template_base_files=False):
    """Requesting that the user provide a package name to be entered into the control.package field, and offering the possibility of removing the base files (icon.png and changelog.txt) for template package usage

    Args:
        control (str or waptpackage.PackageEntry): The path of control file or his PackageEntry call
        control_package (str)   : Prefilled control_package (default: actual control_package)
        silent (bool)           : If True, no user input dialog will be displayed. (default: False)
        remove_template_base_files (bool): Removes base files if parameter is True and str("template") in control.package (default: False)
    """
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)

    old_control_package = control.package
    control_package = (
        control_package.lower()
        .replace("_", "-")
        .replace("~", "-")
        .replace(" ", "-")
        .replace("!", "")
        .replace("'", "")
        .replace("(", "")
        .replace(")", "")
    )
    control_package = "-".join([p.strip() for p in control_package.split("-") if p.strip()])
    if not control_package:
        control_package = control.package

    # Removing template files
    if "template" in control.package.lower() and remove_template_base_files:
        if isfile("WAPT\\changelog.txt"):
            remove_file("WAPT\\changelog.txt")
        if isfile("WAPT\\icon.png"):
            remove_file("WAPT\\icon.png")

    if not silent:
        control_package = control_package.replace("-template", "").strip()
        control.package = ask_input(control.package, "You can redefine the package name", control_package)
        if not control.package:
            control.package = old_control_package

    control.save_control_to_wapt()
    return control.package


def complete_control_name(control, control_name="", silent=False):
    """Requesting that the user provide a package name to be entered into control.name field

    Args:
        control (str or waptpackage.PackageEntry): The path of control file or his PackageEntry call
        control_name (str)  : Prefilled control_name (default: control.name whitout "template" word)
        silent (bool)       : If True, no user input dialog will be displayed. (default: False)
    """
    if not isinstance(control, PackageEntry):
        pkg_dir = convert_control_path_to_dir(control)
        control = PackageEntry().load_control_from_wapt(pkg_dir)
    old_control_name = control.name
    if silent:
        control.name = control_name
    else:
        if not control_name:
            control_name = control.name
        control_name = control_name.replace("Template", "").replace("template", "").strip()
        control.name = ask_input(control.name, "You can redefine the name for the self-service", control_name)

    control.save_control_to_wapt()
    return control.name


def ask_directory(title="Select folder", initial_dir="", raise_error=False):
    """
    Asks the user to select a folder using a directory dialog and returns the path of that folder.

    Args:
        title (str): Specifies the title of the directory dialog window. Default value is "Select folder".
        initial_dir (str): Specifies the initial path of the directory dialog. Default is last provided.
        raise_error (bool): Whether to raise an error if no folder is selected.

    Returns:
        The path of the selected folder.
    """
    import waptguihelper

    folder = waptguihelper.directory_dialog(title, initial_dir)
    if not folder and raise_error:
        error("No folder selected.")
    return folder


def ask_filename(title="Select file", initial_dir="", filename="*.*", filter="All files (*.*)|*.*", raise_error=False):
    """
    This function asks the user to select a file using a filename dialog and returns the path of that file.

    Args:
        title (str): The title for the dialog.
        initialdir (str): The initial directory path. Default is last provided.
        filename (str): The default file name. Default is "*.*".
        filter (str): The filter by description and extension. Default is "All files (*.*)|*.*".
        raise_error (bool): Whether to raise an error if the user cancels the dialog. Default is True.

    Returns:
        str: The path of the selected file.

    Raises:
        ValueError: If the user cancels the dialog and raise_error is True.
    """
    import waptguihelper

    file_path = waptguihelper.filename_dialog(title, initial_dir, filename, filter)
    if not file_path and raise_error:
        error("No file selected.")
    return file_path


def ask_input(title, text, default="", stay_on_top=False, raise_error=False):
    """
    Opens a dialog box with an action input.

    Args:
        title (str): The title for the dialog.
        text (str): Indicates which value the user should type.
        default (str): The default value if the user does not want to type anything.
        stay_on_top (bool): Indicates if the dialog box will always stay on top. Default is False.
        raise_error (bool): Whether to raise an error if no response is given by the user.

    Returns:
        The response from the dialog box.
    """
    import waptguihelper

    response = waptguihelper.input_dialog(title, text, default, stay_on_top)
    if not response and not response == "" and raise_error:
        error("No response given by user")
    return response


def ask_grid(
    title,
    dict_input,
    result_type=0,
    metadata="",
    search_label="Search",
    stay_on_top=False,
    raise_error=False,
):
    """
    Opens a dialog box with an action input.

    Args:
        title (str): The name of the title to display in the dialog box.
        dict_input (dict): A dictionary of input values to display in the dialog box.
        result_type (str or int): The type of result to display in the dialog box. Currently supported options are:
                            - "GRT_ALL"         or (0) to return the whole grid
                            - "GRT_SELECTED"    or (1) to return the selected rows
        metadata (str of a json): Additional metadata to display in the dialog box.
        search_label (str): The label for the search button in the dialog box.
        stay_on_top (bool): Whether to keep the dialog box on top of other windows.
        raise_error (bool): Whether to raise an error if no response is given by the user.

    Returns:
        The result of the dialog box.
    """
    import waptguihelper

    if type(result_type) != int:
        result_type = getattr(waptguihelper, result_type)
    if type(dict_input) == dict:
        dict_input = json.dumps(dict_input)
    if type(metadata) == dict:
        metadata = json.dumps(metadata)

    response = waptguihelper.grid_dialog(title, dict_input, result_type, metadata, search_label, stay_on_top)
    if not response and raise_error:
        error("No response given by user")
    return response


def ask_message(
    title,
    text,
    flags=None,
    raise_error=False,
):
    """
    Opens a message box with customizable buttons and icons.

    Args:
        title (str): The title to display in the message box.
        text (str): The message text to display in the message box.
        flags (int): Options for buttons and icons. You can combine a message and an icon by adding their corresponding
            integer values together. Possible message options:
            - MB_OK (0): OK button
            - MB_OKCANCEL (1): OK and Cancel buttons
            - MB_ABORTRETRYIGNORE (2): Abort, Retry, and Ignore buttons
            - MB_YESNOCANCEL (3): Yes, No, and Cancel buttons
            - MB_YESNO (4): Yes and No buttons

            Possible icon options:
            - MB_ICONERROR (16): Error icon
            - MB_ICONQUESTION (32): Question icon
            - MB_ICONWARNING (48): Warning icon
            - MB_ICONINFORMATION (64): Information icon

            To combine a message and an icon, add their integer values together. For example, to display an OK button
            with an information icon, use: 0 + 64 (MB_OK + MB_ICONINFORMATION).

            Note: For more details and additional options, refer to the documentation at:
            https://www.functionx.com/delphi/msgboxes/messagebox.htm

        raise_error (bool): Whether to raise an error if no response is given by the user.

    Returns:
        The response code indicating the user's choice. Possible return values:
        - ID_OK (1)
        - ID_CANCEL (2)
        - ID_ABORT (3)
        - ID_RETRY (4)
        - ID_IGNORE (5)
        - ID_YES (6)
        - ID_NO (7)
    """
    import waptguihelper

    if flags is None:
        flags = waptguihelper.MB_ICONINFORMATION + waptguihelper.MB_OK
    response = waptguihelper.message_dialog(title, text, flags)
    if not response or response in (2, 3, 4) and raise_error:
        raise ValueError("No response given by the user")
    return response


def get_public_persistent_dir():
    """
    Get the path to the public persistent directory.

    Returns:
        str: Path to the public persistent directory.
    """
    try:
        return makepath(WAPT.wapt_base_dir, "public", "persistent")
    except Exception:
        try:
            return makepath(installed_softwares(uninstallkey="WAPT_is1")[0]["install_location"], "public", "persistent")
        except Exception:
            return makepath(programfiles32, "wapt", "public", "persistent")


def get_public_persistent_file(fname):
    """
    Get the path to a file in the public persistent directory.

    Args:
        fname (str): Filename.

    Returns:
        str: Path to the file in the public persistent directory.
    """
    try:
        return makepath(WAPT.wapt_base_dir, "public", "persistent", fname)
    except Exception:
        try:
            return makepath(installed_softwares(uninstallkey="WAPT_is1")[0]["install_location"], "public", "persistent", fname)
        except Exception:
            return makepath(programfiles32, "wapt", "public", "persistent", fname)


def get_private_persistent_package_file(file_name):
    file_name = os.path.basename(file_name)
    if control.package_uuid:
        if WAPT.is_installed(control.package) is not None and control.package_uuid == WAPT.is_installed(control.package)["package_uuid"]:
            return makepath(WAPT.persistent_root_dir, control.package_uuid, file_name)
    return makepath(os.getcwd(), "WAPT", "persistent", file_name)


def get_private_persistent_package_dir():
    if control.package_uuid:
        if WAPT.is_installed(control.package) is not None and control.package_uuid == WAPT.is_installed(control.package)["package_uuid"]:
            return makepath(WAPT.persistent_root_dir, control.package_uuid)
    return makepath(os.getcwd(), "WAPT", "persistent")


def remove_tree_for_all_users(user_folder_relative_path, ignored_users=None, ignore_system_users=True):
    """
    Remove a specific folder or folders for all user profiles.

    Args:
        user_folder_relative_path (str): Relative path to the user folder. Glob patterns can be used.
        ignored_users (str or list of str): Ignore specified users.
        ignore_system_users (bool): Ignore default, public, all users, etc. (True by default).

    Returns:
        list: List of deleted folders.

    >>> print(remove_tree_for_all_users(makepath(".vscode", "extensions", "ms-toolsai.jupyter-*")))
    ['C:\\Users\\username\\.vscode\\extensions\\ms-toolsai.jupyter-2022.2.1001817079', 'C:\\Users\\username\\.vscode\\extensions\\ms-toolsai.jupyter-keymap-1.0.0', 'C:\\Users\\username\\.vscode\\extensions\\ms-toolsai.jupyter-renderers-1.0.6']

    >>> print(remove_tree_for_all_users(makepath(".vscode", "extensions", "ms-toolsai.jupyter-")))
    []

    >>> print(remove_tree_for_all_users(makepath(".vscode", "extensions", "ms-toolsai.jupyter-[a-z]*")))
    ['C:\\Users\\username\\.vscode\\extensions\\ms-toolsai.jupyter-keymap-1.0.0', 'C:\\Users\\username\\.vscode\\extensions\\ms-toolsai.jupyter-renderers-1.0.6']

    >>> print(remove_tree_for_all_users(makepath(".vscode", "extensions", "ms-toolsai.jupyter-1.0.0")))
    ['/home/username/.vscode/extensions/ms-toolsai.jupyter-keymap-1.0.0']

    """
    system_users_list = ["All Users", "Default", "Default User", "Public", "Shared"]
    if ignored_users is None:
        ignored_users = []
    if not isinstance(ignored_users, list):
        ignored_users = [ignored_users]

    deleted_folders = []
    skipped_users = []
    if ignored_users:
        skipped_users.extend(ignored_users)
    if ignore_system_users:
        skipped_users.extend(system_users_list)

    users_dir = ""
    if os.name == "nt":
        users_dir = os.path.join(os.environ["SystemDrive"], "Users")
    elif os.name == "posix":
        users_dir = "/home"
    elif os.name == "mac":
        users_dir = "/Users"

    for user_profile in glob.glob(f"{users_dir}/*/"):
        for ignored_user in ignored_users:
            if user_profile.rstrip(os.path.sep).split(os.path.sep)[-1] == ignored_user:
                continue
        for user_folder_to_delete in glob.glob(f"{os.path.join(user_profile, user_folder_relative_path)}"):
            deleted_folders.append(user_folder_to_delete)
            rmtree(user_folder_to_delete)
    return deleted_folders


def get_file_extension(filename):
    return os.path.splitext(filename)[1]


def format_dict_to_grid(dict_data, key_name="parameter", value_name="value"):
    dict_list_data = []
    for section in dict_data:
        dict_list_data.append({key_name: section, value_name: dict_data[section]})
    return json.dumps(dict_list_data)


def format_grid_to_dict(dict_list_data, key_name="parameter", value_name="value"):
    dict_data = {}
    for entry in dict_list_data:
        dict_data.update({entry[key_name]: entry[value_name]})
    return dict_data
