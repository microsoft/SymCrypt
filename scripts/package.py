#!/usr/bin/env python3
"""
Packaging helper script for SymCrypt.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Tuple

SYMCRYPT_VERSION_FILE = "inc/symcrypt_internal_shared.inc"

# Common files shared between all packages
PACKAGE_FILE_MAP_TEMPLATE_COMMON = {
    "${SOURCE_DIR}/CHANGELOG.md" : "CHANGELOG.md",
    "${SOURCE_DIR}/LICENSE" : "LICENSE",
    "${SOURCE_DIR}/NOTICE" : "NOTICE",
    "${SOURCE_DIR}/README.md" : "README.md",
    "${SOURCE_DIR}/inc/symcrypt.h" : "inc/symcrypt.h",
    "${SOURCE_DIR}/inc/symcrypt_low_level.h" : "inc/symcrypt_low_level.h",
    "${SOURCE_DIR}/inc/symcrypt_internal.h" : "inc/symcrypt_internal.h",
    "${SOURCE_DIR}/inc/symcrypt_internal_shared.inc" : "inc/symcrypt_internal_shared.inc"
}

# Linux sanitize package - doesn't build shared object libraries
PACKAGE_FILE_MAP_TEMPLATE_LINUX_SANITIZE = PACKAGE_FILE_MAP_TEMPLATE_COMMON.copy()
PACKAGE_FILE_MAP_TEMPLATE_LINUX_SANITIZE.update({
    "${BIN_DIR}/symcrypt.pc" : "lib/pkgconfig/symcrypt.pc",
    "${BIN_DIR}/exe/symcryptunittest" : "test/symcryptunittest"
})

# Linux debug package
PACKAGE_FILE_MAP_TEMPLATE_LINUX_DEBUG = PACKAGE_FILE_MAP_TEMPLATE_LINUX_SANITIZE.copy()
PACKAGE_FILE_MAP_TEMPLATE_LINUX_DEBUG.update({
    "${BIN_DIR}/module/${MODULE_NAME}/libsymcrypt.so" : "lib/libsymcrypt.so",
    "${BIN_DIR}/module/${MODULE_NAME}/libsymcrypt.so.${VERSION_API}" : "lib/libsymcrypt.so.${VERSION_API}",
    "${BIN_DIR}/module/${MODULE_NAME}/libsymcrypt.so.${VERSION_API}.${VERSION_MINOR}.${VERSION_PATCH}" : "lib/libsymcrypt.so.${VERSION_API}.${VERSION_MINOR}.${VERSION_PATCH}",
})

# Linux release package
# The release package is the same as the debug package, except that we add the debug copy of
# libsymcrypt.so, which is placed in the .debug subdirectory. The debug package does not include
# this file because the main binary is not stripped of debugging symbols in the debug package.
PACKAGE_FILE_MAP_TEMPLATE_LINUX_RELEASE = PACKAGE_FILE_MAP_TEMPLATE_LINUX_DEBUG.copy()
PACKAGE_FILE_MAP_TEMPLATE_LINUX_RELEASE.update({
    "${BIN_DIR}/module/${MODULE_NAME}/.debug/libsymcrypt.so.${VERSION_API}.${VERSION_MINOR}.${VERSION_PATCH}" : "lib/.debug/libsymcrypt.so.${VERSION_API}.${VERSION_MINOR}.${VERSION_PATCH}",
})

# Windows debug package
PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_DEBUG = PACKAGE_FILE_MAP_TEMPLATE_COMMON.copy()
PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_DEBUG.update({
    "${BIN_DIR}\\exe\\symcrypttestmodule.dll" : "test\\symcrypttestmodule.dll", 
    "${BIN_DIR}\\exe\\symcryptunittest.exe" : "test\\symcryptunittest.exe", 
    "${BIN_DIR}\\exe\\symcryptunittest_legacy.exe" : "test\\symcryptunittest_legacy.exe", 
    "${BIN_DIR}\\exe\\symcryptunittest_win7nlater.exe" : "test\\symcryptunittest_win7nlater.exe", 
    "${BIN_DIR}\\exe\\symcryptunittest_win8_1nlater.exe" : "test\\symcryptunittest_win8_1nlater.exe", 
})

# Windows release package
# Like Linux, we need to add debugging information (PDB files) which are stripped from the binaries
# in Release builds
PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_RELEASE = PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_DEBUG.copy()
PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_RELEASE.update({
    "${BIN_DIR}\\exe\\symcrypttestmodule.pdb" : "test\\symcrypttestmodule.pdb", 
    "${BIN_DIR}\\exe\\symcryptunittest.pdb" :  "test\\symcryptunittest.pdb", 
    "${BIN_DIR}\\exe\\symcryptunittest_legacy.pdb" : "test\\symcryptunittest_legacy.pdb", 
    "${BIN_DIR}\\exe\\symcryptunittest_win7nlater.pdb" : "test\\symcryptunittest_win7nlater.pdb",
    "${BIN_DIR}\\exe\\symcryptunittest_win8_1nlater.pdb" : "test\\symcryptunittest_win8_1nlater.pdb"
})

PACKAGE_FILE_TEMPLATES = {
    ("linux", "release") : PACKAGE_FILE_MAP_TEMPLATE_LINUX_RELEASE,
    ("linux", "debug") : PACKAGE_FILE_MAP_TEMPLATE_LINUX_DEBUG,
    ("linux", "sanitize") : PACKAGE_FILE_MAP_TEMPLATE_LINUX_SANITIZE,
    ("win32", "release") : PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_RELEASE,
    ("win32", "debug") : PACKAGE_FILE_MAP_TEMPLATE_WINDOWS_DEBUG
    # Sanitize is not currently supported on Windows
}

def get_git_hash() -> str:
    """
    Returns the short git hash of the current commit.
    """

    git_hash_cmd = "git rev-parse --short HEAD"
    git_hash = subprocess.check_output(git_hash_cmd, shell = True).decode("utf-8").strip()

    return git_hash

def read_version() -> Tuple[int, int, int]:
    """
    Reads the current version of SymCrypt from the version file. Returns a tuple of (major, minor, patch).
    """

    # Store the version in a "static" variable so we don't have to read it from disk every time
    if not hasattr(read_version, "version_api"):
        read_version.version_api = None
        read_version.version_minor = None
        read_version.version_patch = None

    if read_version.version_api is None:
        version_file = pathlib.Path(SYMCRYPT_VERSION_FILE)

        if not version_file.exists():
            raise Exception("Version file " + str(version_file) + " does not exist.")

        with open(version_file, "r") as f:
            version_file_contents = f.read()

            version_api_match = re.search(r"#define SYMCRYPT_CODE_VERSION_API[ \t]+([0-9]+)", version_file_contents)
            version_minor_match = re.search(r"#define SYMCRYPT_CODE_VERSION_MINOR[ \t]+([0-9]+)", version_file_contents)
            version_patch_match = re.search(r"#define SYMCRYPT_CODE_VERSION_PATCH[ \t]+([0-9]+)", version_file_contents)

            if not version_api_match or not version_minor_match or not version_patch_match:
                raise Exception("Could not parse version from version file " + str(version_file))

            read_version.version_api = int(version_api_match.group(1))
            read_version.version_minor = int(version_minor_match.group(1))
            read_version.version_patch = int(version_patch_match.group(1))

    return (read_version.version_api, read_version.version_minor, read_version.version_patch)

def get_package_file_map(bin_dir : pathlib.Path, config : str, module_name : str) -> Dict[str, str]:
    """
    Replaces variables in the package file map with their actual values.

    bin_dir: The build output directory.
    module_name: The name of the module being packaged.
    config: The build configuration (Debug/Release/Sanitize)
    """

    source_dir = pathlib.Path(__file__).parent.parent.resolve()
    version_api, version_minor, version_patch = read_version()

    replacement_map = {
        "${SOURCE_DIR}" : str(source_dir),
        "${BIN_DIR}" : str(bin_dir.resolve()),
        "${MODULE_NAME}" : module_name,
        "${VERSION_API}" : str(version_api),
        "${VERSION_MINOR}" : str(version_minor),
        "${VERSION_PATCH}" : str(version_patch)
    }

    try:
        template = PACKAGE_FILE_TEMPLATES[(sys.platform, config.lower())]
    except KeyError:
        raise Exception("Unsupported platform or configuration: " + sys.platform + " " + config)

    package_file_map = {}

    for key, value in template.items():
        for replacement_key, replacement_value in replacement_map.items():
            key = key.replace(replacement_key, replacement_value)
            value = value.replace(replacement_key, replacement_value)

        package_file_map[key] = value

    return package_file_map

def package_module(build_dir : pathlib.Path, arch : str, config : str, module_name : str,
    release_dir : pathlib.Path) -> None:
    """
    Packages the module.

    build_dir: The build output directory.
    arch: Architecture of the binaries to package (for inclusion in the package name).
    config: The build configuration (Debug/Release/Sanitize).
    module_name: The name of the module to package.
    release_dir: The directory to place the release in.
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = pathlib.Path(temp_dir)

        package_file_map = get_package_file_map(build_dir, config, module_name)
        for source, destination in package_file_map.items():
            source = pathlib.Path(source)
            destination = pathlib.Path(destination)

            if not source.exists():
                raise Exception("Source file " + str(source) + " does not exist.")

            destination = temp_dir / destination

            if not destination.parent.exists():
                destination.parent.mkdir(parents = True)

            # Do not follow symlinks, as we want to preserve relative symlinks in the package
            # e.g. libsymcrypt.so -> libsymcrypt.so.x
            shutil.copy(source, destination, follow_symlinks = False)

        if not release_dir.exists():
            release_dir.mkdir(parents = True)

        version_api, version_minor, version_patch = read_version()
        git_hash = get_git_hash()

        archive_name = "symcrypt-{}-{}-{}-{}.{}.{}-{}".format(
            sys.platform,
            module_name,
            arch,
            str(version_api),
            str(version_minor),
            str(version_patch),
            git_hash
        )

        archive_type = None
        archive_ext = None
        if sys.platform == "linux":
            archive_type = "gztar"
            archive_ext = ".tar.gz"
        elif sys.platform == "win32":
            archive_type = "zip"
            archive_ext = ".zip"
        else:
            raise Exception("Unsupported platform: " + sys.platform)

        cwd = os.getcwd()
        os.chdir(release_dir)

        if os.path.exists(archive_name + archive_ext):
            raise Exception("Archive " + archive_name + archive_ext + " already exists.")

        print("Creating archive " + archive_name + " in " + str(release_dir.resolve()) + "...")

        shutil.make_archive(archive_name, archive_type, temp_dir, owner = "root", group = "root")

        os.chdir(cwd)

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Packaging helper script for SymCrypt.")
    parser.add_argument("build_dir", type = pathlib.Path, help = "Build output directory.")
    parser.add_argument("arch", type = str, help = "Architecture of the binaries to package (for inclusion in the package name).", choices = ["X86", "AMD64", "ARM64"])
    parser.add_argument("config", type = str, help = "Build configuration.", choices = ["Debug", "Release", "Sanitize"])
    parser.add_argument("module_name", type = str, help = "Name of the module to package.")
    parser.add_argument("release_dir", type = pathlib.Path, help = "Directory to place the release in.")

    args = parser.parse_args()

    package_module(args.build_dir, args.arch, args.config, args.module_name, args.release_dir)

if __name__ == "__main__":
    main()