#!/usr/bin/env python3
"""
Packaging helper script for SymCrypt.

NOTE: For Windows targets, this script only works with MSBuild builds, because CMake cannot build
Windows kernel drivers.

This script reads the package configuration from SymCryptPackage.json in the repo root, which
contains a list of files in the following format:

   {
       "source" : "...",
       "dest" : "...",
       "platform" : "...",
       "arch"  : "...",
       "config" : "..."
   }

where:

  source: The source file path
  dest: The destination file path
  platform: Platforms to include the file ("win32", "linux")
  arch: Architectures to include the file ("x86", "amd64", "arm", "arm64")
  config: Configurations to include the file ("debug", "release", "sanitize")

Multiple platforms, architectures, and configurations can be specified by separating them with commas,
e.g. "windows,linux" or "x86,amd64". If platform, arch or config are omitted, the file will be included
on all platforms, architectures, or configurations, respectively.

The following special tokens in the source and destination paths:

  ${SOURCE_DIR}: The root of the SymCrypt source tree
  ${BIN_DIR}: The build output directory
  ${MODULE_NAME}: The name of the module to package (currently only relevant for Linux)
  ${VERSION_API}: SymCrypt API version
  ${VERSION_MINOR}: Minor version
  ${VERSION_PATCH}: Patch version

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Tuple

from version import SymCryptVersion, get_version_info

def get_file_list(bin_dir : pathlib.Path, config : str, module_name : str) -> Dict[str, str]:
    """
    Replaces variables in the package file map with their actual values.

    bin_dir: The build output directory.
    module_name: The name of the module being packaged.
    config: The build configuration (Debug/Release/Sanitize)
    """

    source_dir = pathlib.Path(__file__).parent.parent.resolve()
    version = get_version_info()

    replacement_map = {
        "${SOURCE_DIR}" : str(source_dir),
        "${BIN_DIR}" : str(bin_dir.resolve()),
        "${MODULE_NAME}" : module_name,
        "${VERSION_API}" : str(version.major),
        "${VERSION_MINOR}" : str(version.minor),
        "${VERSION_PATCH}" : str(version.patch)
    }

    file_list = []
    with open(source_dir / "SymCryptPackage.json") as f:
        file_json = json.load(f)

        for file in file_json:
            for replacement_key, replacement_value in replacement_map.items():
                file["source"] = file["source"].replace(replacement_key, replacement_value)
                file["dest"] = file["dest"].replace(replacement_key, replacement_value)

            file_list.append(file)

    return file_list

def prepare_package(build_dir : pathlib.Path, package_dir : pathlib.Path,
    arch : str, config : str, module_name : str) -> None:
    """
    Prepares the files for packaging by copying them into a temporary directory. Does not create the archive.

    build_dir: The build output directory.
    package_dir: The directory to copy the files to. Must be an existing directory.
    arch: Architecture of the binaries to package (for inclusion in the package name).
    config: The build configuration (Debug/Release/Sanitize).
    module_name: The name of the module to package.
    """

    file_list = get_file_list(build_dir, config, module_name)
    for file in file_list:

        target_platform = file.get("platform")
        target_arch = file.get("arch")
        target_config = file.get("config")

        if target_platform is not None and sys.platform not in target_platform.split(","):
            continue

        if target_arch is not None and arch not in target_arch.split(","):
            continue

        if target_config is not None and config not in target_config.split(","):
            continue

        print("Copying " + file["dest"])

        source = pathlib.Path(file["source"])
        destination = pathlib.Path(file["dest"])

        if not source.exists():
            raise Exception("Source file " + str(source) + " does not exist.")

        destination = package_dir / destination

        if not destination.parent.exists():
            destination.parent.mkdir(parents = True)

        # Do not follow symlinks, as we want to preserve relative symlinks in the package
        # e.g. libsymcrypt.so -> libsymcrypt.so.x
        shutil.copy(source, destination, follow_symlinks = False)

def create_archive(package_dir : pathlib.Path, release_dir : pathlib.Path, 
    arch : str, config : str, module_name : str) -> None:
    """
    Creates an archive of the package by compressing the files in the package directory into a zip
    or tar.gz archive, depending on the platform.

    package_dir: The directory to place the package files in. Must be an existing directory.
    release_dir: The directory to place the archive in. Must be an existing directory.
    arch: Architecture of the binaries to package (for inclusion in the package name).
    config: The build configuration (Debug/Release/Sanitize).
    module_name: The name of the module to package.
    """

    version = get_version_info()

    archive_name = "symcrypt-{}-{}-{}-{}-{}.{}.{}-{}".format(
        sys.platform,
        module_name,
        arch,
        config,
        str(version.major),
        str(version.minor),
        str(version.patch),
        version.commit_hash
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
    try:
        os.chdir(release_dir)

        if os.path.exists(archive_name + archive_ext):
            raise Exception("Archive " + archive_name + archive_ext + " already exists.")

        print("Creating archive " + archive_name + " in " + str(release_dir.resolve()) + "...")

        shutil.make_archive(archive_name, archive_type, package_dir, owner = "root", group = "root")

        print("Done.")

    finally:
        os.chdir(cwd)

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Packaging helper script for SymCrypt.")
    parser.add_argument("build_dir", type = pathlib.Path, help = "Build output directory.")
    parser.add_argument("arch", type = str.lower, help = "Architecture of the binaries to package (for inclusion in the package name).", choices = ("x86", "amd64", "arm64", "arm"))
    parser.add_argument("config", type = str.lower, help = "Build configuration.", choices = ("debug", "release", "sanitize"))
    parser.add_argument("module_name", type = str, help = "Name of the module to package.")
    parser.add_argument("release_dir", type = pathlib.Path, help = "Directory to place the release in.")
    parser.add_argument("--no-archive", action = "store_true", help = "Do not create a compressed archive, just copy the files.", default = False)

    args = parser.parse_args()

    # Try to create the release directory first to check for permissions
    if args.no_archive and args.release_dir.exists():
        print("Directory " + str(args.release_dir) + " already exists; please remove it first.")
        exit(-1)

    args.release_dir.mkdir(parents = True, exist_ok = True)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = pathlib.Path(temp_dir)
        prepare_package(args.build_dir, temp_dir, args.arch, args.config, args.module_name)

        if args.no_archive:
            print("Copying tree to " + str(args.release_dir.resolve()) + "...")
            shutil.copytree(temp_dir, args.release_dir, symlinks = True, dirs_exist_ok = True)
            print("Done.")
        else:
            create_archive(temp_dir, args.release_dir, args.arch, args.config, args.module_name)

if __name__ == "__main__":
    main()