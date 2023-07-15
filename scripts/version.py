#!/usr/bin/env python3
"""
Versioning helper script for SymCrypt. Parses the version information from the SymCrypt headers
and generates buildInfo.h which contains branch and commit info.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import datetime
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Tuple

from devops_utils import set_task_variable

BUILD_INFO_INPUT_PATH = "build/buildInfo.h.in"
BUILD_INFO_OUTPUT_PATH = "inc/buildInfo.h"
VERSION_INFO_RELATIVE_PATH = "inc/symcrypt_internal_shared.inc"
GIT_BRANCH_CMD = "git branch --show"
GIT_COMMIT_HASH_CMD = "git log -1 --format=%h"
GIT_COMMIT_TIMESTAMP_CMD = "git log -1 --date=iso-strict-local --format=%cd"

@dataclass
class SymCryptVersion:
    """
    Represents the SymCrypt version information.
    """

    major: int
    minor: int
    patch: int
    branch: str
    commit_hash: str
    commit_timestamp: datetime.datetime
    build_timestamp: datetime.datetime

def get_commit_info() -> Tuple[str, str, datetime.datetime]:
    """
    Invokes git to get the branch name, commit hash, and commit timestamp.
    """

    version_branch = None
    version_commit_hash = None
    version_commit_timestamp = None

    # Ensure we're in the correct working directory for Git commands
    cwd = os.getcwd()
    try:
        os.chdir(pathlib.Path(__file__).parent.parent)

        # Parse the branch and commit information from the Git log

        try:
            version_branch = subprocess.check_output(GIT_BRANCH_CMD.split()).decode("utf-8").strip()
        except subprocess.CalledProcessError as e:
            print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
            exit(e.returncode)

        try:
            version_commit_hash = subprocess.check_output(GIT_COMMIT_HASH_CMD.split()).decode("utf-8").strip()
        except subprocess.CalledProcessError as e:
            print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
            exit(e.returncode)

        try:
            version_commit_timestamp = subprocess.check_output(GIT_COMMIT_TIMESTAMP_CMD.split()).decode("utf-8").strip()
            version_commit_timestamp = datetime.datetime.fromisoformat(version_commit_timestamp)
        except subprocess.CalledProcessError as e:
            print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
            exit(e.returncode)
    finally:
        os.chdir(cwd)

    return (version_branch, version_commit_hash, version_commit_timestamp)

def get_version_info() -> SymCryptVersion:
    """
    Parses the version information from the SymCrypt headers and Git commit log.
    """

    # Store the version in a "static" variable so we don't have to re-process it every time if this
    # function is called multiple times by another script
    if not hasattr(get_version_info, "symcrypt_version"):
        get_version_info.symcrypt_version = None

    if get_version_info.symcrypt_version is not None:
        return get_version_info.symcrypt_version

    version_info_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", VERSION_INFO_RELATIVE_PATH)

    # Parse the version information from the SymCrypt headers
    version_info_contents = open(version_info_absolute_path, "r").read()

    version_api_match = re.search(r"#define SYMCRYPT_CODE_VERSION_API\s+(\d+)", version_info_contents)
    version_minor_match = re.search(r"#define SYMCRYPT_CODE_VERSION_MINOR\s+(\d+)", version_info_contents)
    version_patch_match = re.search(r"#define SYMCRYPT_CODE_VERSION_PATCH\s+(\d+)", version_info_contents)

    if not version_api_match or not version_minor_match or not version_patch_match:
                raise Exception("Could not parse version from version file " + version_info_absolute_path)

    (version_branch, version_commit_hash, version_commit_timestamp) = get_commit_info()

    version_build_timestamp = datetime.datetime.now()
    
    get_version_info.symcrypt_version = SymCryptVersion(
        int(version_api_match.group(1)),
        int(version_minor_match.group(1)),
        int(version_patch_match.group(1)),
        version_branch,
        version_commit_hash,
        version_commit_timestamp,
        version_build_timestamp)

    return get_version_info.symcrypt_version

def generate_build_info(version_info: SymCryptVersion) -> None:
    """
    Generates buildInfo.h using the given version info.
    """

    build_info_input_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", BUILD_INFO_INPUT_PATH)

    build_info_template = open(build_info_input_absolute_path, "r").read()

    commit_string = "{}_{}".format(version_info.commit_timestamp.isoformat(timespec = "seconds"), version_info.commit_hash)

    build_info = build_info_template.replace("@SYMCRYPT_BUILD_INFO_BRANCH@", version_info.branch)
    build_info = build_info.replace("@SYMCRYPT_BUILD_INFO_COMMIT@", commit_string)
    build_info = build_info.replace("@SYMCRYPT_BUILD_INFO_TIMESTAMP@", version_info.build_timestamp.isoformat(timespec = "seconds"))

    build_info_output_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", BUILD_INFO_OUTPUT_PATH)

    with open(build_info_output_absolute_path, 'w', encoding = "utf-8") as build_info_output:
        build_info_output.write(build_info)

def print_devops_vars(version_info: SymCryptVersion) -> None:
    """
    Prints the version information in a format suitable for setting Azure DevOps variables.
    """

    set_task_variable("VER_MAJOR", version_info.major)
    set_task_variable("VER_MINOR", version_info.minor)
    set_task_variable("VER_PATCH", version_info.patch)

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Versioning helper script for SymCrypt.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", "--build-info", help = "Generate buildInfo.h", action = "store_true")
    group.add_argument("--devops", help = "Format output to set Azure DevOps variables", action = "store_true")

    args = parser.parse_args()

    # Parse the version information from the SymCrypt headers
    version_info = get_version_info()

    print("{}.{}.{}".format(version_info.major, version_info.minor, version_info.patch))

    if args.build_info:
        generate_build_info(version_info)
    elif args.devops:
        print_devops_vars(version_info)

if __name__ == "__main__":
    main()