#!/usr/bin/env python3
"""
Versioning helper script for SymCrypt. Parses the version information from the SymCrypt headers
and generates buildInfo.h which contains branch and commit info.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Tuple

from devops_utils import set_task_variable

VERSION_INFO_PATH = "version.json"

SHARED_HEADER_INPUT_PATH = "conf/symcrypt_internal_shared.inc.in"
SHARED_HEADER_OUTPUT_PATH = "inc/symcrypt_internal_shared.inc"

BUILD_INFO_INPUT_PATH = "conf/buildInfo.h.in"
BUILD_INFO_OUTPUT_PATH = "inc/buildInfo.h"

GIT_BRANCH_CMD = "git branch --show"
GIT_COMMIT_HASH_CMD = "git log -1 --format=%h"
GIT_COMMIT_TIMESTAMP_CMD = "git log -1 --date=iso-strict-local --format=%cd"
ENV_SYMCRYPT_BRANCH = "SYMCRYPT_BRANCH"
ENV_SYMCRYPT_COMMIT_HASH = "SYMCRYPT_COMMIT_HASH"
ENV_SYMCRYPT_COMMIT_TIMESTAMP = "SYMCRYPT_COMMIT_TIMESTAMP"

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

        # Parse the branch and commit information from the Git log unless set in environment variables

        version_branch = os.environ.get(ENV_SYMCRYPT_BRANCH)
        if version_branch is None:
            try:
                version_branch = subprocess.check_output(GIT_BRANCH_CMD.split()).decode("utf-8").strip()
            except subprocess.CalledProcessError as e:
                print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
                exit(e.returncode)

        version_commit_hash = os.environ.get(ENV_SYMCRYPT_COMMIT_HASH)
        if version_commit_hash is None:
            try:
                version_commit_hash = subprocess.check_output(GIT_COMMIT_HASH_CMD.split()).decode("utf-8").strip()
            except subprocess.CalledProcessError as e:
                print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
                exit(e.returncode)

        version_commit_timestamp = os.environ.get(ENV_SYMCRYPT_COMMIT_TIMESTAMP)
        if version_commit_timestamp is None:
            try:
                version_commit_timestamp = subprocess.check_output(GIT_COMMIT_TIMESTAMP_CMD.split()).decode("utf-8").strip()
            except subprocess.CalledProcessError as e:
                print("git exited unsuccessfully with code {}".format(str(e.returncode)), file = sys.stderr)
                exit(e.returncode)
        # Workaround for Python < 3.11 not supporting the 'Z' suffix for UTC timestamps
        if version_commit_timestamp.endswith("Z"):
            version_commit_timestamp = version_commit_timestamp[:-1] + "+00:00"

        version_commit_timestamp = datetime.datetime.fromisoformat(version_commit_timestamp)

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

    version_info_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", VERSION_INFO_PATH)

    # Parse the version information from the SymCrypt headers
    version_info = json.loads(open(version_info_absolute_path, "r").read())

    version_major = version_info.get("major")
    version_minor = version_info.get("minor")
    version_patch = version_info.get("patch")

    if type(version_major) is not int or type(version_minor) is not int or type(version_patch) is not int:
                raise Exception("Could not parse version from version file " + version_info_absolute_path)

    (version_branch, version_commit_hash, version_commit_timestamp) = get_commit_info()

    version_build_timestamp = datetime.datetime.now()
    get_version_info.symcrypt_version = SymCryptVersion(
        version_major,
        version_minor,
        version_patch,
        version_branch,
        version_commit_hash,
        version_commit_timestamp,
        version_build_timestamp)

    return get_version_info.symcrypt_version

def generate_build_info(version_info: SymCryptVersion) -> None:
    """
    Generates buildInfo.h and symcrypt_internal_shared.inc using the given version info.
    """

    # Generate buildInfo.h from template
    build_info_input_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", BUILD_INFO_INPUT_PATH)
    build_info_output_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", BUILD_INFO_OUTPUT_PATH)

    build_info_template = open(build_info_input_absolute_path, "r").read()

    commit_string = "{}_{}".format(version_info.commit_timestamp.isoformat(timespec = "seconds"), version_info.commit_hash)

    build_info = build_info_template.replace("@SYMCRYPT_BUILD_INFO_BRANCH@", version_info.branch)
    build_info = build_info.replace("@SYMCRYPT_BUILD_INFO_COMMIT@", commit_string)
    build_info = build_info.replace("@SYMCRYPT_BUILD_INFO_TIMESTAMP@", version_info.build_timestamp.isoformat(timespec = "seconds"))

    # Generate symcrypt_internal_shared.inc from template
    shared_header_input_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", SHARED_HEADER_INPUT_PATH)
    shared_header_output_absolute_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", SHARED_HEADER_OUTPUT_PATH)

    shared_header_template = open(shared_header_input_absolute_path, "r").read()

    shared_header = shared_header_template.replace("@SYMCRYPT_VERSION_MAJOR@", str(version_info.major))
    shared_header = shared_header.replace("@SYMCRYPT_VERSION_MINOR@", str(version_info.minor))
    shared_header = shared_header.replace("@SYMCRYPT_VERSION_PATCH@", str(version_info.patch))

    # Write both files to disk
    with open(build_info_output_absolute_path, 'w', encoding = "utf-8") as build_info_output:
        build_info_output.write(build_info)

    with open(shared_header_output_absolute_path, 'w', encoding = "utf-8") as shared_header_output:
        shared_header_output.write(shared_header)

def print_devops_vars(version_info: SymCryptVersion) -> None:
    """
    Prints the version information in a format suitable for setting Azure DevOps variables.
    """

    set_task_variable("VER_MAJOR", version_info.major)
    set_task_variable("VER_MINOR", version_info.minor)
    set_task_variable("VER_PATCH", version_info.patch)

def print_commit_info(version_info: SymCryptVersion) -> None:
    """
    Prints the commit information as environment variables that would override the commit hash and timestamp.
    """

    print("export {}={}".format(ENV_SYMCRYPT_BRANCH, version_info.branch))
    print("export {}={}".format(ENV_SYMCRYPT_COMMIT_HASH, version_info.commit_hash))
    print("export {}={}".format(ENV_SYMCRYPT_COMMIT_TIMESTAMP, version_info.commit_timestamp.isoformat(timespec = "seconds")))

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Versioning helper script for SymCrypt.")
    parser.add_argument("--no-print-version-number", dest = "print_version_number", help = "Do not print the version number", action = "store_false", default = True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", "--build-info", help = "Generate buildInfo.h", action = "store_true")
    group.add_argument("--devops", help = "Format output to set Azure DevOps variables", action = "store_true")
    group.add_argument("--commit-info",
        help = "Format commit info as environment variables that would override the commit hash and timestamp, which can then be used when building from the source tarball rather than a git clone.",
        action = "store_true")

    args = parser.parse_args()

    # Parse the version information from the SymCrypt headers
    version_info = get_version_info()

    if args.print_version_number:
        print("{}.{}.{}".format(version_info.major, version_info.minor, version_info.patch))

    if args.build_info:
        generate_build_info(version_info)
    elif args.devops:
        print_devops_vars(version_info)
    elif args.commit_info:
        print_commit_info(version_info)

if __name__ == "__main__":
    main()
