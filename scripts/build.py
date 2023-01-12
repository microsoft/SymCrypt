#!/usr/bin/env python3
"""
Build helper script for SymCrypt.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
from typing import List

def get_normalized_host_arch() -> str:
    """
    Gets the host architecture, normalized to Windows conventions, e.g. X86, AMD64, ARM, ARM64
    """

    normalized_arch = None
    host_arch = platform.machine()

    if re.fullmatch("[Xx]86|i[3456]86", host_arch):
        normalized_arch = "X86"
    elif re.fullmatch("AMD64|x86_64", host_arch):
        normalized_arch = "AMD64"
    elif re.fullmatch("ARM64|aarch64", host_arch):
        normalized_arch = "ARM64"

    # No support for ARM32 right now

    if not normalized_arch:
        print("Unrecognized host architecture " + host_arch, file = sys.stderr)
        exit(-1)

    return normalized_arch

def invoke_cmake(args : List[str]) -> None:
    """
    Invokes CMake with the given arguments.

    args: A list of string arguments to pass to CMake.
    """

    cmake_invocation = ["cmake"]
    cmake_invocation.extend(args)

    print("Executing: " + " ".join(cmake_invocation))

    try:
        subprocess.run(cmake_invocation, check = True)
    except subprocess.CalledProcessError as e:
        print("CMake exited unsuccessfully with code " + str(e.returncode), file = sys.stderr)
        exit(e.returncode)

def configure(args : argparse.Namespace) -> None:
    """
    Sets up CMake arguments based on the arguments given to this script, and invokes CMake's
    configuration process accordingly.

    args: The result of argparse.ArgumentParser.parse_args()
    """

    # Starting arguments: -S <source dir> -B <build dir> -DCMAKE_BUILD_TYPE=<build type>
    cmake_args = ["-S", str(args.source_dir), "-B", str(args.build_dir), "-DCMAKE_BUILD_TYPE=" + args.config]

    if args.host_os == "win32":
        cmake_args.append("-A")
        if args.arch == "X86":
            cmake_args.append("Win32")
        elif args.arch == "AMD64":
            cmake_args.append("x64")
        elif args.arch == "ARM64":
            cmake_args.append("arm64")
        
        # No support for ARM32 right now
    
    if args.host_arch != args.arch:
        cmake_args.append("-DSYMCRYPT_TARGET_ARCH=" + args.arch)

    if args.cc:
        cmake_args.append("-DCMAKE_C_COMPILER=" + args.cc)

    if args.cxx:
        cmake_args.append("-DCMAKE_CXX_COMPILER=" + args.cxx)

    if not args.asm:
        cmake_args.append("-DSYMCRYPT_USE_ASM=OFF")

    if not args.fips:
        cmake_args.append("-DSYMCRYPT_FIPS_BUILD=OFF")

    if args.toolchain:
        cmake_args.append("-DCMAKE_TOOLCHAIN_FILE=" + str(args.toolchain))


    if args.verbose:
        cmake_args.append("-DCMAKE_VERBOSE_MAKEFILE=ON")

    if args.clean and args.build_dir.exists():
        shutil.rmtree(args.build_dir)

    if not args.build_dir.exists():
        os.mkdir(args.build_dir)

    invoke_cmake(cmake_args)


def build(args : argparse.Namespace) -> None:
    """
    Sets up CMake build arguments based on the arguments given to this script, and invokes CMake's
    build process accordingly.

    args: The result of argparse.ArgumentParser.parse_args()
    """

    cmake_args = ["--build", str(args.build_dir)]

    if args.host_os == "win32":
        cmake_args.extend(["--config", args.config])

    if args.parallel_build:
        cmake_args.append("-j")

    invoke_cmake(cmake_args)

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Build helper script for SymCrypt.")
    parser.add_argument("build_dir", type = pathlib.Path, help = "Build output directory.")
    parser.add_argument("--arch", type = str, help = "Target architecture. Defaults to host architecture.", choices = ["X86", "AMD64", "ARM64"], default = "")
    parser.add_argument("--config", type = str, help = "Build configuration. Defaults to Debug.", choices = ["Debug", "Release", "Sanitize"], default = "Debug")
    parser.add_argument("--cc", type = str, help = "Specify the C compiler to use. If not provided, uses platform default.")
    parser.add_argument("--cxx", type = str, help = "Specify the C++ compiler to use. If not provided, uses platform default.")
    parser.add_argument("--no-asm", action = "store_false", dest = "asm", help = "Disable handwritten ASM optimizations.", default = True)
    parser.add_argument("--no-fips", action = "store_false", dest = "fips", help = "Disable FIPS selftests and postprocessing of binary. Currently only affects Linux targets.", default = True)
    parser.add_argument("--toolchain", type = pathlib.Path, help = "Toolchain file to use for cross-compiling.")
    parser.add_argument("--clean", action = "store_true", help = "Clean output directory before building.")
    parser.add_argument("--configure-only", action = "store_true", help = "Run CMake configuration, but do not build.")
    parser.add_argument("--no-parallel-build", action = "store_false", dest = "parallel_build", help = "Disable parallel CMake build.", default = True)
    parser.add_argument("--verbose", action = "store_true", help = "Enable CMake verbose mode.", default = False)

    args = parser.parse_args()

    # Add some additional helper values to to the input arguments, and clean up the given build path
    args.source_dir = pathlib.Path(__file__).parent.parent.resolve()
    args.host_os = sys.platform # e.g. win32, linux
    args.host_arch = get_normalized_host_arch()

    # Always convert "Release" builds to "RelWithDebInfo" or the build will not output debug symbols
    if args.config == "Release":
        args.config = "RelWithDebInfo"

    if not args.arch:
        args.arch = args.host_arch

    configure(args)

    if not args.configure_only:
        build(args)

if __name__ == "__main__":
    main()