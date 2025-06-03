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

ARCH_CMAKE = ("x86", "amd64", "arm64", "arm")
CONFIG_CMAKE = ("Debug", "Release", "Sanitize")

ARCH_MSBUILD = ("x86", "amd64", "arm64")
CONFIG_MSBUILD = ("Debug", "Release")

def get_normalized_host_arch() -> str:
    """
    Gets the host architecture, normalized to Windows conventions, e.g. X86, AMD64, ARM64
    """

    normalized_arch = None
    host_arch = platform.machine()

    if re.fullmatch("[Xx]86|i[3456]86", host_arch):
        normalized_arch = "x86"
    elif re.fullmatch("AMD64|x86_64", host_arch):
        normalized_arch = "amd64"
    elif re.fullmatch("ARM64|aarch64|arm64", host_arch):
        normalized_arch = "arm64"
    elif re.fullmatch("ARM32|aarch32|armv8l", host_arch):
        normalized_arch = "arm"

    if not normalized_arch:
        print("Unrecognized host architecture " + host_arch, file = sys.stderr)
        exit(-1)

    return normalized_arch

def invoke_build_tool(tool: str, args : List[str]) -> None:
    """
    Invokes the specified build tool with the given arguments.

    tool: The name of the build tool to invoke, e.g. cmake or msbuild
    args: A list of string arguments to pass to CMake.
    """

    invocation = [tool]
    invocation.extend(args)

    print("Executing: " + " ".join(invocation))

    try:
        subprocess.run(invocation, check = True)
    except subprocess.CalledProcessError as e:
        print("{} exited unsuccessfully with code {}".format(tool, str(e.returncode)), file = sys.stderr)
        exit(e.returncode)

def configure_cmake(args : argparse.Namespace) -> None:
    """
    Sets up CMake arguments based on the arguments given to this script, and invokes CMake's
    configuration process accordingly.

    args: The result of argparse.ArgumentParser.parse_args()
    """

    # Starting arguments: -S <source dir> -B <build dir> -DCMAKE_BUILD_TYPE=<build type> -DPython3_EXECUTABLE=<path_to_this_python>
    cmake_args = ["-S", str(args.source_dir), "-B", str(args.build_dir), "-DCMAKE_BUILD_TYPE=" + args.config, "-DPython3_EXECUTABLE=" + sys.executable]

    if args.host_os == "win32":
        cmake_args.append("-A")
        if args.arch == "x86":
            cmake_args.append("Win32")
        elif args.arch == "amd64":
            cmake_args.append("x64")
        elif args.arch == "arm64":
            cmake_args.append("arm64")
        elif args.arch == "arm":
            cmake_args.append("arm")
        # No support for ARM32 right now

    if args.host_arch != args.arch:
        cmake_args.append("-DSYMCRYPT_TARGET_ARCH=" + args.arch.upper())

    if args.cc:
        cmake_args.append("-DCMAKE_C_COMPILER=" + args.cc)

    if args.cxx:
        cmake_args.append("-DCMAKE_CXX_COMPILER=" + args.cxx)

    if not args.asm:
        cmake_args.append("-DSYMCRYPT_USE_ASM=OFF")

    if not args.fips:
        cmake_args.append("-DSYMCRYPT_FIPS_BUILD=OFF")

    if not args.strip_binary:
        cmake_args.append("-DSYMCRYPT_STRIP_BINARY=OFF")

    if not args.fips_postprocess:
        cmake_args.append("-DSYMCRYPT_FIPS_POSTPROCESS=OFF")

    if args.test_legacy_impl:
        cmake_args.append("-DSYMCRYPT_TEST_LEGACY_IMPL=ON")

    if args.toolchain:
        cmake_args.append("-DCMAKE_TOOLCHAIN_FILE=" + str(args.toolchain))

    if args.verbose:
        cmake_args.append("-DCMAKE_VERBOSE_MAKEFILE=ON")

    if args.openssl_build_from_source:
        cmake_args.append("-DOPENSSL_BUILD_FROM_SOURCE=ON")
        args.openssl = True

    if args.openssl:
        cmake_args.append("-DSYMCRYPT_TEST_WITH_OPENSSL=ON")

    if args.openssl_branch:
        cmake_args.append("-DOPENSSL_BUILD_BRANCH=" + args.openssl_branch)

    if args.libcrux:
        cmake_args.append("-DSYMCRYPT_TEST_LIBCRUX=ON")

    # OPTEE
    if args.optee:
        cmake_args.append("-DSYMCRYPT_OPTEE=ON")

    if args.ta_dev_kit_inc:
        cmake_args.append("-DTA_DEV_KIT_INC=" + args.ta_dev_kit_inc)

    # Experimental SymCRust link
    if args.symcrust:
        cmake_args.append("-DSYMCRYPT_SYMCRUST=ON")

    if args.clean and args.build_dir.exists():
        shutil.rmtree(args.build_dir)

    if not args.build_dir.exists():
        os.mkdir(args.build_dir)

    invoke_build_tool("cmake", cmake_args)


def build_cmake(args : argparse.Namespace) -> None:
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

    if args.target:
        cmake_args.append("--target " + args.target)

    invoke_build_tool("cmake", cmake_args)

def build_msbuild(args : argparse.Namespace) -> None:
    """
    Sets up MSBuild arguments based on the arguments given to this script, and invokes MSBuild's
    build process accordingly.

    args: The result of argparse.ArgumentParser.parse_args()
    """

    # Note: these aliases aren't the same as the ones used by the Visual Studio CMake generator :|
    # (Specifically, MSBuild uses x86 whereas the CMake Visual Studio generator uses Win32)
    ARCH_MSBUILD_ALIASES = {
        "x86": "x86",
        "amd64": "x64",
        "arm64": "ARM64"
    }

    if args.all:
        # Build all architecture/configuration combinations
        for arch in ARCH_MSBUILD:
            for config in CONFIG_MSBUILD:
                print("Building {} {}".format(arch, config))

                msbuild_args = ["/t:Rebuild"]
                msbuild_args.append("/p:Platform=" + ARCH_MSBUILD_ALIASES[arch])
                msbuild_args.append("/p:Configuration=" + config)
                msbuild_args.append(str(args.source_dir / "SymCrypt.sln"))

                invoke_build_tool("msbuild", msbuild_args)

    else:
        # Just build the architecture the user specified
        msbuild_args = ["/t:Rebuild"]

        if args.arch:
            msbuild_args.append("/p:Platform=" + ARCH_MSBUILD_ALIASES[args.arch])

        msbuild_args.extend(["/p:Configuration=" + args.config, str(args.source_dir / "SymCrypt.sln")])

        invoke_build_tool("msbuild", msbuild_args)

def main() -> None:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Build helper script for SymCrypt.")
    subparsers = parser.add_subparsers(title = "Build tools", dest = "build_tool", required = True)

    # CMake build options
    parser_cmake = subparsers.add_parser("cmake", help = "Build using CMake.")

    parser_cmake.add_argument("build_dir", type = pathlib.Path, help = "Build output directory.")
    parser_cmake.add_argument("--arch", type = str.lower, help = "Target architecture. Defaults to host architecture.", choices = ARCH_CMAKE, default = "")
    parser_cmake.add_argument("--config", type = str, help = "Build configuration. Defaults to Debug.", choices = CONFIG_CMAKE, default = "Debug")
    parser_cmake.add_argument("--cc", type = str, help = "Specify the C compiler to use. If not provided, uses platform default.")
    parser_cmake.add_argument("--cxx", type = str, help = "Specify the C++ compiler to use. If not provided, uses platform default.")
    parser_cmake.add_argument("--no-asm", action = "store_false", dest = "asm", help = "Disable handwritten ASM optimizations.", default = True)
    parser_cmake.add_argument("--no-fips", action = "store_false", dest = "fips", help = "Disable FIPS selftests, postprocessing of binary, and remove JitterEntropy dependency. Behavior varies by platform.", default = True)
    parser_cmake.add_argument("--no-strip-binary", action = "store_false", dest = "strip_binary", help = "Disable stripping of binary.", default = True)
    parser_cmake.add_argument("--no-fips-postprocess", action = "store_false", dest = "fips_postprocess", help = "Disable FIPS postprocessing of binary.", default = True)
    parser_cmake.add_argument("--test-legacy-impl", action = "store_true",
        help = "Build unit tests with support for legacy Windows cryptographic implementations. Requires access to private static libraries.",
        default = False)
    parser_cmake.add_argument("--toolchain", type = pathlib.Path, help = "Toolchain file to use for cross-compiling.")
    parser_cmake.add_argument("--clean", action = "store_true", help = "Clean output directory before building.")
    parser_cmake.add_argument("--configure-only", action = "store_true", help = "Run CMake configuration, but do not build.")
    parser_cmake.add_argument("--no-parallel-build", action = "store_false", dest = "parallel_build", help = "Disable parallel CMake build.", default = True)
    parser_cmake.add_argument("--verbose", action = "store_true", help = "Enable CMake verbose mode.", default = False)
    parser_cmake.add_argument("--libcrux", action = "store_true", help = "Enable libcrux performance comparison.", default = False)
    parser_cmake.add_argument("--openssl", action = "store_true", help = "Enable OpenSSL performance comparison.", default = False)
    parser_cmake.add_argument("--openssl-branch", type = str, help = "Checkout and build specified branch of OpenSSL.", default = None)
    parser_cmake.add_argument("--openssl-build-from-source", action = "store_true", help = "Build OpenSSL from source.", default = False)
    parser_cmake.add_argument("--target", type = str, help = "Build a specific target.")

    # OPTEE
    parser_cmake.add_argument("--optee", action = "store_true", help = "Build SymCrypt for OPTEE env.", default = False)
    parser_cmake.add_argument("--ta_dev_kit_inc", type = str, help = "TA DEV KIT include folder, needed for OPTEE TA compilation.")

    # SymCRust
    parser_cmake.add_argument("--symcrust", action = "store_true", help = "Build SymCrypt with experimental Rust (SymCRust) source.", default = False)

    # MSBuild build options
    parser_msbuild = subparsers.add_parser("msbuild", help = "Build using MSBuild.")

    parser_msbuild.add_argument("--arch", type = str.lower, help = "Target architecture. Defaults to host architecture.", choices = ARCH_MSBUILD, default = "")
    parser_msbuild.add_argument("--config", type = str, help = "Build configuration. Defaults to Debug.", choices = CONFIG_MSBUILD, default = "Debug")
    parser_msbuild.add_argument("--all", action = "store_true", help = "Build for all architecture/configuration combinations.", default = False)

    args = parser.parse_args()

    args.source_dir = pathlib.Path(__file__).parent.parent.resolve()

    # Add some additional helper values to to the input arguments
    args.host_os = sys.platform # e.g. win32, linux
    args.host_arch = get_normalized_host_arch()

    if not args.arch:
        args.arch = args.host_arch

    if args.build_tool == "cmake":

        # Always convert "Release" builds to "RelWithDebInfo" or the build will not output debug symbols
        if args.config == "Release":
            args.config = "RelWithDebInfo"

        configure_cmake(args)

        if not args.configure_only:
            build_cmake(args)

    elif args.build_tool == "msbuild":
        build_msbuild(args)


if __name__ == "__main__":
    main()
