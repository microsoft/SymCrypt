#!/usr/bin/env python3
"""
Helper script for running SymCrypt unit tests.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import os
import pathlib
import subprocess
import sys
from typing import List

UNITTEST_RELATIVE_PATH = ("exe", "symcryptunittest")
UNITTEST_EXTENSION_WINDOWS = ".exe"

def run_unittest(build_dir : pathlib.Path, emulator : str,
    emulator_lib_dir : pathlib.Path, disable_ymm : bool = False, *additional_args : List[str]) -> int:
    """
    Runs the SymCrypt unit test executable with the given arguments and returns the exit code.

    build_dir: The build directory.
    emulator: The emulator to use when executing unit tests a non-native architecture (e.g. qemu-aarch64).
    emulator_lib_dir: The directory containing system libraries in the target architecture. Required when using --emulator.
    additional_args: A list of additional arguments to pass to the unit test executable.
    """

    # Build the path to the executable
    path_to_exe = os.path.join(build_dir, *UNITTEST_RELATIVE_PATH)
    
    if sys.platform == "win32":
        path_to_exe += UNITTEST_EXTENSION_WINDOWS

        if disable_ymm:
            print("Warning: --glibc-disable-ymm is not supported on Windows.", file = sys.stderr)
            disable_ymm = False

    unittest_invocation = [path_to_exe]
    unittest_invocation.extend(additional_args)

    # If we're using an emulator, prepend the unit test invocation with the emulator information
    if emulator:
        if not emulator_lib_dir:
            print("Error: --emulator-lib-dir is required when using --emulator.", file = sys.stderr)
            exit(-1)

        unittest_invocation = [emulator, "-L", str(emulator_lib_dir.resolve())] + unittest_invocation

    print("Running unit test: " + " ".join(unittest_invocation))

    env = os.environ.copy()
    if disable_ymm:
        env["GLIBC_TUNABLES"] = "glibc.cpu.hwcaps=-AVX_Usable,-AVX_Fast_Unaligned_Load,-AVX2_Usable"

    # Run the test
    try:
        subprocess.run(unittest_invocation, env = env, check = True)
    except subprocess.CalledProcessError as e:
        print("Unit test exited unsuccessfully with code " + str(e.returncode), file = sys.stderr)
        return e.returncode

    return 0

def main() -> int:
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Testing helper script for SymCrypt.")
    parser.add_argument("build_dir", type = pathlib.Path, help = "Build output directory.")
    parser.add_argument("--glibc-disable-ymm", action = "store_true", help = "Run the unit test with the environment configured to disable the use of YMM registers by glibc. This allows validation of YMM save/restore behavior.")
    parser.add_argument("--emulator", type = str, help = "The emulator to use when executing unit test on a non-native architecture (e.g. qemu-aarch64).")
    parser.add_argument("--emulator-lib-dir", type = pathlib.Path, help = "The directory containing system libraries in the target architecture. Required when using --emulator.")
    parser.add_argument("additional_args", nargs = argparse.REMAINDER, help = "Additional arguments to pass to the unit test.")

    args = parser.parse_args()

    result = run_unittest(args.build_dir, args.emulator, args.emulator_lib_dir, args.glibc_disable_ymm, *args.additional_args)
    return result

if __name__ == "__main__":
    main()