#!/usr/bin/env python3
"""
Build helper script for SymCRust; wraps cargo to select the Rust toolchain and cargo config for a
given SymCRust build configuration.

The first argument must be the SymCRust build configuration:
  Public - Use the toolchain pinned by rust-toolchain.toml and the default .cargo/config.toml
           (suitable for external builds).
  MSRust - Additionally select the Microsoft internal toolchain channel and layer on
           .cargo/config_internal.toml (used by internal official and development builds).
Additional configurations may be added here in the future.

All remaining arguments are passed through to cargo unchanged.

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import pathlib
import subprocess
import sys

# Overwrites the default channel specified in rust-toolchain.toml
# NOTE: Ensure this is in sync with the rustVersion in the .pipelines
INTERNAL_TOOLCHAIN_CHANNEL = "ms-prod-1.93"
# Adds internal cargo configuration beyond the default .cargo/config.toml
INTERNAL_CARGO_CONFIG_TOML = (
    pathlib.Path(__file__).resolve().parent
    / ".cargo/config_internal.toml" )

SYMCRUST_CONFIGS = ("Public", "MSRust")

if len(sys.argv) < 2 or sys.argv[1] not in SYMCRUST_CONFIGS:
    print(
        f"symcrust_cargo.py: first argument must be one of {', '.join(SYMCRUST_CONFIGS)}",
        file=sys.stderr )
    sys.exit(2)

symcrust_config = sys.argv[1]
cargo_args = sys.argv[2:]

cmd = ["cargo"]

if symcrust_config == "MSRust":
    cmd.append(f"+{INTERNAL_TOOLCHAIN_CHANNEL}")
    cmd.append(f"--config={INTERNAL_CARGO_CONFIG_TOML}")
    print(f"symcrust_cargo.py config=MSRust TOOLCHAIN:{INTERNAL_TOOLCHAIN_CHANNEL} CONFIG_TOML:{INTERNAL_CARGO_CONFIG_TOML}")
else:
    print("symcrust_cargo.py config=Public (default toolchain and config)")

cmd.extend(cargo_args)

print(f"cmd:{cmd}")

sys.exit(subprocess.call(cmd))
