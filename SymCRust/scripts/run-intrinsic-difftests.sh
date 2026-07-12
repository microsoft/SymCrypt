#!/usr/bin/env bash
#
# run-intrinsic-difftests.sh — run the SymCRust intrinsic differential tests
# and enforce that each one produced *real* evidence (N > 0 rows, 0 failures).
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT ENFORCES
# ---------------------------------------------------------------------------
# Each harness under `src/verify/tests/<arch>_<ext>_hw.rs` cross-checks a Rust
# intrinsic *model* (`src/verify/intrinsics/**`) against the REAL hardware
# intrinsic:  model(x) == core::arch::<arch>::<intrinsic>(x)  (or a NIST KAT
# for the axiomatised crypto opcodes). This is the "§1 P7" empirical evidence
# behind the `lean/Intrinsics` axioms and theorems.
#
# For every harness it decides to run, this script:
#   1. builds/runs it with the EXACT `RUSTFLAGS="-C target-feature=+..."` that
#      the harness needs (without them the silicon side is `#[cfg]`-compiled
#      out and the harness silently executes 0 rows);
#   2. parses `test result: ok. N passed; M failed`;
#   3. FAILS unless  M == 0  AND  N > 0.
# The `N > 0` clause is the whole point: it rejects the "vacuous green" 0-row
# run that a wrong/missing target-feature produces.
#
# It does NOT prove anything and is NOT required for `lake build` / the Lean
# proofs — those stand on their own. This is reproducible empirical evidence
# for the trust boundary, nothing more.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT CANNOT ENFORCE ON ITS OWN  (the multiarch caveat)
# ---------------------------------------------------------------------------
# `-C target-feature=+X` tells the compiler to ASSUME feature X is present. If
# the host CPU does NOT actually have X, the harness will execute an illegal
# instruction and crash (SIGILL) — it is *not* a graceful skip. Therefore a
# single run on one machine can only exercise the extensions THAT MACHINE has:
#
#   * A given harness is run only if the host CPU advertises its feature
#     (probed from /proc/cpuinfo on Linux, `sysctl`/`sysinfo` elsewhere).
#     Features the host lacks are reported as SKIPPED (host-missing), never as
#     pass and never as fail — the gap is surfaced, not hidden.
#   * SHA-NI in particular is absent on many cloud/CI CPUs, so `sha_ni_*` will
#     usually SKIP unless you run on SHA-capable silicon.
#   * The aarch64 harnesses (`aarch64_*`) only execute on an aarch64 host, or
#     under qemu-user with an aarch64 cross-build (`--qemu`, see below). On an
#     x86_64 host without qemu they are SKIPPED (running the x86 binary would
#     compile them to 0 rows — vacuous — which we refuse to count).
#
# => FULL coverage of the intrinsic trust boundary requires running this
#    script across a MATRIX of hosts:
#       - an x86_64 host WITH aes+pclmulqdq+avx2 (covers the SHA-3/ML-KEM
#         in-scope subset: SSE2/AVX/AVX2, plus AES-NI/PCLMULQDQ for AES/GCM);
#       - an x86_64 host WITH sha_ni (covers SHA-NI, for SHA-2);
#       - an aarch64 host (or `--qemu` on x86) WITH neon+aes (covers NEON/AES).
#    No single machine can witness them all. The final summary prints exactly
#    which harnesses RAN, which were SKIPPED (and why), and which FAILED, so a
#    CI matrix can aggregate the per-host results into full coverage.
#
# Scope reminder: only SSE2, AVX, AVX2 (x86_64) and NEON (aarch64) are in the
# trust base of the primitives verified in THIS release (SHA-3, ML-KEM). The
# AES-NI / SHA-NI / PCLMULQDQ / aarch64-AES harnesses cover models used only
# by other/forthcoming primitives (see lean/Intrinsics/INTRINSICS.md §2).
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   scripts/run-intrinsic-difftests.sh [--qemu] [--require <feat[,feat...]>]
#                                      [--list] [-h|--help]
#
#   --qemu              Also run the aarch64 harnesses via an aarch64 cross
#                       build under qemu-user (needs the aarch64 target,
#                       aarch64-linux-gnu-gcc and qemu-aarch64-static).
#   --require <feats>   Comma-separated features that MUST run (else the script
#                       exits non-zero even though they were host-missing).
#                       Use in CI on a runner you KNOW has them, to prevent a
#                       silently-degraded run from passing. e.g.
#                       --require avx2,aes,pclmulqdq
#   --list              Print the harness/feature/RUSTFLAGS matrix and exit.
#   --toolchain <name>  Run cargo with `+<name>` (e.g. `stable`). This crate's
#                       `rust-toolchain` pins an internal production toolchain
#                       that a public checkout will not have; the differential
#                       harnesses need no nightly features, so any recent
#                       stable/nightly works. Also settable via
#                       DIFFTEST_TOOLCHAIN. If unset, cargo uses the pinned
#                       toolchain (fine inside the internal environment).
#   -h, --help          This help.
#
# Run from the SymCRust/ directory (or anywhere inside the crate).
#
# We build the harnesses with `--features benchmarking` (which implies `std`
# but tells build.rs to skip linking libsymcrypt): the differential tests only
# compare intrinsic models against `core::arch`, so they need no C library and
# no SYMCRYPT_LIB_PATH. (`--features std` alone would force the C link.)
set -uo pipefail

# --- harness matrix -------------------------------------------------------
# Each row: harness-name-filter | cpu-feature | RUSTFLAGS target-feature list
# The cpu-feature is the token looked up in the host capability probe.
# The single registered test target is `intrinsics_verify_tests`
# (src/verify/tests/mod.rs); we select a harness with a name filter.
X86_MATRIX=(
  "x86_64_sse2_hw_extras|sse2|+sse2"
  "x86_64_avx2_hw|avx2|+avx2"
  "x86_64_ymm_hw|avx2|+avx2"
  "x86_64_pclmulqdq_hw|pclmulqdq|+pclmulqdq"
  "x86_64_aes_hw|aes|+aes"
  "sha_ni_intrinsics_hw|sha_ni|+sha,+sse4.1,+ssse3"
)
# aarch64 harnesses (run natively on aarch64, or under --qemu from x86):
ARM_MATRIX=(
  "aarch64_neon_hw|neon|+neon"
  "aarch64_aes_hw|aes|+neon,+aes"
)

QEMU=0
LIST=0
REQUIRE=""
TOOLCHAIN="${DIFFTEST_TOOLCHAIN:-}"   # e.g. "stable" / "nightly-YYYY-MM-DD"

usage() { sed -n '2,120p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --qemu) QEMU=1; shift;;
    --require) REQUIRE="${2:-}"; shift 2;;
    --toolchain) TOOLCHAIN="${2:-}"; shift 2;;
    --list) LIST=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 2;;
  esac
done

# --- locate crate root ----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"      # SymCRust/
cd "$CRATE_DIR"

if [ "$LIST" = 1 ]; then
  printf '%-24s %-12s %s\n' "HARNESS" "CPU-FEATURE" "RUSTFLAGS target-feature"
  for row in "${X86_MATRIX[@]}" "${ARM_MATRIX[@]}"; do
    IFS='|' read -r h f rf <<<"$row"; printf '%-24s %-12s %s\n' "$h" "$f" "$rf"
  done
  exit 0
fi

# --- host capability probe ------------------------------------------------
HOST_ARCH="$(uname -m)"
declare -A HAVE                 # HAVE[feature]=1 if host CPU supports it

probe_x86_features() {
  # cpuinfo flag names: sse2 ssse3 avx avx2 aes pclmulqdq sha_ni
  local flags=""
  if [ -r /proc/cpuinfo ]; then
    flags="$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2)"
  elif command -v sysctl >/dev/null 2>&1; then
    flags="$(sysctl -n machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null | tr 'A-Z.' 'a-z_')"
  fi
  for f in sse2 ssse3 avx avx2 aes pclmulqdq sha_ni; do
    case " $flags " in *" $f "*) HAVE[$f]=1;; esac
  done
  # macOS/other spellings
  case " $flags " in *" pclmulqdq "*|*" pclmul "*) HAVE[pclmulqdq]=1;; esac
}

probe_arm_features() {
  local flags=""
  [ -r /proc/cpuinfo ] && flags="$(grep -m1 -E '^(Features|flags)' /proc/cpuinfo | cut -d: -f2)"
  # aarch64 always has "neon" (advertised as "asimd"); aes is optional.
  case " $flags " in *" asimd "*|*" neon "*) HAVE[neon]=1;; esac
  [ "$HOST_ARCH" = "aarch64" ] && HAVE[neon]=1
  case " $flags " in *" aes "*) HAVE[aes]=1;; esac
}

case "$HOST_ARCH" in
  x86_64|amd64) probe_x86_features;;
  aarch64|arm64) probe_arm_features;;
esac

# --- runner ---------------------------------------------------------------
RAN=(); SKIPPED=(); FAILED=()

# run_one <harness> <rustflags> [extra cargo args...]
# Enforces: `test result: ok. N passed; 0 failed` with N > 0.
run_one() {
  local harness="$1"; shift
  local rustflags="$1"; shift
  local out tc=()
  [ -n "$TOOLCHAIN" ] && tc=("+$TOOLCHAIN")
  echo "── running $harness  (RUSTFLAGS=$rustflags${TOOLCHAIN:+, toolchain=$TOOLCHAIN}) ──"
  out="$(RUSTFLAGS="-C target-feature=$rustflags" \
        cargo "${tc[@]}" test --features benchmarking "$@" "$harness" -- --nocapture 2>&1)"
  local rc=$?
  echo "$out" | tail -n 8
  # Strip ANSI colour (cargo colourises "ok"), then sum passed/failed across
  # every "test result:" line the run produced.
  local clean passed failed
  clean="$(printf '%s' "$out" | sed -E 's/\x1b\[[0-9;]*m//g')"
  passed="$(printf '%s\n' "$clean" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
  failed="$(printf '%s\n' "$clean" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' | awk '{s+=$1} END{print s+0}')"
  passed="${passed:-0}"; failed="${failed:-0}"
  if [ "$rc" -ne 0 ] || [ "$failed" -ne 0 ]; then
    echo "   ✗ FAIL  ($passed passed, $failed failed, cargo rc=$rc)"
    FAILED+=("$harness")
  elif [ "$passed" -le 0 ]; then
    echo "   ✗ FAIL  0 rows executed — vacuous (wrong target-feature / gated out); not a pass"
    FAILED+=("$harness")
  else
    echo "   ✓ ok    $passed rows, 0 failed"
    RAN+=("$harness")
  fi
}

# x86 harnesses on an x86 host
if [ "$HOST_ARCH" = "x86_64" ] || [ "$HOST_ARCH" = "amd64" ]; then
  for row in "${X86_MATRIX[@]}"; do
    IFS='|' read -r h feat rf <<<"$row"
    if [ "${HAVE[$feat]:-0}" = 1 ]; then
      run_one "$h" "$rf"
    else
      echo "── skip $h — host CPU lacks '$feat' (running it would SIGILL)"
      SKIPPED+=("$h (no $feat)")
    fi
  done
fi

# aarch64 harnesses: native, or under qemu from x86
run_arm_native() {
  for row in "${ARM_MATRIX[@]}"; do
    IFS='|' read -r h feat rf <<<"$row"
    if [ "${HAVE[$feat]:-0}" = 1 ]; then run_one "$h" "$rf"; else
      echo "── skip $h — host lacks '$feat'"; SKIPPED+=("$h (no $feat)"); fi
  done
}
run_arm_qemu() {
  local tgt=aarch64-unknown-linux-gnu
  if ! command -v qemu-aarch64-static >/dev/null 2>&1 || \
     ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "── skip aarch64 (--qemu): need qemu-aarch64-static + aarch64-linux-gnu-gcc"
    SKIPPED+=("aarch64_neon_hw (no qemu)" "aarch64_aes_hw (no qemu)"); return
  fi
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64-static
  for row in "${ARM_MATRIX[@]}"; do
    IFS='|' read -r h feat rf <<<"$row"
    run_one "$h" "$rf" --target "$tgt"
  done
}
if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ]; then
  run_arm_native
elif [ "$QEMU" = 1 ]; then
  run_arm_qemu
else
  echo "── skip aarch64_{neon,aes}_hw — not an aarch64 host (pass --qemu to cross-run)"
  SKIPPED+=("aarch64_neon_hw (x86 host)" "aarch64_aes_hw (x86 host)")
fi

# --- summary --------------------------------------------------------------
echo
echo "==================== differential-test summary ===================="
echo "host arch      : $HOST_ARCH"
echo "RAN (evidence) : ${RAN[*]:-<none>}"
echo "SKIPPED        : ${SKIPPED[*]:-<none>}"
echo "FAILED         : ${FAILED[*]:-<none>}"
echo "NOTE: SKIPPED harnesses have NO evidence on this host — full coverage"
echo "      needs the multi-host matrix documented at the top of this script."
echo "==================================================================="

# --require: fail if a demanded feature did not actually RUN.
rc=0
if [ -n "$REQUIRE" ]; then
  IFS=',' read -ra req <<<"$REQUIRE"
  for feat in "${req[@]}"; do
    if ! printf '%s\n' "${RAN[@]:-}" | grep -q "$feat"; then
      echo "✗ --require: '$feat' was demanded but no matching harness RAN" >&2
      rc=1
    fi
  done
fi
[ "${#FAILED[@]}" -gt 0 ] && rc=1
exit $rc
