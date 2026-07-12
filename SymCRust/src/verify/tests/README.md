# SymCRust intrinsic differential tests

Each `src/verify/tests/<arch>_<ext>_hw.rs` harness cross-checks a Rust model in
`src/verify/intrinsics/<arch>/<ext>.rs` against the **real** silicon intrinsic
(`model(x) == core::arch::<arch>::<intrinsic>(x)`). This is the §1 P7
"differential = empirical evidence" witness behind every `lean/Intrinsics`
axiom/theorem.

> **This file is the authoritative how-to-run for the differential harnesses.**
> The quick-reference table below lists every harness and its run command.

## Quick reference

| harness | run command (from `SymCRust/`) |
|---|---|
| `x86_64_sse2_hw_extras` | `RUSTFLAGS="-C target-feature=+sse2" cargo test --features std x86_64_sse2_hw_extras` |
| `x86_64_avx2_hw` | `RUSTFLAGS="-C target-feature=+avx2" cargo test --features std x86_64_avx2_hw` |
| `x86_64_ymm_hw` | `RUSTFLAGS="-C target-feature=+avx2" cargo test --features std x86_64_ymm_hw` |
| `x86_64_pclmulqdq_hw` | `RUSTFLAGS="-C target-feature=+pclmulqdq" cargo test --features std x86_64_pclmulqdq_hw` |
| `x86_64_aes_hw` | `RUSTFLAGS="-C target-feature=+aes" cargo test --features std x86_64_aes_hw` |
| `sha_ni_intrinsics_hw` | `RUSTFLAGS="-C target-feature=+sha,+sse4.1,+ssse3" cargo test --features std sha_ni_intrinsics_hw` |
| `aarch64_neon_hw` | aarch64 only — see below |
| `aarch64_aes_hw` | aarch64 only — see below |

A pass is `test result: ok. N passed; 0 failed` with **N > 0**. Without the
matching `RUSTFLAGS` the silicon side is gated out and the harness silently
runs **0 rows** — that is not a pass.

## aarch64 harnesses (the gotcha)

`aarch64_{neon,aes}_hw` are `#[cfg(target_arch = "aarch64")]`-gated. On an
x86_64 host `cargo test --test aarch64_neon_hw` runs **0 rows** (vacuous green —
**never** cite it as coverage). On a non-aarch64 host you can only **type-check**
them; real execution needs an aarch64 host or `qemu-user`:

```sh
# type-check (any host, no execution):
RUSTFLAGS="-C target-feature=+neon,+aes" \
  cargo check --features std --target aarch64-unknown-linux-gnu

# execute under qemu-user (recommended for x86 CI):
apt-get install -y gcc-aarch64-linux-gnu qemu-user-static
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64-static
RUSTFLAGS="-C target-feature=+neon,+aes" \
  cargo test --features std --target aarch64-unknown-linux-gnu \
    --test aarch64_neon_hw --test aarch64_aes_hw
```

See [`INTRINSICS.md`](../../../lean/Intrinsics/INTRINSICS.md) for the
differential-testing methodology behind these harnesses.
