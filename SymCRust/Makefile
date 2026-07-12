CHARON_HOME ?= ../../aeneas/charon
AENEAS_HOME ?= ../../aeneas

CHARON_OPTIONS += --targets=x86_64-unknown-linux-gnu,i686-unknown-linux-gnu,aarch64-unknown-linux-gnu
AENEAS_OPTIONS ?=

# Toolchain used for extraction only.  The project `rust-toolchain.toml` now
# pins the public `nightly-2026-06-01` by default (internal builds select
# `ms-prod-1.93` via `SYMCRUST_CONFIG=MSRust`), matching the `verify` + Charon
# nightly requirement, so no override is normally needed.  We still derive
# `EXTRACT_TOOLCHAIN` from Charon's own `rust-toolchain` so the metadata-pass
# nightly always matches the `charon-driver` nightly and cannot drift stale;
# override on the command line if needed
# (`make extract EXTRACT_TOOLCHAIN=nightly-YYYY-MM-DD`).  (Charon itself also
# carries its own `charon-driver` toolchain; this governs the cargo metadata pass.)
EXTRACT_TOOLCHAIN ?= $(shell awk -F'"' '/^channel/{print $$2}' $(CHARON_HOME)/rust-toolchain 2>/dev/null)

# Provenance log for every extraction. See
# aeneas-skills/.github/skills/aeneas-extraction-pipeline (§Reproducibility)
# for the rationale: every Code/*.lean file we commit must be replayable
# from (the Rust sources committed in this same tree, Aeneas commit, Charon
# pin, rustc toolchain, options).  We deliberately do NOT record a Rust
# commit hash: src/ and the extracted Code/ are committed together, so the
# extraction is reproduced from the working tree itself (`make extract` then
# `git diff`), not from a self-referential commit pointer.
EXTRACTION_LOG ?= lean/Symcrust/Code/EXTRACTION.md

# `make` with no target runs a full extraction of the RC's entire scope
# (SHA-3 + ML-KEM + verify + common). Extract a superset, never a subset.
.DEFAULT_GOAL := extract

.PHONY: extract-log
extract-log:
	@printf '# Provenance of Code/\n\nThis file is overwritten by `make extract` after successful extraction.\n\ndate       : %s\n' "$$(date -u +'%Y-%m-%d %H:%M UTC')" > $(EXTRACTION_LOG)
	@printf 'source     : the SymCRust Rust sources committed in this same tree\n' >> $(EXTRACTION_LOG)
	@printf '             (reproduce: run `make extract`)\n' >> $(EXTRACTION_LOG)
	@printf 'aeneas     : %s @ %s\n' \
	        "$$(git -C $(AENEAS_HOME) config --get remote.origin.url 2>/dev/null || echo unknown)" \
	        "$$(git -C $(AENEAS_HOME) rev-parse --short HEAD 2>/dev/null || echo unknown)" >> $(EXTRACTION_LOG)
	@printf 'charon     : %s @ %s\n' \
	        "$$(git -C $(CHARON_HOME) config --get remote.origin.url 2>/dev/null || echo unknown)" \
	        "$$(git -C $(CHARON_HOME) rev-parse --short HEAD 2>/dev/null || echo unknown)" >> $(EXTRACTION_LOG)
	@printf 'rustc      : extraction %s  /  charon-driver %s\n' \
	        "$(EXTRACT_TOOLCHAIN)" \
	        "$$(awk -F'\"' '/^channel/{print $$2}' $(CHARON_HOME)/rust-toolchain 2>/dev/null || echo unknown)" >> $(EXTRACTION_LOG)
	@printf 'options    : CHARON_OPTIONS=%s  AENEAS_OPTIONS=%s\n' \
	        "$(CHARON_OPTIONS)" "$(AENEAS_OPTIONS)"                        >> $(EXTRACTION_LOG)
	@printf 'lean       : %s\n' "$$(cat lean/lean-toolchain 2>/dev/null || echo unknown)" >> $(EXTRACTION_LOG)
	@echo "[extract-log] wrote single provenance record to $(EXTRACTION_LOG)"

# Pin Lean to whatever Aeneas itself is built against. On a fresh checkout
# (no `lean/lean-toolchain` yet) this seeds the file; on subsequent
# extractions it FAILS if the two diverge, so a Lean upgrade is always a
# deliberate decision (proofs may not survive a version bump).
AENEAS_LEAN_TOOLCHAIN ?= $(AENEAS_HOME)/backends/lean/lean-toolchain
LOCAL_LEAN_TOOLCHAIN  ?= lean/lean-toolchain

.PHONY: check-lean-toolchain
check-lean-toolchain:
	@if [ ! -f $(AENEAS_LEAN_TOOLCHAIN) ]; then \
	    echo "[lean-toolchain] WARNING: $(AENEAS_LEAN_TOOLCHAIN) not found; skipping pin check"; \
	    exit 0; \
	fi; \
	if [ ! -f $(LOCAL_LEAN_TOOLCHAIN) ]; then \
	    cp $(AENEAS_LEAN_TOOLCHAIN) $(LOCAL_LEAN_TOOLCHAIN); \
	    echo "[lean-toolchain] seeded $(LOCAL_LEAN_TOOLCHAIN) from $(AENEAS_LEAN_TOOLCHAIN) ($$(cat $(LOCAL_LEAN_TOOLCHAIN)))"; \
	elif ! diff -q $(AENEAS_LEAN_TOOLCHAIN) $(LOCAL_LEAN_TOOLCHAIN) >/dev/null; then \
	    echo "[lean-toolchain] ERROR: Lean toolchain mismatch with Aeneas." >&2; \
	    echo "[lean-toolchain]   aeneas pins : $$(cat $(AENEAS_LEAN_TOOLCHAIN))" >&2; \
	    echo "[lean-toolchain]   we pin      : $$(cat $(LOCAL_LEAN_TOOLCHAIN))" >&2; \
	    echo "[lean-toolchain]   To realign:  cp $(AENEAS_LEAN_TOOLCHAIN) $(LOCAL_LEAN_TOOLCHAIN)" >&2; \
	    echo "[lean-toolchain]   (then rebuild proofs; a Lean upgrade may break them)" >&2; \
	    exit 1; \
	fi

# Post-processing for the `extract` target.
#
# Parameterised on EXTRACT_SUBDIR (relative path under lean/, default
# Symcrust/Code) so the logic stays independent of the destination tree.
#
# (1) `TypesExternal_Template.lean` / `FunsExternal_Template.lean` are
#     auto-generated. We copy them to the user-editable filenames *only* on the
#     first extraction (when `*External.lean` doesn't exist yet). On later
#     extractions, leave the user-edited files alone and let the developer
#     diff `*_Template.lean` vs `*External.lean` to reconcile new axioms /
#     hand-written `def` bodies (e.g. iterator implementations needed by `step*`).
# (2) Bump `maxRecDepth` in the generated `Funs.lean` so the auto-param
#     `(by simp)` of `Aeneas.Std.Array.make` can elaborate the 256-entry NTT
#     zeta tables (`mldsa.ntt.{ZETA_BITREV_TIMES_R,NEG_ZETA_BITREV_TIMES_R}`).
#     Without this, `lake build` fails at the table definitions.
# (3) Pin Lean to the toolchain Aeneas itself uses (its backend & test suite
#     are built against). Auto-create `lean/lean-toolchain` on first
#     extraction; fail loudly on mismatch on later extractions so the upgrade
#     is a deliberate decision (proofs may not survive a Lean version bump).
EXTRACT_SUBDIR ?= Symcrust/Code
.PHONY: extract-postprocess
# Fail early with a clear message if the Charon/Aeneas executables are missing.
.PHONY: check-extract-tools
check-extract-tools:
	@[ -x "$(AENEAS_HOME)/bin/aeneas" ] || { echo "[extract] ERROR: $(AENEAS_HOME)/bin/aeneas not found" >&2; exit 1; }
	@[ -x "$(CHARON_HOME)/bin/charon" ] || { echo "[extract] ERROR: $(CHARON_HOME)/bin/charon not found" >&2; exit 1; }

extract-postprocess: check-lean-toolchain
	@D=lean/$(EXTRACT_SUBDIR); \
	if [ -f $$D/FunsExternal_Template.lean ]; then \
	    echo "[postprocess] running prune-external-template.py on $$D/FunsExternal_Template.lean"; \
	    python3 scripts/prune-external-template.py --subdir $(EXTRACT_SUBDIR) || \
	      echo "[postprocess] WARNING: prune-external-template.py reported unbound silicon paths (non-fatal)"; \
	fi; \
	if [ -f $$D/TypesExternal_Template.lean ] && [ ! -f $$D/TypesExternal.lean ]; then \
	    cp $$D/TypesExternal_Template.lean $$D/TypesExternal.lean; \
	    echo "[postprocess] copied $$D/TypesExternal_Template.lean -> TypesExternal.lean"; \
	fi; \
	if [ -f $$D/FunsExternal_Template.lean ] && [ ! -f $$D/FunsExternal.lean ]; then \
	    cp $$D/FunsExternal_Template.lean $$D/FunsExternal.lean; \
	    echo "[postprocess] copied $$D/FunsExternal_Template.lean -> FunsExternal.lean"; \
	fi; \
	if [ -f $$D/FunsExternal_Template.lean ] && [ -f $$D/FunsExternal.lean ] \
	   && ! diff -q $$D/FunsExternal_Template.lean $$D/FunsExternal.lean >/dev/null; then \
	    echo "[postprocess] WARNING: $$D/FunsExternal.lean differs from FunsExternal_Template.lean."; \
	    echo "[postprocess]   This is expected if you have hand-written def bodies (e.g. iterator impls)."; \
	    echo "[postprocess]   Diff them and reconcile any new axioms before building:"; \
	    echo "[postprocess]     diff -u $$D/FunsExternal{,_Template}.lean"; \
	fi; \
	if [ -f $$D/Funs.lean ] && ! grep -q '^set_option maxRecDepth' $$D/Funs.lean; then \
	    sed -i '/^set_option maxHeartbeats /a \\n/- Bumped from default 512 so the auto-param `(by simp)` of `Aeneas.Std.Array.make`\n   can discharge `(<long-literal-list>).length = 256` for the NTT zeta tables. -/\nset_option maxRecDepth 2048' $$D/Funs.lean; \
	    echo "[postprocess] injected set_option maxRecDepth 2048 into $$D/Funs.lean"; \
	fi; \
	if [ -f $$D/Types.lean ]; then \
	    python3 scripts/disambiguate-trait-fields.py --subdir $(EXTRACT_SUBDIR) || \
	      { echo "[postprocess] ERROR: disambiguate-trait-fields.py failed" >&2; exit 1; }; \
	fi; \
	if [ -f $$D/Funs.lean ]; then \
	    python3 scripts/strip-iterator-zip-rev.py $$D/Funs.lean || \
	      { echo "[postprocess] ERROR: strip-iterator-zip-rev.py failed" >&2; exit 1; }; \
	fi

################################################################################
# Extraction target
#
# This published branch is scoped to **intrinsics + SHA-3 + ML-KEM** (see
# README-VERIFIEDCRYPTO.md). The AES/GCM Rust source is kept byte-identical to
# `feature/verifiedcrypto` (it is gated behind the `aes` Cargo feature, which we
# never enable, so it is never compiled or extracted). To keep `Code/` scoped to
# exactly the verified surface — and NOT pull in out-of-scope items such as the
# ungated `block_cipher` trait — we seed Charon from the in-scope module roots
# rather than extracting the whole crate:
#
#   crate::sha3   crate::mlkem   crate::verify   crate::common
#
# Charon follows `use` transitively from each seed, so the shared `hash`
# support and all `src/verify` intrinsic models are pulled in automatically.
# `crate::common` is seeded as a whole module (not just reached transitively)
# because a few of its items the proofs depend on — `const_time_slice_copy`,
# the `SYMCRYPT_CPU_FEATURE_PCLMULQDQ` constant, and `Error`'s derived
# `PartialEq` — are otherwise only reachable through the AES path (gated out),
# so a transitive-only closure would drop them. The one further exception is
# `keccak_permute_textbook`: it is a private fn reached only from a
# `#[cfg(test)]` test, so no public-API seed reaches it — it must be named
# explicitly (the `Properties/SHA3/Keccak/Textbook` proof depends on it).
# Likewise `keccak_opt::keccak_permute_opt`: production `keccak_permute` routes
# through `keccak_permute_textbook` (matching `feature/verifiedcrypto`), so the
# optimized variant loses its only non-test caller and must be named explicitly
# to stay extracted — we keep proving it equivalent (`Properties/SHA3/Keccak`).
#
# `--features verify` activates the verification cfg and the
# per-target SIMD NTT variants (`ntt_xmm` / SSE2, `ntt_neon` / NEON,
# `ntt_avx2` / AVX2) whose loop proofs live in `Properties/MLKEM/Intrinsics/`.
#
# `-loops-to-rec` emits loops as recursive `partial_fixpoint` `_loop`
# functions (explicit `IteratorRange.next`, walked by step lemmas), the
# shape the SHA-3 Sponge / Keccak and ML-KEM proofs were authored against.
.PHONY: extract
extract: check-extract-tools
	RUSTUP_TOOLCHAIN=$(EXTRACT_TOOLCHAIN) $(CHARON_HOME)/bin/charon cargo --preset=aeneas \
	    --start-from 'crate::sha3' \
	    --start-from 'crate::mlkem' \
	    --start-from 'crate::verify' \
	    --start-from 'crate::common' \
	    --start-from 'crate::sha3::sha3_impl::keccak_permute_textbook' \
	    --start-from 'crate::sha3::keccak_opt::keccak_permute_opt' \
	    --dest-file symcrust.llbc \
	    $(CHARON_OPTIONS) -- --features verify \
	  || { echo "[extract] ERROR: charon failed; Code/ and EXTRACTION.md left unchanged." >&2; exit 1; }
	$(AENEAS_HOME)/bin/aeneas symcrust.llbc -dest lean -subdir Symcrust/Code -split-files -backend lean -print-error-emitters -color -max-error-spans -1 -loops-to-rec $(AENEAS_OPTIONS) \
	  || { echo "[extract] ERROR: aeneas failed; EXTRACTION.md left unchanged (Code/ may be partial)." >&2; exit 1; }
	@test -f lean/Symcrust/Code/Funs.lean \
	  || { echo "[extract] ERROR: aeneas produced no Funs.lean; EXTRACTION.md left unchanged." >&2; exit 1; }
	$(MAKE) extract-postprocess
	EXTRACT_CMD='make extract' $(MAKE) extract-log
	@echo "[extract] SUCCESS: Code/ regenerated; EXTRACTION.md rewritten as a single record."
