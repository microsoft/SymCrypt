-- Active build closure: aggregates the verified Properties trees shipped in
-- this branch: SHA-3 family (FIPS 202) and ML-KEM (FIPS 203, scalar + Sse2 +
-- Neon paths). Built as `@[default_target] lean_lib Symcrust` from
-- `lakefile.lean`.
import Symcrust.Properties.SHA3
import Symcrust.Properties.MLKEM
