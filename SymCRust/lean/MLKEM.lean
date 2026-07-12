-- Convenience build target: ML-KEM (FIPS 203).
-- Builds the active MLKEM Spec + Properties closure in isolation
-- (transitively includes SHA-3 for the verified hash interface).
-- Usage: `lake build MLKEM`
import Symcrust.Properties.MLKEM
