-- Top-level Spec aggregator.
-- Re-exports the FIPS / NIST specifications whose verified implementations
-- are shipped in this branch: SHA-3 family (FIPS 202) and ML-KEM (FIPS 203).
-- Build with `lake build Spec`.
import Spec.Defs
import Spec.NatBit
import Spec.Round

-- SHA-3 family (FIPS 202): Keccak, SHA3-{224,256,384,512}, SHAKE-{128,256}
import Spec.SHA3.Spec
import Spec.SHA3.XOF
import Spec.SHA3.Properties
import Spec.SHA3.XOFProperties
import Spec.SHA3.Permutation
import Spec.SHA3.Termination

-- ML-KEM (FIPS 203)
import Spec.MLKEM.Spec
import Spec.MLKEM.Polynomials
