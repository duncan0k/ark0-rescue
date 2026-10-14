"""Protocol constants for VOLEitH rescue proofs, version 0.1 (see SPEC.md §2).

Everything here is fixed by the protocol version; nothing is negotiable at
run time.
"""

# Protocol version byte carried in the proof header and hashed into mu.
VERSION = 0x01
# ASCII version label used inside every domain-separation tag.
VERSION_LABEL = "v0.1"

# Security parameter and field size: GF(2^128).
LAMBDA = 128
LAMBDA_BYTES = LAMBDA // 8

# Vector commitments: TAU independent GGM trees with 2^K leaves each.
TAU = 16
K = 8
N_LEAVES = 1 << K
assert TAU * K == LAMBDA

# Extra VOLE rows appended after the witness rows:
#   QS_MASK_BITS rows mask the QuickSilver response (one GF(2^128) element),
#   VH_MASK_BITS rows mask the VOLE consistency hash (two GF(2^128) elements).
QS_MASK_BITS = LAMBDA
VH_OUT_BITS = 2 * LAMBDA
VH_MASK_BITS = VH_OUT_BITS

# Hedging randomness drawn from the injected rng for every proof.
RHO_BYTES = 32

# Largest message accepted by prove() and verify().
MAX_MESSAGE_LEN = 65535

# Proof header: version byte, statement id byte.
HEADER_BYTES = 2
