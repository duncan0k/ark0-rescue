"""Protocol constants for VOLEitH rescue proofs, version 0.2 (see SPEC.md §2).

Everything here is fixed by the protocol version; nothing is negotiable at
run time.
"""

# Protocol version byte carried in the proof header and hashed into mu.
VERSION = 0x02
# ASCII version label used inside every domain-separation tag.
VERSION_LABEL = "v0.2"

# Security parameter and field size: GF(2^128).
LAMBDA = 128
LAMBDA_BYTES = LAMBDA // 8

# Deepest GGM tree supported (node indices are encoded in 16 bits).
MAX_DEPTH = 8


class TreeSplit:
    """FAEST-style split of the LAMBDA challenge bits over tau GGM trees.

    The first tau0 = LAMBDA mod tau trees have depth k0 = ceil(LAMBDA / tau),
    the other tau1 = tau - tau0 trees depth k1 = floor(LAMBDA / tau), so that
    tau0 * k0 + tau1 * k1 = LAMBDA. Tree i hides the leaf whose index is
    bits [offset_i, offset_i + depth_i) of Delta, offset_i being the sum of
    the depths of the trees before it.
    """

    __slots__ = ("tau", "tau0", "k0", "tau1", "k1", "depths", "offsets")

    def __init__(self, tau):
        if type(tau) is not int or not 1 <= tau <= LAMBDA:
            raise ValueError("tau must be an integer in [1, LAMBDA]")
        self.tau = tau
        self.k1 = LAMBDA // tau
        self.k0 = -(-LAMBDA // tau)
        self.tau0 = LAMBDA % tau
        self.tau1 = tau - self.tau0
        if self.k0 > MAX_DEPTH:
            raise ValueError("trees deeper than %d are not supported" % MAX_DEPTH)
        self.depths = (self.k0,) * self.tau0 + (self.k1,) * self.tau1
        offsets = []
        acc = 0
        for k in self.depths:
            offsets.append(acc)
            acc += k
        assert acc == LAMBDA
        self.offsets = tuple(offsets)

    def challenge_index(self, delta, i):
        """The hidden leaf of tree i: bits [offset_i, offset_i + depth_i) of Delta."""
        return (delta >> self.offsets[i]) & ((1 << self.depths[i]) - 1)

    def __eq__(self, other):
        return isinstance(other, TreeSplit) and other.tau == self.tau

    def __hash__(self):
        return hash(self.tau)

    def __repr__(self):
        return "TreeSplit(%d: %d x %d + %d x %d)" % (self.tau, self.tau0, self.k0,
                                                     self.tau1, self.k1)


# The parameter set of this version: 24 trees, 8 of depth 6 and 16 of depth 5.
SPLIT = TreeSplit(24)

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
