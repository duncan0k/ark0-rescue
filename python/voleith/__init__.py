"""VOLE-in-the-head rescue proofs, reference implementation of SPEC.md v0.2.

Standard library only. Not constant time; not for production signing.
"""

from .statements import Statement, statement1, statement1_for_seed, STATEMENT1_ID
from .proof import prove, verify, proof_length

__all__ = ["Statement", "statement1", "statement1_for_seed", "STATEMENT1_ID",
           "prove", "verify", "proof_length"]
