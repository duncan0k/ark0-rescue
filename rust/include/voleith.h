/* voleith: VOLE-in-the-head rescue proofs (SPEC.md v0.2, version byte 0x02),
 * C ABI of the Rust static library (rust/, crate-type staticlib). */
#ifndef VOLEITH_H
#define VOLEITH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify a statement 0x01 proof: knowledge of x with
 * HMAC-SHA256(k, x || suffix) = y, bound to msg.
 *
 * Returns 1 if the proof is valid and 0 otherwise, including for every
 * malformed input (k_len outside 1..64, non-printable K, msg_len > 65535,
 * proof_len != 130218, null pointers with nonzero lengths) and any internal
 * error. Lengths are checked before any pointer is read. Pointers may be
 * null only when their length is 0; y must point to 32 bytes.
 *
 * This checks the proof only. The rescue-lane preconditions of SPEC.md
 * section 12 (y fixed by the spent output, the sighash rules, a 96-byte
 * message) are the caller's to enforce. */
int voleith_verify_s1(const uint8_t *k, size_t k_len, uint8_t suffix,
                      const uint8_t y[32], const uint8_t *msg, size_t msg_len,
                      const uint8_t *proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* VOLEITH_H */
