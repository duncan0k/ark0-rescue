"""Vector commitment, ConvertToVOLE, transposition and universal hashes."""

import random
import unittest

from voleith import gf128, vc, vole
from voleith.params import TAU, K, N_LEAVES, LAMBDA
from voleith.unihash import VoleHash, ZkHash

RNG = random.Random(2026)


def rb(n):
    return RNG.randbytes(n)


class TestVectorCommitment(unittest.TestCase):
    def test_open_reconstruct(self):
        rng = random.Random(21)
        root = rb(16)
        iv = rb(16)
        h, nodes, sds, coms = vc.commit(root, iv, 3)
        for jstar in [0, 1, 128, 255] + rng.sample(range(N_LEAVES), 4):
            opening = vc.open_(nodes, coms, jstar)
            self.assertEqual(len(opening), vc.OPENING_BYTES)
            h2, sds2 = vc.reconstruct(opening, iv, 3, jstar)
            self.assertEqual(h2, h)
            self.assertIsNone(sds2[jstar])
            for j in range(N_LEAVES):
                if j != jstar:
                    self.assertEqual(sds2[j], sds[j])

    def test_tampered_opening_changes_commitment(self):
        root, iv = rb(16), rb(16)
        h, nodes, _, coms = vc.commit(root, iv, 0)
        opening = vc.open_(nodes, coms, 77)
        for pos in (0, 15, 16 * (K - 1), vc.OPENING_BYTES - 1):
            bad = bytearray(opening)
            bad[pos] ^= 0x10
            self.assertNotEqual(vc.reconstruct(bytes(bad), iv, 0, 77)[0], h)
        # Opening at the wrong index does not reproduce the commitment.
        self.assertNotEqual(vc.reconstruct(opening, iv, 0, 78)[0], h)
        # The tree index and the IV are bound.
        self.assertNotEqual(vc.reconstruct(opening, iv, 1, 77)[0], h)
        self.assertNotEqual(vc.reconstruct(opening, rb(16), 0, 77)[0], h)


class TestConvertToVole(unittest.TestCase):
    def test_small_vole_relation(self):
        rng = random.Random(22)
        nbits = 300
        rs = [rng.getrandbits(nbits) for _ in range(N_LEAVES)]
        u, v = vole.convert_prover(rs)
        for jstar in (0, 1, 200, 255):
            masked = [None if x == jstar else r for x, r in enumerate(rs)]
            q = vole.convert_verifier(masked, jstar)
            for b in range(K):
                self.assertEqual(q[b], v[b] ^ (u if (jstar >> b) & 1 else 0))

    def test_full_commit_reconstruct(self):
        lhat = 333
        r, iv = rb(16), rb(16)
        hcom, decom, corrections, u, cols = vole.commit(r, iv, lhat)
        self.assertEqual(len(corrections), TAU - 1)
        for _ in range(2):
            delta = RNG.getrandbits(128)
            openings = [vc.open_(decom[i][0], decom[i][1], vole.challenge_index(delta, i))
                        for i in range(TAU)]
            hcom2, qcols = vole.reconstruct(openings, corrections, delta, iv, lhat)
            self.assertEqual(hcom2, hcom)
            for j in range(LAMBDA):
                self.assertEqual(qcols[j], cols[j] ^ (u if (delta >> j) & 1 else 0))
            # Row view: q_r = v_r + u_r * Delta in GF(2^128).
            vrows = vole.columns_to_rows(cols, lhat)
            qrows = vole.columns_to_rows(qcols, lhat)
            for r_ in range(lhat):
                self.assertEqual(qrows[r_], vrows[r_] ^ (delta if (u >> r_) & 1 else 0))


class TestTranspose(unittest.TestCase):
    def test_against_naive(self):
        rng = random.Random(23)
        for nrows in (1, 7, 127, 128, 129, 300, 513):
            cols = [rng.getrandbits(nrows + 50) for _ in range(128)]
            rows = vole.columns_to_rows(cols, nrows)
            for r in range(nrows):
                expect = sum(((cols[j] >> r) & 1) << j for j in range(128))
                self.assertEqual(rows[r], expect)


class TestUniversalHashes(unittest.TestCase):
    def test_vole_hash_linear_and_masked(self):
        rng = random.Random(24)
        ell = 1000
        vh = VoleHash(rb(32), ell)
        n = ell + 3 * LAMBDA
        for _ in range(5):
            a, b = rng.getrandbits(n), rng.getrandbits(n)
            ha, hb, hab = vh(a), vh(b), vh(a ^ b)
            self.assertEqual(bytes(x ^ y for x, y in zip(ha, hb)), hab)
        self.assertEqual(vh(0), bytes(32))
        # The last 2*LAMBDA bits are an additive mask.
        m = rng.getrandbits(256)
        self.assertEqual(vh(m << (ell + LAMBDA)), m.to_bytes(32, "little"))

    def test_vole_hash_definition(self):
        chall1 = rb(32)
        ell = 200
        vh = VoleHash(chall1, ell)
        s = gf128.from_bytes(chall1[:16])
        t = gf128.from_bytes(chall1[16:])
        x = RNG.getrandbits(ell + 3 * LAMBDA)
        x0 = x & ((1 << (ell + LAMBDA)) - 1)
        nb = (ell + LAMBDA + 127) // 128
        ys = [(x0 >> (128 * j)) & gf128.MASK for j in range(nb)]
        hs = 0
        ht = 0
        for j, y in enumerate(ys):
            hs ^= gf128.mul(y, gf128.pow_(s, nb - j))
            ht ^= gf128.mul(y, gf128.pow_(t, nb - j))
        x1 = x >> (ell + LAMBDA)
        expect = gf128.to_bytes(hs ^ (x1 & gf128.MASK)) + gf128.to_bytes(ht ^ (x1 >> 128))
        self.assertEqual(vh(x), expect)

    def test_zk_hash_definition(self):
        chall2 = rb(64)
        zk = ZkHash(chall2)
        r0, r1, s, t = (gf128.from_bytes(chall2[16 * i:16 * i + 16]) for i in range(4))
        xs = [RNG.getrandbits(128) for _ in range(9)]
        mask = RNG.getrandbits(128)
        n = len(xs)
        hs = 0
        ht = 0
        for i, x in enumerate(xs):
            hs ^= gf128.mul(x, gf128.pow_(s, n - 1 - i))
            ht ^= gf128.mul(x, gf128.pow_(t, n - 1 - i))
        self.assertEqual(zk(xs, mask), gf128.mul(r0, hs) ^ gf128.mul(r1, ht) ^ mask)


if __name__ == "__main__":
    unittest.main()
