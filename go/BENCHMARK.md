# Verify benchmark

Median single-thread time of `voleith.Verify`. The run uses
`GOMAXPROCS(1)`, 101 timed runs after 3 warm-up runs, and builds the circuit
once beforehand.

Machine: Intel Xeon @ 2.10 GHz (cloud VM, 4 vCPUs), Go 1.24.7 linux/amd64,
SHAKE256 from the standard library's `crypto/sha3`.

| input | verdict | median | min | max |
|---|---|---|---|---|
| KAT 0, valid, 96-byte message | accept | **27.08 ms** | 22.63 ms | 32.03 ms |
| KAT 0 with `chall3 = ff…ff` (full verification, then reject) | reject | 27.25 ms | 25.20 ms | 35.37 ms |
| differential `valid-005`, valid, 65,535-byte message | accept | 27.00 ms | 24.55 ms | 32.63 ms |

`go test -bench Verify -cpu 1` (mean): 27.1 ms/op.

Profile: Keccak-f[1600] takes about 52% of the time (about 5.3 MB of SHAKE256
output); GF(2^128) multiplication about 30% (table multiplication by fixed
keys, plus a 4-bit-window carry-less multiply for `q_a·q_b`); the rest is
bit transposition, XOR of columns and circuit evaluation. The verifier
processes public data only, so the table lookups are not a side-channel
concern.

A one-time build of the statement 0x01 circuit costs about 40–70 ms and is
excluded from these figures. It runs lazily, after the format checks of step
6.

Reproduce:

```
cd go
VOLEITH_BENCH=101 go test -run TestMedianVerifyTime -v ./voleith
go test -run XXX -bench Verify -cpu 1 ./voleith
```
