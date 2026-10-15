// Go-verifier driver for the cross-check. It is copied into the cleanroom Go
// module (branch cleanroom/go-verifier, directory go/) at cmd/xcverify by
// run.sh and run there:
//
//	go run ./cmd/xcverify <cases.tsv> <proofs.txt> <tests.tsv> <verdicts.tsv>
//
// Same formats as the Rust driver (crosscheck/src/main.rs).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ark0-rescue/go/voleith"
)

func unhex(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func lines(path string) [][]string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var out [][]string
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			out = append(out, strings.Split(l, "\t"))
		}
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}
	return out
}

func main() {
	cases := lines(os.Args[1])
	proofs := lines(os.Args[2])
	tests := lines(os.Args[3])
	out, err := os.Create(os.Args[4])
	if err != nil {
		panic(err)
	}
	defer out.Close()
	t0 := time.Now()
	for _, f := range tests {
		ci, _ := strconv.Atoi(f[1])
		bit, _ := strconv.Atoi(f[4])
		pub := unhex(cases[ci][1])
		msg := unhex(cases[ci][2])
		proof := unhex(proofs[ci][0])
		switch f[3] {
		case "none":
		case "proof":
			proof[bit/8] ^= 1 << (bit % 8)
		case "msg":
			if bit < 0 {
				msg = append(msg, 0)
			} else {
				msg[bit/8] ^= 1 << (bit % 8)
			}
		case "pub":
			pub = unhex(f[5])
		default:
			panic("unknown target " + f[3])
		}
		v := "0"
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "go: test %s panicked: %v\n", f[0], r)
					v = "E"
				}
			}()
			if voleith.Verify(voleith.Statement{ID: 0x01, Public: pub}, msg, proof) {
				v = "1"
			}
		}()
		fmt.Fprintf(out, "%s\t%s\n", f[0], v)
	}
	fmt.Fprintf(os.Stderr, "go: verified %d tests in %v\n", len(tests), time.Since(t0))
}
