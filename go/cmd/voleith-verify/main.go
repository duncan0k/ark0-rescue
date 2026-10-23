// Command voleith-verify verifies a statement 0x01 proof (SPEC.md §11).
//
//	voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> --msg-hex <hex> --proof <file>
//
// It prints "valid" and exits 0 for a valid proof, prints "invalid" and
// exits 1 for an invalid one, and exits 2 with a message on standard error
// for a usage error. The same command line gives the same result with the
// Rust voleith-verify and python/tools/verify_cli.py:
//
//   - every option is "--name value" (two arguments), given exactly once; an
//     unknown, missing or repeated option is a usage error;
//   - --k: 1 to 64 bytes, each in 0x20..0x7E;
//   - --suffix: a decimal integer 0..255 without sign or leading zeros;
//   - --y-hex: exactly 64 hexadecimal digits;
//   - --msg-hex: an even number of hexadecimal digits, at most 131,070
//     (65,535 bytes); may be empty;
//   - --proof: a readable file; one of the wrong length is an invalid proof.
//
// Hexadecimal digits may be upper or lower case. Standard library only.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"ark0-rescue/go/voleith"
)

const usage = "usage: voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> " +
	"--msg-hex <hex> --proof <file>"

var names = []string{"k", "suffix", "y-hex", "msg-hex", "proof"}

func parseOptions(args []string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		a := args[i]
		name := ""
		if len(a) > 2 && a[:2] == "--" {
			for _, n := range names {
				if a[2:] == n {
					name = n
				}
			}
		}
		if name == "" {
			return nil, errors.New("unknown argument")
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("--%s needs a value", name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("--%s given twice", name)
		}
		out[name] = args[i+1]
	}
	for _, n := range names {
		if _, ok := out[n]; !ok {
			return nil, fmt.Errorf("--%s missing", n)
		}
	}
	return out, nil
}

func parseK(s string) ([]byte, error) {
	k := []byte(s)
	if len(k) < 1 || len(k) > 64 {
		return nil, errors.New("--k: K must be 1 to 64 bytes long")
	}
	for _, c := range k {
		if c < 0x20 || c > 0x7e {
			return nil, errors.New("--k: K must be printable ASCII (0x20..0x7E)")
		}
	}
	return k, nil
}

func parseSuffix(s string) (byte, error) {
	bad := errors.New("--suffix: must be a decimal integer from 0 to 255")
	if len(s) < 1 || len(s) > 3 || (s[0] == '0' && len(s) > 1) {
		return 0, bad
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, bad
		}
		v = 10*v + int(s[i]-'0')
	}
	if v > 255 {
		return 0, bad
	}
	return byte(v), nil
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func parseHex(name, s string, maxBytes int) ([]byte, error) {
	if len(s) > 2*maxBytes {
		return nil, fmt.Errorf("--%s: longer than %d bytes", name, maxBytes)
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("--%s: odd number of hexadecimal digits", name)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, ok1 := hexDigit(s[2*i])
		lo, ok2 := hexDigit(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("--%s: not hexadecimal", name)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// run returns the verdict, or an error for a usage error.
func run(args []string) (bool, error) {
	o, err := parseOptions(args)
	if err != nil {
		return false, err
	}
	k, err := parseK(o["k"])
	if err != nil {
		return false, err
	}
	suffix, err := parseSuffix(o["suffix"])
	if err != nil {
		return false, err
	}
	if len(o["y-hex"]) != 64 {
		return false, errors.New("--y-hex: must be exactly 64 hexadecimal digits")
	}
	y, err := parseHex("y-hex", o["y-hex"], 32)
	if err != nil {
		return false, err
	}
	msg, err := parseHex("msg-hex", o["msg-hex"], voleith.MaxMessage)
	if err != nil {
		return false, err
	}
	limit := voleith.ProofLen(voleith.StatementHMAC)
	f, err := os.Open(o["proof"])
	if err != nil {
		return false, fmt.Errorf("--proof: cannot read the file: %v", err)
	}
	defer f.Close()
	proof, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return false, fmt.Errorf("--proof: cannot read the file: %v", err)
	}
	if len(proof) > limit {
		return false, nil
	}
	pub := make([]byte, 0, len(k)+34)
	pub = append(pub, byte(len(k)))
	pub = append(pub, k...)
	pub = append(pub, suffix)
	pub = append(pub, y...)
	return voleith.Verify(voleith.Statement{ID: voleith.StatementHMAC, Public: pub}, msg, proof), nil
}

func main() {
	ok, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "voleith-verify: %v\n%s\n", err, usage)
		os.Exit(2)
	}
	if ok {
		fmt.Println("valid")
		os.Exit(0)
	}
	fmt.Println("invalid")
	os.Exit(1)
}
