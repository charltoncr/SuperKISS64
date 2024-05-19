// This file is public domain.  Public domain is per CC0 1.0; see
// <https://creativecommons.org/publicdomain/zero/1.0/> for information.
//
// CryptoSource implements a cryptographic Source/Source64 for math/rand.
//
// By Ron Charlton 2021-03-19.

// $Id: cryptosource.go,v 1.35 2024-05-19 14:48:59-04 ron Exp $

package SuperKISS64

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"reflect"
)

var csDummy uint64
var u64bytes = int(reflect.TypeOf(csDummy).Size())

// CryptoSource holds the state of one instance of the
// CryptoSource PRNG.  New instances can be allocated using NewCryptoSource.
// math/rand.New() can wrap NewCryptoSource.
type CryptoSource struct {
	buf  []byte
	next int
}

// NewCryptoSource returns a cryptographically-based math/rand.Source.
// NewCryptoSource is NOT intended for cryptographic use.
// It is for obtaining high-quality, non-repeatable pseudorandom sequences
// for general use.
//
// NewCryptoSource may be wrapped by math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewCryptoSource())
//
// Then r can use methods provided by math/rand, such as r.Int31n() r.Perm()
// and r.Shuffle(), with CryptoSource as their basis.
//
// A single instance is not safe for concurrent access by different
// goroutines.  If more than one goroutine accesses CryptoSource the
// callers must synchronize access using sync.Mutex or similar, or allocate
// multiple instances of CryptoSource.
func NewCryptoSource() *CryptoSource {
	// multiplicand was empirically optimized on a 3.2 GHz 2020 M1 Mac mini
	bufSize := u64bytes * 32

	return &CryptoSource{
		buf:  make([]byte, bufSize),
		next: bufSize,
	}
}

// Seed is part of the math/rand.Source interface.  Seed is a noop.
func (r *CryptoSource) Seed(seed int64) {
	// noop
}

// Uint64 returns a uniformly-distributed, pseudorandom 64-bit value in
// the range [0,2^64) from CryptoSource.
// This method implements the math/rand.Source64 interface.
func (r *CryptoSource) Uint64() (n uint64) {
	if r.next >= len(r.buf) {
		if _, err := crand.Read(r.buf); err != nil {
			panic(fmt.Sprintf("crypto/rand.Read error in CryptoSource.Uint64: %v", err))
		}
		r.next = 0
	}

	n = binary.LittleEndian.Uint64(r.buf[r.next:])
	r.next += u64bytes

	return
}

// Int63 returns a uniformly-distributed, pseudorandom 64-bit value in
// the range [0,2^63) from CryptoSource.
// This method is part of the math/rand.Source interface.
func (r *CryptoSource) Int63() int64 {
	return int64(r.Uint64() >> 1)
}

// Read fills p with pseudorandom bytes from crypto/rand.  n is the number
// of bytes read into p; err is the error indicator.  n == len(p) iff err == nil.
// This method implements the io.Reader interface.
func (r *CryptoSource) Read(p []byte) (n int, err error) {
	return crand.Read(p)
}
