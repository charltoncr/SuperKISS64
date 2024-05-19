/* SuperKISS64.go - an extremely long period pseudorandom number generator by
 * George Marsaglia from http://forums.silverfrost.com/viewtopic.php?t=1480
 * posted 2009-11-22, modified and ported to Go by Ron Charlton 2021-06-03.
 * For math only see
 * https://www.thecodingforums.com/threads/superkiss-for-32-and-64-bit-rngs-in-both-c-and-fortran.706893/
 *
 * 6.1 ns per call on iBUYPOWER P700 Pro with 3.60 GHz Intel Core i7-3820 with
 * 667 MHz memory.  RonC 2021-05-xx.
 *
 * 5.1 ns per call on 2021 Mac Mini with 3.2 GHz M1 processor. RonC 2021-06-05.
 */

/* Ron Charlton's additions are public domain as per CC0 1.0; see
 * <https://creativecommons.org/publicdomain/zero/1.0/> for information.
 */

// George Marsaglia (GM):

/*
--------------------------------------------------------
Here is SUPRKISS64.c, the immense-period 64-bit RNG. I
invite you to cut, paste, compile and run to see if you
get the result I do. It should take around 20 seconds.
--------------------------------------------------------
*/

/* SUPRKISS64.c, period 5*2^1320480*(2^64-1) (or more than 10^397524) */

// Ron Charlton (RC) code:

// $Id: SuperKISS64.go,v 1.69 2024-05-19 13:42:33-04 ron Exp $

/* To find 10^397525 on Windows (with unxutils' GNU awk, bc, tr & wc):
 * awk "BEGIN{printf(\"5*2^^1320480*(2^^64-1)\n\")}" | bc -q | tr -cd "0-9" | wc -c
 * On macOS/Linux:
 * echo "5*2^1320480*(2^64-1)" | bc -q | tr -cd "0-9" | wc -c
 */

package SuperKISS64

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// Derived from GM C code:

// QSIZE64 is the size of array Q.
const QSIZE64 = 20632

// SK64 is the state for SuperKISS64 methods.  SuperKISS64's period is
// more than 10^397524.
type SK64 struct {
	Carry  uint64   `xml:"Carry"`
	Xcng   uint64   `xml:"Xcng"`
	Xs     uint64   `xml:"Xs"`
	Index  uint64   `xml:"Index"`
	Q      []uint64 `xml:"Q"`
	Seeded bool     `xml:"Seeded"`
}

// cng is a congruential PRNG for internal use by SuperKISS64.
func (r *SK64) cng() uint64 {
	r.Xcng = 6906969069*r.Xcng + 123
	return r.Xcng
}

// xs is an Xor-Shift PRNG for internal use by SuperKISS64.
func xs(x uint64) uint64 {
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 43
	return x
}

// RC code:

var vvv uint64

// NewSuperKISS64 allocates a new SuperKISS64 PRNG.  Parameter seed determines
// whether to initialize for testing or to a state based on math/rand.Uint64.
// Seed with 0 for testing; use any other int64 seed otherwise.
// To "randomly" seed, use time.UnixNano() as the argument for seed.
// If a larger number of starting states is desired, use NewSuperKISS64Array
// or NewSuperKISS64Rand.
// NewSuperKISS64 may be wrapped by math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64(seed))
//
// Then r can use methods provided by math/rand, such as r.Int31n(), r.Perm()
// and r.Shuffle().
//
// See function TestSK64SaveLoadWrappedState in SuperKISS64_test.go for an
// example of how to save and load the state of a wrapped generator.
func NewSuperKISS64(seed int64) *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64, QSIZE64),
	}
	r.Seed(seed)
	return r
}

// NewSuperKISS64Rand allocates a new SuperKISS64 PRNG and initializes it with
// random numbers from crypto/rand.  This does NOT make SuperKISS64
// cryptographically secure.  It provides easy access to all possible
// SuperKISS64 sequences.
// NewSuperKISS64Rand may be wrapped by math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64Rand())
//
// Then r can use methods provided by math/rand, such as r.Int31n(). r.Perm()
// and r.Shuffle().
func NewSuperKISS64Rand() *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64, QSIZE64),
	}
	r.SeedFromCrypto()
	return r
}

// NewSuperKISS64Array allocates a new SuperKISS64 PRNG and
// initializes it with array q. Array q should contain QSIZE64 or more "random"
// values, although fewer or more numbers are acceptable.
// NewSuperKISS64Array may be wrapped by math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64Array(q))
//
// Then r can use methods provided by math/rand, such as r.Int31n()
// and r.Shuffle().
func NewSuperKISS64Array(q []uint64) *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64, QSIZE64),
	}
	r.SeedArray(q)
	return r
}

// SaveState saves the state of SuperKISS64 PRNG r as XML to file outfile.
// The saved file size is about 524 KB.
// If outfile ends with ".gz" then a gzip'ped XML file will be written, and
// the typical saved file size is about 212 KB.  A saved state file of either
// type can be restored by calling SK64LoadState.
func (r *SK64) SaveState(outfile string) (err error) {
	var fOut *os.File
	var gw *gzip.Writer
	if fOut, err = os.Create(outfile); err != nil {
		return
	}
	defer fOut.Close()
	w := io.Writer(fOut)
	if strings.HasSuffix(outfile, ".gz") {
		best := gzip.BestCompression
		if gw, err = gzip.NewWriterLevel(fOut, best); err != nil {
			return
		}
		defer gw.Close()
		w = gw
	}
	fmt.Fprintf(w, xml.Header)
	encoder := xml.NewEncoder(w)
	err = encoder.Encode(r)
	return
}

// SK64LoadState returns a pointer to a SuperKISS64 state read from an
// XML file that was written earlier with SaveState.  If infile ends in ".gz"
// then SK64LoadState expects a gzip'ped XML file.  Infile should
// match the file name used for saving the state.
// (nil, err) is returned if an error occurs.
func SK64LoadState(infile string) (r *SK64, err error) {
	var in *os.File
	var gr *gzip.Reader

	if in, err = os.Open(infile); err != nil {
		return
	}
	defer in.Close()
	rdr := io.Reader(in)
	if strings.HasSuffix(infile, ".gz") {
		if gr, err = gzip.NewReader(in); err != nil {
			return
		}
		defer gr.Close()
		rdr = gr
	}
	r = &SK64{}
	decoder := xml.NewDecoder(rdr)
	if err = decoder.Decode(r); err != nil {
		r = nil
	}
	return
}

// Seed added to C code by Ron Charlton in 2017.

// Seed initializes a SuperKISS64 instance with seed.
// Call with seed == 0 for util_test.go:TestSuperKISS64.  Call with seed of
// any int64 value (including 0) otherwise.  For a "random" seed, call Seed
// with argument time.UnixNano().
func (r *SK64) Seed(seed int64) {
	r.Seeded = true

	if seed == 0 {
		r.Xcng = 12367890123456
	} else {
		r.Xcng = uint64(seed)
	}
	r.Xs = 521288629546311
	r.Carry = 36243678541
	r.Index = QSIZE64
	for i := 0; i < QSIZE64; i++ {
		r.Xs = xs(r.Xs)
		r.Q[i] = r.cng() + r.Xs
	}

	// warm up the generator
	if seed != 0 {
		for i := 0; i < (QSIZE64 * 4); i++ {
			vvv = r.Uint64()
		}
	}
}

// SeedArray added to C code by Ron Charlton on 2020-09-05.

// SeedArray provides a full range of repeatable initializations (Seed has
// only 2^63-1 starting points with math/rand). Call SeedArray with a
// pointer to an array of one or more random numbers.
// It is best to call SeedArray with QSIZE64 random numbers, although
// any number of values is acceptable.
func (r *SK64) SeedArray(array []uint64) {
	var i, j, n uint64
	var count uint64 = uint64(len(array))
	r.Seeded = true

	r.Xcng = 12367890123456
	r.Xs = 521288629546311
	r.Carry = 36243678541
	r.Index = QSIZE64

	if count > 0 {
		r.Xs = xs(r.Xs)
		r.Q[0] = array[j] + r.cng() + r.Xs
		j++
		for i = 1; i < QSIZE64; i++ {
			n = r.Q[i-1]
			j %= count // in this location in case count is 1
			r.Q[i] = array[j] + r.cng() + xs(n) + i
			j++
		}
		r.Q[0] = array[j%count] + r.cng() + xs(r.Q[i-1]) + i
	} else {
		for i = 0; i < QSIZE64; i++ {
			r.Xs = xs(r.Xs)
			r.Q[i] = r.cng() + r.Xs
		}
	}

	// warm up the generator
	for i = 0; i < (QSIZE64 * 4); i++ {
		vvv = r.Uint64()
	}
}

// SeedFromCrypto does NOT make SuperKISS64 cryptographically secure.
// It initializes SuperKISS64 with random numbers from crypto/rand.
// SeedFromCrypto provides easy access to all possible SuperKISS64 sequences.
func (r *SK64) SeedFromCrypto() {
	r.Seeded = true
	cr := NewCryptoSource()
	r.Xcng = cr.Uint64()
	r.Xs = cr.Uint64()
	for r.Xs == 0 {
		r.Xs = cr.Uint64()
	}
	r.Carry = cr.Uint64()
	r.Index = QSIZE64
	for i := 0; i < QSIZE64; i++ {
		r.Q[i] = cr.Uint64()
	}
}

// Derived from GM C code:

func (r *SK64) refill() uint64 {
	var z, h uint64

	for i := 0; i < QSIZE64; i++ {
		h = r.Carry & 1
		z = ((r.Q[i] << 41) >> 1) + ((r.Q[i] << 39) >> 1) + (r.Carry >> 1)
		r.Carry = (r.Q[i] >> 23) + (r.Q[i] >> 25) + (z >> 63)
		r.Q[i] = ^((z << 1) + h)
	}

	r.Index = 1

	return r.Q[0]
}

// Uint64 returns a 64-bit, uniformly distributed pseudorandom number from
// SuperKISS64.  This method implements the math/rand.Source64 interface.
func (r *SK64) Uint64() (result uint64) {
	if !r.Seeded {
		r.Seed(1)
	}

	if r.Index < QSIZE64 {
		result = r.Q[r.Index]
		r.Index++
	} else {
		result = r.refill()
	}
	r.Xs = xs(r.Xs)
	result += r.cng() + r.Xs
	return
}

// RC code:

// Int63 returns a uniformly distributed pseudorandom number [0,2^63) from
// SuperKISS64.  This method implements the math/rand.Source interface.
func (r *SK64) Int63() int64 {
	return int64(r.Uint64() >> 1)
}

// Float64 provides a uniformly-distributed, pseudorandom float64 value in
// range [0.0,1.0) from SuperKISS64. It assumes IEEE 754-1985 or later
// floating point.
func (r *SK64) Float64() float64 {
	// See the table in
	// https://en.wikipedia.org/wiki/IEEE_754-1985#Range_and_precision,
	// Double precision, Actual Exponent of 0.
	n := (r.Uint64() >> 2) | 0x3FF0000000000000
	return math.Float64frombits(n) - 1.0
}

// Read fills p with pseudorandom bytes from SuperKISS64.  This method implements
// the io.Reader interface.  The returned length n is always len(p) and err
// is always nil.
func (r *SK64) Read(p []byte) (n int, err error) {
	for ; n+8 <= len(p); n += 8 {
		binary.LittleEndian.PutUint64(p[n:], r.Uint64())
	}
	if n < len(p) {
		val := r.Uint64()
		for n < len(p) {
			p[n] = byte(val)
			val >>= 8
			n++
		}
	}
	return n, nil
}
