// SuperKISS64.go - an extremely long period pseudorandom number generator by
// George Marsaglia, from http://forums.silverfrost.com/viewtopic.php?t=1480
// posted 2009-11-22, augmented/ported to Go by Ron Charlton 2021-06-03.
// For math only see
// https://www.thecodingforums.com/threads/superkiss-for-32-and-64-bit-rngs-in-both-c-and-fortran.706893/
//
// 6.1 ns per call on iBUYPOWER P700 Pro with 3.60 GHz Intel Core i7-3820 with
// 667 MHz memory.  RonC 2021-05-xx.
//
// 5.1 ns per call on 2021 Mac Mini with 3.2 GHz M1 processor. RonC 2021-06-05.
//
// 4.6 ns per call on 2023 Mac Studio with 3.504 GHz M2 Max processor. RonC 2024-05-24.

// Ron Charlton's additions are public domain as per CC0 1.0; see
// <https://creativecommons.org/publicdomain/zero/1.0/> for information.

// George Marsaglia (GM) code:

/*
--------------------------------------------------------
Here is SUPRKISS64.c, the immense-period 64-bit RNG. I
invite you to cut, paste, compile and run to see if you
get the result I do. It should take around 20 seconds.
--------------------------------------------------------
*/

/* SUPRKISS64.c, period 5*2^1320480*(2^64-1) (or more than 10^397524) */

// Ron Charlton (RC) code:

// $Id: SuperKISS64.go,v 2.17 2024-07-08 06:36:37-04 ron Exp $

// To run the GM test suggested above, type "go test" in this file's
// directory.  SuperKISS64_test.go and cryptosource.go must also be present.

// To find 10^397524 on Windows (with unxutils' GNU awk, bc, tr & wc):
// awk "BEGIN{printf(\"5*2^^1320480*(2^^64-1)\n\")}" | bc -q | tr -cd "0-9" | wc -c
// On macOS/Linux:
// echo "5*2^1320480*(2^64-1)" | bc -q | tr -cd "0-9" | wc -c

// SuperKISS64 is useful when a huge number of different possible
// pseudorandom sequences is needed.
// For example, to fairly shuffle a deck of 52 cards, a
// generator capable of 52! different starting states and sequences is required.
// 52! is approximately 10^68.  math/rand has only about 10^19 starting
// states and sequences.  SuperKISS64 has more than 10^397524 starting states
// and sequences.
//
// SuperKISS64 passes all dieharder version 3.31.1 tests using George
// Marsaglia's acceptable alpha of 0.00001 for PRNGs.
// Typical runs of SuperKISS64 with dieharder yield one or a few WEAK results,
// but not always on the same particular sub-tests.  This behavior is also
// exhibited by a true cryptographically safe PRNG with dieharder.
// George Marsaglia says this is expected behavior in running many tests.
//
// SuperKISS64.go is dependent on cryptosource.go. cryptosource.go may be
// used without SuperKISS64.go.
package SuperKISS64

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

// Ported by RC from GM C code:

// QSIZE64 specifies len(SK64.Q).
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

// cng is a congruential pseudorandom number generator (PRNG) for internal
// use by SuperKISS64.
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

// New allocates a SuperKISS64 PRNG and initializes it with a "random" seed.
// It is useful when repeating a sequence is not required.
// Approximately 10^19 sequences are possible.
// See also NewSuperKISS64, NewSuperKISS64Rand and NewSuperKISS64FromSlice.
func New() *SK64 {
	n := int64(xs(uint64(time.Now().UnixNano())))
	return NewSuperKISS64(n)
}

// NewSuperKISS64 allocates a new SuperKISS64 PRNG.  Parameter seed determines
// whether or not to initialize for testing.
// Seed with 0 for George Marsaglia's test; otherwise use any int64 seed.
// Approximately 10^19 sequences are possible.
// If a larger number of starting states/sequences is desired, use
// NewSuperKISS64FromSlice or NewSuperKISS64Rand.
// NewSuperKISS64 can be wrapped with math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64(seed))
//
// Then r can use methods provided by math/rand, such as r.Int31n(), r.Perm()
// and r.Shuffle().
// See function TestSK64SaveLoadWrapped in SuperKISS64_test.go for an
// example of how to save and load the state of a wrapped generator.
func NewSuperKISS64(seed int64) *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64),
	}
	r.Seed(seed)
	return r
}

// NewSuperKISS64Rand does NOT make SuperKISS64 cryptographically secure.
// It allocates a new SuperKISS64 PRNG and initializes it with
// random numbers from crypto/rand.  Again, this does NOT make SuperKISS64
// cryptographically secure.  It provides easy access to all 10^397524
// possible SuperKISS64 sequences.
//
// To provide a repeatable initialization with the full range of possible
// sequences, call NewSuperKISS64Rand then immediately call SaveState
// or SK64SaveState.  Then to use that state again, call LoadState or
// SK64LoadState.
//
// NewSuperKISS64Rand can be wrapped with math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64Rand())
//
// Then r can use methods provided by math/rand, such as r.Int31n(), r.Perm()
// and r.Shuffle().
// See function TestSK64SaveLoadWrapped in SuperKISS64_test.go for an
// example of how to save and load the state of a wrapped generator.
func NewSuperKISS64Rand() *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64),
	}
	r.SeedFromCrypto()
	return r
}

// NewSuperKISS64FromSlice allocates a new SuperKISS64 PRNG and
// initializes it using slice s. Slice s should contain QSIZE64 or more "random"
// values, although fewer or more numbers are acceptable.
// If len(s) > QSIZE64, only the first QSIZE64 elements in s are used.
// NewSuperKISS64FromSlice can be wrapped with math/rand.New as in this example:
//
//	import "math/rand"
//	r := rand.New(NewSuperKISS64FromSlice(q))
//
// Then r can use methods provided by math/rand, such as r.Int31n(), r.Perm()
// and r.Shuffle().
// See function TestSK64SaveLoadWrapped in SuperKISS64_test.go for an
// example of how to save and load the state of a wrapped generator.
func NewSuperKISS64FromSlice(s []uint64) *SK64 {
	r := &SK64{
		Q: make([]uint64, QSIZE64),
	}
	r.SeedFromSlice(s)
	return r
}

// NewSuperKISS64Array is provided for compatibility with older versions.
// It is deprecated.  Use NewSuperKISS64FromSlice in new code.
func NewSuperKISS64Array(q []uint64) *SK64 {
	return NewSuperKISS64FromSlice(q)
}

// SaveState saves the state of SuperKISS64 PRNG r as XML to a file named
// by outfile.  The saved file size is about 524 KB.
// If outfile ends with ".gz" a gzip'ped XML file is saved, and
// the typical saved file size is about 212 KB.  Either type of saved state
// file can be loaded by calling either SK64LoadState or LoadState with the
// same file name used to save the file.
//
// To view a SuperKISS64-saved XML file with line breaks added:
//
//	$ xmllint --format myFile.xml | less
//
// OR
//
//	$ gzip -cd myFile.xml.gz | xmllint --format - | less
func (r *SK64) SaveState(outfile string) (err error) {
	var out *os.File
	var gw *gzip.Writer

	if r == nil {
		return errors.New("SuperKISS64:SaveState called with nil r")
	}
	if out, err = os.Create(outfile); err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, out.Close())
	}()
	w := io.Writer(out)
	if strings.HasSuffix(outfile, ".gz") {
		best := gzip.BestCompression
		if gw, err = gzip.NewWriterLevel(out, best); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, gw.Close())
		}()
		w = gw
	}
	io.WriteString(w, xml.Header)
	e := xml.NewEncoder(w)
	defer func() {
		err = errors.Join(err, e.Close())
	}()
	err = e.Encode(r)
	return
}

// SK64SaveState saves a SuperKISS64 state r to an XML file named by outfile.
// The file size is about 524 KB.
// If outfile ends with ".gz" SK64SaveState saves a gzip'ped XML file;
// then the typical saved file size is about 212 KB.  Either type of saved
// state file can be loaded by calling either SK64LoadState or LoadState
// with the same file name used to save the file.
func SK64SaveState(r *SK64, outfile string) (err error) {
	if r == nil {
		return errors.New("SuperKISS64:SK64SaveState called with nil r")
	}
	return r.SaveState(outfile)
}

// LoadState loads SuperKISS64 state r from an XML state file saved earlier
// with SaveState or SK64SaveState.
// Infile should match the file name used to save the state.
// If infile ends with ".gz" then LoadState expects a gzip'ped XML file.
// If an error occurs r is left unchanged.
func (r *SK64) LoadState(infile string) (err error) {
	var in *os.File
	var gr *gzip.Reader

	if r == nil {
		return errors.New("SuperKISS64:LoadState called with nil r")
	}
	if in, err = os.Open(infile); err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, in.Close())
	}()
	rdr := io.Reader(in)
	if strings.HasSuffix(infile, ".gz") {
		if gr, err = gzip.NewReader(in); err != nil {
			return
		}
		defer func() {
			err = errors.Join(err, gr.Close())
		}()
		rdr = gr
	}
	q := &SK64{}
	decoder := xml.NewDecoder(rdr)
	if err = decoder.Decode(q); err == nil {
		*r = *q
	}
	return
}

// SK64LoadState returns a SuperKISS64 generator r loaded from an
// XML state file saved earlier with SaveState or SK64SaveState.  Infile should
// match the file name used to save the state.  If infile ends with ".gz"
// then SK64LoadState expects a gzip'ped XML file.
// (nil, err) is returned if an error occurs.
func SK64LoadState(infile string) (r *SK64, err error) {
	r = &SK64{}
	if err = r.LoadState(infile); err != nil {
		r = nil
	}
	return
}

// Seed added to C code by Ron Charlton in 2017.

// Seed initializes a SuperKISS64 instance r with seed.
// Call with seed == 0 for SuperKISS64_test.go:TestSuperKISS64.  Or call with
// a seed of any int64 value.  For a "random" seed,
// call Seed with argument time.Now().UnixNano(), as New does.
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

// SeedFromSlice provides a full range of repeatable initializations (Seed has
// only 2^63-1 starting points with math/rand). Call SeedFromSlice with a
// slice of one or more random uint64 numbers.
// It is best to call SeedFromSlice with QSIZE64 random numbers, although
// any number of values is acceptable. If len(s) > QSIZE64, only the first
// QSIZE64 elements in s are used.
func (r *SK64) SeedFromSlice(s []uint64) {
	var i, j, n uint64
	count := uint64(len(s))
	r.Seeded = true

	r.Xcng = 12367890123456
	r.Xs = 521288629546311
	r.Carry = 36243678541
	r.Index = QSIZE64

	if count > 0 {
		r.Xs = xs(r.Xs)
		r.Q[0] = s[j] + r.cng() + r.Xs
		j++
		for i = 1; i < QSIZE64; i++ {
			n = r.Q[i-1]
			j %= count // in this location in case count is 1
			r.Q[i] = s[j] + r.cng() + xs(n) + i
			j++
		}
		r.Q[0] = s[j%count] + r.cng() + xs(r.Q[i-1]) + i
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

// SeedArray is provided for compatibility with older versions.  It is
// deprecated.  Use SeedFromSlice instead in new code.
func (r *SK64) SeedArray(array []uint64) {
	r.SeedFromSlice(array)
}

// SeedFromCrypto does NOT make r cryptographically secure.
// It initializes r with random numbers from crypto/rand.
// Again, SeedFromCrypto does NOT make r cryptographically secure.
// SeedFromCrypto provides easy access to all 10^397524 possible
// SuperKISS64 sequences.
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

// Ported by RC from GM C code:

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

// Uint64 returns a 64-bit, uniformly distributed pseudorandom number
// in the range [0,2^64) from SuperKISS64.  This method implements the
// math/rand.Source64 interface.
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

// Int63 returns a uniformly distributed pseudorandom number in the range
// [0,2^63) from SuperKISS64.  This method implements the math/rand.Source
// interface.
func (r *SK64) Int63() int64 {
	return int64(r.Uint64() >> 1)
}

// Float64 returns a uniformly-distributed, pseudorandom float64 value in
// range [0.0,1.0) from SuperKISS64. It assumes IEEE 754-1985 or later
// floating point.
func (r *SK64) Float64() float64 {
	// See the table in
	// https://en.wikipedia.org/wiki/IEEE_754-1985#Range_and_precision,
	// Double precision, Actual Exponent of 0.
	n := (r.Uint64() >> 2) | 0x3FF0000000000000
	return math.Float64frombits(n) - 1.0
}

// Float32 returns a uniformly-distributed, pseudorandom float32 value in
// range [0.0,1.0) from SuperKISS64. It assumes IEEE 754-1985 or later
// floating point.
func (r *SK64) Float32() float32 {
	// See the table in
	// https://en.wikipedia.org/wiki/IEEE_754-1985#Range_and_precision,
	// Single precision, Actual Exponent of 0.
	n := uint32(r.Uint64())>>2 | 0x3F800000
	return math.Float32frombits(n) - 1.0
}

// Read fills p with pseudorandom bytes from SuperKISS64.  This method
// implements the io.Reader interface.  The returned length n is always
// len(p) and err is always nil.
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
	return
}
