// $Id: SuperKISS64_test.go,v 1.23 2024-05-24 16:22:45-04 ron Exp $

package SuperKISS64

import (
	"io"
	"math"
	"math/rand"
	"os"
	"testing"
	"time"
)

const alpha = 0.00001 // acceptable p-value limit

// Ported by Ron Charlton from p_value.c on 2018-08-29.
// From https://www.codeproject.com/Articles/432194/How-to-Calculate-the-Chi-Squared-P-Value
// on 2018-08-29, where it was named chisqr.c. I (Ron) included gamma.c's
// relevant function within this file for simplicity.  My port to the Go
// programming language is in the public domain, as is the original.

// Comment from chisqr.c:
/*  Implementation of the Chi-Square Distribution, Gamma Function &
	Incomplete Gamma Function in C

	Written By Jacob Wells
	July 31, 2012
    Based on the formulas found here:

    Wikipedia - Incomplete Gamma Function -> Evaluation formulae -> Connection
	with Kummer's confluent hypergeometric function
    http://en.wikipedia.org/wiki/Regularized_Gamma_function#Connection_with_Kummer.27s_confluent_hypergeometric_function

    Wikipedia - Chi-squared Distribution -> Cumulative distribution function
    http://en.wikipedia.org/wiki/Chi-squared_distribution#Cumulative_distribution_function

    These functions are placed in the Public Domain, and may be used by anyone,
	anywhere, for any reason, absolutely free of charge.
*/

// $Id: SuperKISS64_test.go,v 1.23 2024-05-24 16:22:45-04 ron Exp $

/*
c:\Users\Ron\go\src>go run TestPValue.go 255 160
0.999999393099

c:\Users\Ron\go\src>go run TestPValue.go 255 250
0.57663526365

c:\Users\Ron\go\src>go run TestPValue.go 255 300
0.02772752205332
*/

// Dof is degrees of freedom.  Cv is critical value (chi-square).
// Cv is sum( (observed - expected)^2 / expected )

// PValue returns a p-value when given a degrees-of-freedom value and a
// chi-square Critical value.
func PValue(Dof int, Cv float64) float64 {
	if Cv < 0 || Dof < 1 {
		return 0.0
	}

	K := float64(Dof) * 0.5
	X := Cv * 0.5

	if Dof == 2 {
		return math.Exp(-X)
	}

	PValue := 1.0 - math.Exp(LogIgamma(K, X)-LogGamma(K))

	return PValue
}

/*
	Returns the Natural Logarithm of the Incomplete Gamma Function.

	I converted the p-value to work with Logarithms, and only calculate
	the finished Value right at the end.  This allows us much more accurate
	calculations.  One result of this is that I had to increase the Number
	of Iterations from 200 to 1000.  Feel free to play around with this if
	you like, but this is the only way I've gotten it to work.
	Also, to make the code easier to work, I separated out the main loop.
*/

// LogIgamma returns the natural logarithm of the lower Incomplete Gamma
// Function.
func LogIgamma(S, Z float64) float64 {

	if Z < 0.0 {
		return 0.0
	}

	Sc := (math.Log(Z) * S) - Z - math.Log(S)

	K := km(S, Z)

	return math.Log(K) + Sc
}

func km(S, Z float64) float64 {
	Sum := 1.0
	Num := 1.0
	Denom := 1.0

	for I := 0; I < 1000; I++ {
		Num *= Z
		S++
		Denom *= S
		// The if statement was added by Ron Charlton to prevent invalidating
		// Sum when using float64 numbers.
		if Denom > 1.0e307 || Num > 1.0e307 {
			break
		}
		Sum += (Num / Denom)
	}

	return Sum
}

// from gamma.c
/*
    Implementation of the Gamma function using Spouge's Approximation in C.

    Written By Jacob F. Wells
	7/31/2012
    Public Domain

    This code may be used by anyone for any reason
    with no restrictions absolutely free of cost.
*/

const a float64 = 11 // 15 for long double
/*
    'a' is the level of accuracy you wish to calculate.
    Spouge's Approximation is slightly tricky, as you
    can only reach the desired level of precision if
    you have EXTRA precision available so that it can
    build up to the desired level.

    If you're using double (64 bit wide datatype), you
    will need to set a to 11, as well as remember to
    change the math functions to the regular
    (i.e. pow() instead of powl())

   !! IF YOU GO OVER OR UNDER THESE VALUES YOU WILL !!!
              !!! LOSE PRECISION !!!
*/

// LogGamma returns the natural logarithm of Gamma function using Spouge's
// Approximation. The Gamma Function allows you to compute the Factorial
// of decimals (e.g. 5.5!).
func LogGamma(N float64) float64 {
	// The constant SQRT2PI is defined as sqrt(2.0 * PI);
	// For speed the constant is already defined in decimal
	// form.  However, if you wish to ensure that you achieve
	// maximum precision on your own machine, you can calculate
	// it yourself using (sqrt(atan(1.0) * 8.0))

	//var SQRT2PI float64 = math.Sqrt(math.Atan(1.0) * 8.0)
	const SQRT2PI float64 = 2.5066282746310005024157652848110452530069867406099383

	Z := N

	Sc := (math.Log(Z+a) * (Z + 0.5)) - (Z + a) - math.Log(Z)

	F := 1.0
	Sum := SQRT2PI

	for K := float64(1); K < a; K++ {
		Z++
		Ck := math.Pow(a-K, K-0.5)
		Ck *= math.Exp(a - K)
		Ck /= F

		Sum += Ck / Z

		F *= -K
	}

	return math.Log(Sum) + Sc
}

func TestCryptoSource(t *testing.T) {
	rng := rand.New(NewCryptoSource())
	rng.Seed(time.Now().UnixNano()) // no effect
	b := make([]byte, 2047)
	for i := 0; i < 10000; i++ {
		rng.Uint64()
		rng.Int63()
		if m := rng.Int31n(1000); m >= 1000 || m < 0 {
			t.Errorf("error in Int31n(1000), got %d", m)
		}
		if n, err := rng.Read(b); err != nil || n != len(b) {
			t.Errorf("error in Read: %v", err)
		}
	}
}

func TestSuperKISS64(t *testing.T) {
	// George Marsaglia's test
	var got uint64
	const want = 4013566000157423768
	r := New()
	for i := 0; i < 1000000000; i++ {
		got = r.Uint64()
	}

	if got != want {
		t.Errorf("want %v but got %d", want, got)
	}
	pValueTest(NewSuperKISS64Rand(), t)
}

func TestNewSuperKISS64Array(t *testing.T) {
	var q = []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// x data is taken from SuperKISS64_test.c output
	var x = []float64{
		0.41220837956570899,
		0.48274503148508496,
		0.95863961958564214,
		0.09328491655867133,
		0.60216498744900138,
		0.36813425752037832,
		0.68242169093785998,
	}

	r := NewSuperKISS64Array(q)

	for i := 0; i < len(x); i++ {
		n := r.Float64()
		if n != x[i] {
			t.Errorf("want %v but got %v", x[i], n)
		}
	}
}

func TestSK64SaveLoadState(t *testing.T) {
	fName := "SuperKISS64SaveLoadTest.xml"
	var w []uint64
	var r, z *SK64
	var err error

	r = NewSuperKISS64Rand() // random initialization

	if err = r.SaveState(fName); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}
	for i := 0; i < 100; i++ {
		w = append(w, r.Uint64())
	}
	r.Uint64()

	if z, err = SK64LoadState(fName); err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}
	for i, want := range w {
		got := z.Uint64()
		if got != want {
			t.Errorf("want %v but got %v at index %v", want, got, i)
		}
	}
	os.Remove(fName)
}

var Www []int

func TestSK64SaveLoadWrappedState(t *testing.T) {
	fName := "SuperKISS64SaveLoadWrappedTest.xml.gz"
	var err error
	var want, got []int
	const n = QSIZE64 + 100 // use every Q value at least once

	c := NewSuperKISS64Rand() // random initialization
	r := rand.New(c)

	Www = r.Perm(n + 20) // change state by running PRNG

	// save SK64 state after use by math/rand
	if err = c.SaveState(fName); err != nil {
		t.Fatalf("SaveState returned error: %v", err)
	}
	want = r.Perm(n) // next values after saving state are used

	Www = r.Perm(n + 37) // change state by running PRNG

	if err = c.LoadState(fName); err != nil {
		t.Fatalf("LoadState returned error: %v", err)
	}
	r = rand.New(c) // new math/rand with same state as saved earlier
	got = r.Perm(n)
	// Do got slice values equal want slice values?
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("want %v but got %v at index %v", want[i], got[i], i)
		}
	}
	os.Remove(fName)
}

// Calculate many p-values for many PRNG runs, then calculate the
// p-value of the p-values, testing all p-values for acceptability.
func pValueTest(rng *SK64, t *testing.T) {
	binsOfPValues := make([]int, 10)       // 10 bins for p-values
	PValueCount := len(binsOfPValues) * 10 // 10 average per bin (min. 5 req'd)
	const binCount = 256                   // a byte can store 256 different values
	buf := make([]byte, 800000)
	for m := 0; m < PValueCount; m++ {
		bins := make([]int, binCount)
		rng.Read(buf)
		for _, b := range buf {
			bins[int(b)]++
		}
		expected := float64(len(buf)) / binCount
		chiSquare := 0.0
		for _, observed := range bins {
			x := float64(observed) - expected
			chiSquare += x * x / expected
		}
		dof := binCount - 1
		pValue := PValue(dof, chiSquare)
		if pValue == 1.0 {
			pValue -= alpha / 2 // prevent index out-of-range
		}
		binsOfPValues[int(pValue*float64(len(binsOfPValues)))]++
		if pValue < alpha || pValue > 1-alpha {
			t.Errorf("Extreme p-value: %.15g.  This test is not "+
				"deterministic.\n", pValue)
		}
	}
	// calculate p-value of p-values
	expected := float64(PValueCount) / float64(len(binsOfPValues))
	chiSquare := 0.0
	for _, observed := range binsOfPValues {
		x := float64(observed) - expected
		chiSquare += x * x / expected
	}
	dof := len(binsOfPValues) - 1
	pValue := PValue(dof, chiSquare)
	if pValue < alpha || pValue > 1-alpha {
		t.Errorf("Extreme p-value of p-values: %.15g.  This test is not "+
			"deterministic.\n", pValue)
	}
}

// Compile time test: CryptoSource implements the rand.Source interface.
var _ rand.Source = &CryptoSource{}

// Compile time test: CryptoSource implements the rand.Source64 interface.
var _ rand.Source64 = &CryptoSource{}

// Compile time test: CryptoSource implements the io.Reader interface.
var _ io.Reader = &CryptoSource{}

// SuperKISS64 implementation tests:
// Compile time test: SK64 implements the rand.Source interface.
var _ rand.Source = &SK64{}

// Compile time test: SK64 implements the rand.Source64 interface.
var _ rand.Source64 = &SK64{}

// Compile time test: SK64 implements the io.Reader interface.
var _ io.Reader = &SK64{}

//////////////////////////////////////////////////////////////////////////////
//==========================================================================//
//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

var v uint64

func BenchmarkCryptoSource(b *testing.B) {
	b.SetBytes(8)
	r := NewCryptoSource()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v = r.Uint64()
	}
}

func BenchmarkSuperKISS64(b *testing.B) {
	b.SetBytes(8)
	r := NewSuperKISS64Rand()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v = r.Uint64()
	}
}
