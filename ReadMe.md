# SuperKISS64 Pseudorandom Number Generator

SuperKISS64 is an extremely long period (more than 10^397524) pseudorandom number 
generator by George Marsaglia, from 
[http://forums.silverfrost.com/viewtopic.php?t=1480](http://forums.silverfrost.com/viewtopic.php?t=1480)
posted 2009-11-22, modified and ported to Go by Ron Charlton 2021-06-03.

For math only see
[https://www.thecodingforums.com/threads/superkiss-for-32-and-64-bit-rngs-in-both-c-and-fortran.706893/](https://www.thecodingforums.com/threads/superkiss-for-32-and-64-bit-rngs-in-both-c-and-fortran.706893/)

SuperKISS64 may be wrapped by math/rand.New; it implements math/rand Source and
Source64.  It also implements an io.Reader.

cryptosource.go is used only to initialize SuperKISS64. It doesn't make SuperKISS64
cryptographically secure. cryptosource.go may be used independent of SuperKISS64
if desired.  It too implements math/rand Source and Source64 and may be wrapped
by math/rand.New.
