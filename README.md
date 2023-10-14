# sigscanner

My home-made version of byte pattern searching implementation. Use as you wish.

# Usage

```c++
#include "sigscanner.h"

// length & mask deduced automatically
sigscan::SigSearch sig_ct("\x44\x3B\xC7\x0F\x8C\xA4\xFD\xFF\xFF"sig); // ok
//sigscan::SigSearch sig_ct("\x44\x3B\xC7\x0F\x8C\xA4\xFD\xFF\xFF"); // error: has to specify sig user literal

uintptr_t memory_region_start{/*...*/};
uintptr_t memory_region_end{/*...*/};
uintptr_t* address = sig_ct.search_in_address_space(memory_region_start, memory_region_end);

// or with IDA-style pattern

using namespace sigscan::literals;
//sigscan::SigSearch sig_ida("44 3B C7 0F 8C A4 FD FF FF"sig); // error: this will fail, use SigSearchIDA instead.
sigscan::SigSearchIDA sig_ida("44 3B C7 0F 8C A4 FD FF FF"sig); // ok

uintptr_t* address2 = sig_ida.search_in_address_space(memory_region_start, memory_region_end);
```

# Safety

```c++
sigscan::SigSearchIDA sig("4"sig); // will assert, sig too short
sigscan::SigSearchIDA sig1("44 3B "sig); // will assert, ends with a whitespace
sigscan::SigSearchIDA sig2("44 3B X9"sig); // will assert, has invalid hexadecimal character
```