== Notes on Portability ==

The library is written mostly on C89, but uses the header inttypes.h
from C99, in particular, types uint8_t, uint32_t and uint64_t are used.

Beyond standard C guarantees, the code only makes one (widely true)
assumption: to be possible to load uint64_t values from 4 bytes aligned
memory.

Since all algorithms are specified in little-endian, if LITTLE_ENDIAN
macro is specified during compilation, optimized code dependant on little
endian machine will be used; otherwise, generic code that works on any
endianess will be used. Thus, the code is portable to big-endian machines,
but probably performs better on little-endian.
