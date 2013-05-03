This is a simple cryptographic library implementing all stream ciphers
from eSTREAM Profile 1 (software), namely: HC-128, Rabbit, Salsa20/12
and Sosemanuk. All the implementations passes all test vectors provided
by eSTREAM.

Stream ciphers should not be used without a MAC (Message Authentication
Code), because it is extremely easy to tamper with the data if the
attacker can guess what is in traffic (i.e. stream ciphers guarantees
secrecy, but not integrity). So, for sake of completeness, a variation
of UMAC (a mathematically proven secure message authentication code,
specified on RFC 4418) is also provided, together with a simple
connection-oriented protocol that will refuse to deliver any tampered
message.

Unfortunately the library is not so complete as to provide a secure
key exchange mechanism. Thus, in order to be useful, the communicating
parties must share a secret key through some other secure mean.

I did not try to write the most efficient code possible, but only cared
for speed when it did not compromised the code organization and
readability. Thus, the library relies heavily on the compiler's ability
to optimize and generate quality code. Enabling optimization flags
on build is highly recommended. Note that it does not means the
implementations are slow, just that the code is not a bloody mess to
try to extract every bit of performance.

## Building

On UNIX-like, edit the options on top of the Makefile, then run:

    $ make all

This will build the main "libestream.a" static library, the test
programs, and a sample application using the simple protocol. On
Windows, I do not know.

## Using

There are three levels of abstraction on how the library can be used.

The lowest level interface is to use the algorithms themselves
directly. This interface is provided by the ciphers' headers:
"hc-128.h", "rabbit.h", "salsa20.h" and "sosemanuk.h".

The stream cipher algorithms are just pseudo-random number generators
with some properties that make them suitable to cryptography, by XORing
the generated pseudo-random string with the clear/cipher text to get
the cipher/clear text, respectively. Thus, the low level interface just
provide the means to extract this pseudo random string from the state
initialized with the secret key and an IV, in chunks of size particular
to each algorithm.

In order to facilitate the encryption/decryption of messages of any
size with any algorithm, no matter what is its internal chunk size, the
second level interface was created, defined in "buffered.h". It will
care to encrypt/decrypt any message, and store the remaining unused
bytes from the pseudo-random stream for use in the next call.

The last and highest level API is provided by "protocol.h", that will
sign/verify the message with modified UMAC, encrypt/decrypt with
buffered interface and send/receive through an user supplied functions.
The sample chat application (in "/sample/chat.c") uses this interface.

## Modified UMAC

UMAC original specification is composed by a function called UHASH,
used together with the well known block encryption standard AES.
UHASH is the actual universal hash function, and AES is used for
expanding the full key of the hash function, as well to make its output
secret (apparently, a necessity when using this kind of hash function)
simulating a stream cipher by encrypting a nonce and XORing it with
the hash output.

Since it is out of purpose to implement AES in this library, and the
implemented stream ciphers fit much better in the job of expanding keys
(they are pseudo-random number generators) and encrypting with XOR
(that is how they are supposed to be used from start), the eSTREAM
ciphers are used, instead.

Thus, if you are not using the "protocol.h" interface, but want your
system to be tampering-safe (highly advisable for almost anyone), feel
free to use this UMAC implementation as MAC, available in "umac.h"
(what is actually an implementation of UHASH and a key expansion
function based on "buffered.h" interface), but **do encrypt** the hash
output before exposing it to any untrusted medium, like together
with the rest of your message, because currently know universal
hash functions can not stand on they own. If you are using the
"protocol.h" interface, it is done for you.

## Notes on Portability

The library is written mostly on C89, but uses the header inttypes.h
from C99, in particular, types uint8_t, uint32_t and uint64_t are used,
and the non-standard function le32toh and htole32 on header "endian.h".

Beyond standard C guarantees, the code only makes one (widely true)
assumption: to be possible to load uint64_t values from 4 bytes aligned
memory.

The only part of the code to use dynamically allocated memory is the
receiving function of "protocol.c", which is part of the convenience
simple protocol. The algorithms themselves are malloc free.

Since all algorithms are specified in little-endian, if LITTLE_ENDIAN
macro is specified during compilation, optimized code dependant on little
endian machine will be used; otherwise, generic code that works on any
endianess will be used. Thus, the code is portable to big-endian machines,
but probably performs better on little-endian.

Likewise, you may gain a small performance boost by defining the macro
UNALIGNED_ACCESS_ALLOWED if your target machine does support byte
granularity when accessing memory, such as x86 *does*, and
ARM *does not*.
