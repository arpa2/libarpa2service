# ARPA2 ID library

This repository contains both a command-line tool and a library of functions to
test and parse ARPA2 identities and selectors.

Features:
* a2idmatch - Command line tool to test A2IDs with a selector
* libarpa2id - C89 library without dependencies to parse and match A2IDs

Status: **beta**


## Examples

### command-line a2idmatch
Test whether the A2ID "john+singer@example.com" matches the A2ID selector
"@example.com".
```sh
$ a2idmatch john+singer@example.com @example.com
MATCH
```

Test whether the A2ID "john@example.com" matches the A2ID selector
"@.example.com".
```sh
$ a2idmatch john@example.com @.example.com
MISMATCH
```

### arpa2id library

After the library is installed, make sure to include arpa2/a2id.h in your source
file and hint the compiler to include the arpa2id library with the -l flag.

```sh
$ cc -Wall -larpa2id yourcode.c
```


## Requirements

Build requirements:
* CMake >= 3.1
* CMake [ARPA2CM] package
* A C89 compiler

Run-time requirements:
* Any POSIX-compliant system


## Installation

Make sure the [ARPA2CM] module is installed. Then compile and install
a2idmatch(1) and the arpa2id library:

```sh
$ git clone https://github.com/arpa2/libarpa2service.git
$ cd libarpa2service
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```


## Documentation

The syntax of an A2ID and an A2ID Selector is given in ABNF in [a2idgrammar.txt]
and [a2idselgrammar.txt], respectively.

For further documentation please refer to the corresponding man page:
* [a2idmatch(1)]
* [a2id_alloc(3)]
* [a2id_fromstr(3)]
* [a2id_match(3)]
* [a2id_parsestr(3)]


## License

ISC

Copyright (c) 2018 Tim Kuijsten

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.


[ARPA2CM]: https://github.com/arpa2/arpa2cm
[a2idmatch(1)]: https://netsend.nl/a2id/a2idmatch.1.html
[a2id_alloc(3)]: https://netsend.nl/a2id/a2id_alloc.3.html
[a2id_fromstr(3)]: https://netsend.nl/a2id/a2id_fromstr.3.html
[a2id_match(3)]: https://netsend.nl/a2id/a2id_match.3.html
[a2id_parsestr(3)]: https://netsend.nl/a2id/a2id_parsestr.3.html
[a2idgrammar.txt]: https://github.com/timkuijsten/libarpa2service/blob/a2id/doc/design/a2idgrammar.txt
[a2idselgrammar.txt]: https://github.com/timkuijsten/libarpa2service/blob/a2id/doc/design/a2idselgrammar.txt
