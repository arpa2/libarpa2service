# ARPA2 ID library

This repository contains command-line tools and libraries to work with [ARPA2]
Identities, Selectors and ACLs.

Features:
* liba2id - library to parse and match A2IDs
* a2acl - command-line tool to test if communication between two A2IDs is allowed
* liba2acl - library to work with A2ACLs
* a2idmatch - command-line tool to test if an A2ID matches a selector
* Libraries are POSIX C89 without extra dependencies

Status: **beta**

## Requirements

Build requirements:
* A C89 compiler
* CMake >= 3.3

Run-time requirements:
* Any POSIX-compliant system

## Installation

```sh
$ git clone https://github.com/arpa2/libarpa2service.git
$ cd libarpa2service/build
$ cmake ..
$ make
$ sudo make install
$ sudo ldconfig
```

## Using the libraries

After the libraries are installed, make sure to include `arpa2/a2id.h` or
`arpa2/a2acl.h` in your source file and hint the compiler to include the a2id or
a2acl library with the -l flag.

```sh
$ cc -la2id yourcode.c
```

## Documentation

For further documentation please refer to [ARPA2 Identifier and ACL introduction]
and the manpages:
* [a2acl(1)]
* [a2idmatch(1)]
* [a2acl(3)]
* [a2id(3)]
* [a2id_match(3)]
* [a2acl.conf(5)]

## Examples

Some examples on how-to use the two included command-line tools [a2acl(1)] and
[a2idmatch(1)]. If you're not yet familiar with ARPA2 IDs or ACLs, please see
the [ARPA2 Identifier and ACL introduction].

### a2acl

> NOTE: the following example can be easily replayed by using the docker-demo:
> ```sh
> git clone https://github.com/arpa2/docker-demo.git
> cd docker-demo/demo-acl
> docker build -t a2acl .
> docker run -it a2acl bash
> cd /root/arpa2
> ```

We are going to define the following policy:
1. Whitelist all communication from anyone @ashop.example.com to tim+ashop@dev.arpa2.org
2. Blacklist all communication from anyone @ashop.example.com to tim@dev.arpa2.org or
any other alias of tim@dev.arpa2.org
3. Abandon all communication from anyone @.tk to tim@dev.arpa2.org (or any
alias)
4. Blacklist all communication from anyone to tim@dev.arpa2.org (or any alias)

The above ACL policy is notated in the text file `demopolicy` as follows:

```ascii
@ashop.example.com tim@dev.arpa2.org %W +ashop %B +
@.tk tim@dev.arpa2.org %A +
@. tim@dev.arpa2.org %B +
```

Each line in the file contains one ACL rule. A rule is a triplet of a remote
selector, a local ID in core form, and one (or more) ACL segments. So the first
rule can be broken down as follows:
* the remote selector: `@ashop.example.com`
* the local ID in core form: `tim@dev.arpa2.org`
* the ACL segments: `%W +ashop` and `%B +`

Each ACL segment consists of the first letter of the list and an alias, `%W` and
`+ashop`, respectively. The alias must be combined with the local ID and would
yield tim+ashop@dev.arpa2.org. This holds for each ACL segment. The full meaning
of the first rule is that any communication from remote selector
`@ashop.example.com` to `tim+ashop@dev.arpa2.org` is whitelisted and any
communication from remote selector `@ashop.example.com` to `tim@dev.arpa2.org`
or any other alias of tim@dev.arpa2.org is blacklisted.

A couple of other things to note. Order is significant and the first match wins,
so if a rule matches, subsequent rules are not evaluated. Second, `@.tk` matches
any user at any subdomain of the `.tk` top-level domain. Third, `@.` is the
catch-all selector, matching any user at any domain. Fourth, the `+` alias in an
ACL segment matches any alias. And at last, the combination of a remote selector
and the local ID in core form must be unique. As said, for a detailed
explanation see [ARPA2 Identifier and ACL introduction].

> XXX The current rule syntax closely resembles the internal storage format
> which is fine for a machine, but not for human beings. At the same time it is
> vital that no mistakes are made, so expect a new import format somewhere in
> the future. Possibly something like the following (open for suggestions):
>
> ```ascii
> W @ashop.example.com tim+ashop@dev.arpa2.org
> B @ashop.example.com tim+@dev.arpa2.org
> A @.tk tim+@dev.arpa2.org
> B @. tim+@dev.arpa2.org
> ```

The policy can be used with [a2acl(1)] by testing different combinations of
sender and receiver. The first test will check whether communication between
order@ashop.example.com and tim@dev.arpa2.org is allowed according to the above
policy.

```sh
$ a2acl demopolicy order@ashop.example.com tim@dev.arpa2.org
B
```
The result of this test is that communication between these two A2IDs is
blacklisted. The first letter of the list this pair is listed on is echoed back,
in this case the `B` of blacklist because it matches the second rule.

```sh
$ a2acl demopolicy order@ashop.example.com tim+ashop@dev.arpa2.org
W
```

This matches the first rule and the result is that communication between
order@ashop.example.com and tim+ashop@dev.arpa2.org is whitelisted.

```sh
$ a2acl demopolicy some@one.com tim+analias@dev.arpa2.org
B
```

This matches the fourth rule and the result is that this communication pair is
blacklisted.

```sh
$ a2acl demopolicy jane@somedomain.tk tim@dev.arpa2.org
A
```

This matches the third rule and communication between these two IDs is abandoned.

Remember that you can easily execute these examples yourself by using the
docker-demo as noted at the beginning of this chapter.

### a2idmatch

This tool is created to easily experiment with A2IDs and A2ID Selectors. This
way you can test whether a selector matches an ID.

For example, test whether the A2ID "john+dev@example.com" matches the A2ID
selector "@example.com".

```sh
$ a2idmatch john+dev@example.com @example.com
MATCH
```

Or test whether the A2ID "john@example.com" matches the A2ID selector
"@.example.com".

```sh
$ a2idmatch john@example.com @.example.com
MISMATCH
```

## License

ISC

Copyright (c) 2018, 2019 Tim Kuijsten

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

[ARPA2]: http://arpa2.net
[ARPA2 Identifier and ACL introduction]: /doc/design/a2idacl-intro.md
[a2acl(1)]: https://netsend.nl/arpa2/a2acl.1.html
[a2idmatch(1)]: https://netsend.nl/arpa2/a2idmatch.1.html
[a2id(3)]: https://netsend.nl/arpa2/a2id.3.html
[a2acl(3)]: https://netsend.nl/arpa2/a2acl.3.html
[a2id_match(3)]: https://netsend.nl/arpa2/a2id_match.3.html
[a2acl.conf(5)]: https://netsend.nl/arpa2/a2acl.conf.5.html
[a2idgrammar.txt]: /doc/design/a2idgrammar.txt
[a2idselgrammar.txt]: /doc/design/a2idselgrammar.txt
[ARPA2CM]: https://github.com/arpa2/arpa2cm
