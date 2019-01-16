# ARPA2 Identifier and ACL introduction

An ARPA2 Identifier, or A2ID, is a unique identifier belonging to a domain and
optionally one or more persons or a service within that domain. There are three
distinct types of an A2ID:

* _GENERIC_; belongs to a person, group or role within a domain
* _SERVICE_; belongs to a service (process) within a domain
* _DOMAINONLY_; belongs to a domain only

Each A2ID has an owner. The owner of an A2ID is the person or process with
access to the private key of the A2ID. In case an A2ID belongs to a group or role
it's possible multiple people have access to the private key of an A2ID.

## Anatomy of an A2ID

An A2ID is separated into two logical parts, the *localpart* and the *domain*.
The localpart is subdivided into one or more segments separated by a plus
character. A domain consists of labels separated by a dot. Both a SERVICE and a
GENERIC A2ID have a localpart and a domain name. A DOMAINONLY A2ID has no
localpart, only a domain name.

### Localpart segments

Each localpart consists of one or more segements. There are three different
types of segments:

* _name segment_; always the first segment of a localpart and must appear exactly
once.

* _optional segment_; of which the first always appears right after the name segment
and can occur multiple times, or not at all.

* _sigflags segment_; must appear as the last segment of the localpart if present.

## A2ID forms

There are two forms of an A2ID. The core form and the extended form. The core
form is the base identity of an A2ID. It has a localpart with only the name
segment. Each A2ID has exactly one core form. The extended form is a form that
is based on the core form but extended with optional segments and/or a sigflags
segment, hereafter "extra segments". There are practically an infinite number of
extended forms that can be made out of a core form.

### Core form

The core form of a GENERIC and SERVICE A2ID consist of a name segment followed
by the domain name. The core form of a DOMAINONLY A2ID is just the domain name
without a localpart.  See [A2ID grammar] for an exact definition of the
structure of an A2ID.

Example core form of a GENERIC A2ID:

    john@example.com

Example core form of a SERVICE A2ID:

    +smtp@example.com

Example core form of a DOMAINONLY A2ID:

    @example.com

### Extended form

The core form of SERVICE and GENERIC A2IDs can be extended with extra segments.
The number of extra segments and length of each segment is only restricted by
the maximum length of the complete A2ID (including the domain), which is
currently set at 512 characters.

Segments are separated from each other with a *+* character. The set of allowed
characters is specified in the [A2ID grammar]. Broadly speaking it's every
graphical ASCII character except for the *+* and *@*.

A DOMAINONLY A2ID has no extended form since it has no localpart.

Example of the core form "john@example.com" extended with the alias "doe":

    john+doe@example.com

Example of the core form "dev@example.com" extended with group members "mike"
and "jane" by using two optional segments:

    dev+mike+jane@example.com

### Signature and flags segment

Apart from the optional segments a localpart can be extended with a *sigflags*
segment. The presence of flags require presence of a signature but the presence
of a signature does not require flags. Flags indicate which data is included in
the signature.

Both flags and a signature are combined into the *sigflags segment*. This
segment is optional but if present must appear as the last segment in the
localpart. The signature and flags are encoded in Base32. The sigflags segment
must end with a *+* character. [SIGFLAGS] specifies the exact details of the
structure of this segment.

An example A2ID extended with an optional segment and a sigflags segment:

    john+doe+n5iu0wca+@example.com

Here the core form would be "john@example.com", it is extended with the alias
"doe" and the sigflags segment "n5iu0wca".

## Communication ACL

Each owner of an A2ID can define a policy that specifies whether or not
communication may take place with some other A2ID. The other A2ID, hereafter
"remote ID" may be specified as an exact A2ID or more broadly as an
[A2ID Selector].

The combination of a remote ID and a local ID is called a communication pair. To
answer the question about whether or not two IDs may communicate, the pair
should be on one of the following lists:

* _Blacklist_: communication between the remote and local ID is not allowed

* _Whitelist_: communication between the remote and local ID is allowed

* _Greylist_: it is not yet decided whether communication between the remote
    and local ID is allowed or not

* _Abandoned_: communication between the remote and local ID is not allowed
    and there is no guarantee this is communicated back to the remote

The way communication pairs are put on one of the above lists is by specifying
a policy that consists of one or more *ACL rules*. Each rule is a triplet that
consists of a remote ID in the form of a selector and a local ID in it's core
form that is combined with *ACL segments* (explained hereafter). The triplet can
be summarized as follows:

    <remote selector, local ID core form, ACL segments>

The remote selector is to be matched with the remote ID of a communication pair
in a process called *generalization* (explained later). The core form of the
local ID must be combined with one of the segments in the *ACL segments* part of
the triplet. Each ACL segment starts with a list specifier.

Because the remote ID of a policy is specified as an A2ID Selector it is
possible to quickly define a policy for a broad range of remote A2IDs and set
defaults. By using more specific selectors or even concrete A2IDs for the remote
a more fine-grained policy can be set and overrule broader policies.

### ACL segments

An ACL segment binds different extended forms of the local ID to a list.
Multiple ACL segments may exist to bind different extended forms to different
lists. The first matching one wins. Within an ACL segment, one or more *extra
segments* can be specified using a syntax that allows for wildcard matching and
the ability to require a signature in a local ID without having to specify the
resulting signature upfront.

The ACL segment syntax can be described as follows:

1. Each ACL segment starts with a list specifier, a *%* followed by the first
letter of the list it is subject to.

2. Each following *extra segment* must start with a *+* character.

3. If presence of a signature is required, this can be expressed by terminating
the *extra segment* with a *+*.

4. If the *extra segment* consists of only the *+* character this is to be
interpreted as a wildcard match, matching all extra segments, including none.
This syntax may be combined with rule 3 to match all extended forms of the local
ID that have a signature.

See [ACL grammar] for the exact definition.

I.e. to whitelist communication from anyone with jane+dev@example.com, the
following rule could be set:

    <@., jane@example.com, %W +dev>

The segment *%W +dev* combined with the local ID *jane@example.com* would match
jane+dev@example.com, jane+dev+clang@example.com, but not the core form
jane@example.com (the remote selector *@.* is explained hereafter).

Or an ACL segment to greylist all *signed* local IDs:

    %G ++
    
This ACL segment starts with the wildcard *+* and terminates with a *+* to
express the requirement of a signature. If the local ID again were
jane@example.com, this ACL segment would match the extended forms
jane+dev+n5iu0wca+@example.com and jane+n5iu0wca+@example.com, but not
jane@example.com (this time because a signature is required).

### Generalization

In order to check if a remote ID matches a remote selector of an ACL rule (not
to be confused with an ACL segment), the remote ID is generalized until a match
is found. Generalization is the process of removing segments from the localpart
and labels from the domain. At first the localpart is generalized. Each
generalization step yields in a new localpart that has one segment removed. The
new resulting remote ID is then compared with the remote selector of the ACL
rule. If there is a match, this process stops and the ACL rule is taken into
consideration. If the generalized remote ID does not match and there are still
segments in the localpart or labels in the domain, the remote ID is generalized
further. If there is no match at each generalization step, and all no segments
and labels have been removed (resulting in the most general selector *@.*) this
process ends and the ACL rule does not match this remote ID. If there are more
ACL rules, this process starts all over with the remote selector of the next
rule. Further details of this process can be found in [A2ID Selector].

### Examples

Assume the following two ACL rules define the policy of *jane@example.com*.

    <@arpa2.net, jane@example.com, %W +dev>
    <@., jane@example.com, %B +>

The first triplet whitelists communication from anyone at arpa2.net with
jane+dev@example.com. Remember that an ACL segment consists of a list (*%W* in
this case), and one or more ACL extra segments (here it's *+dev*). These
extra segments are to be combined with the local ID, hence we get
jane+dev@example.com.

The second triplet specifies a catch-all remote selector, namely *@.* and a
wildcard local ID ACL segment, the *+* without a suffix. This rule will apply to
anyone that wants to communicate with jane@example.com as long as it is not
machted by another triplet that has a more specific remote selector. It
effectively means that a global blacklist policy is set.

Now imagine mike@arpa2.net wants to communicate with jane+dev@example.com and
the above policy is in place. In order to decide if communication is allowed and
on which list this communication pair is put, the remote ID *mike@arpa2.net* is compared with
the remote selector of each ACL rule until a match is found.

The first ACL rule with remote selector *@arpa2.net* is compared with
*mike@arpa2.net*. This abviously doesn't match, so the remote ID is generalized
by one step, in this case removing the segment *mike* from the localpart. This
new resulting remote ID *@arpa2* is compared with the remote selector *@arpa2*.
This time there is a match, so no further generalization is needed and this ACL
rule is used for further evaluation of the local ID.

In the next phase each extra segment of the rules ACL segment is combined with
the local ID and compared with the local ID of the communication pair. In this
case the first (and only) ACL segment is *%W +dev*. The extra segment *+dev* is
combined with the local ID in the triplet, which yields jane+dev@example.com and
compaired with the original local ID of the communication pair
*jane+dev@example.com*. Since this is an exact match it is deciced that
communication is whitelisted.

## Resource ACL

Resource ACLs work like communication ACLs except that the local ID is not an
A2ID but a 128 bit UUID of a resource. Furthermore access rights are set instead
of different policy lists. The following rights are defined:

    A superpower
    D right to delete
    C right to create
    W writing
    R reading
    K checking for existence
    O editing and removing one's own objects

See [ACL] for a more precise specification of resource ACLs.

[A2ID grammar]: https://github.com/timkuijsten/libarpa2service/blob/master/doc/design/a2idgrammar.txt
[ACL grammar]: https://github.com/timkuijsten/libarpa2service/blob/acl/doc/design/a2aclgrammar.txt
[SIGFLAGS]: http://a2id.arpa2.org/sigflags.html
[A2ID Selector]: http://donai.arpa2.net/selector.html
[ACL]: http://donai.arpa2.net/acl-impl.html
