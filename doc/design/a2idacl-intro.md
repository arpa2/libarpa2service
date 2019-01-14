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

    john+doe+jzdxrpbn5iu0wca+@example.com

Here the core form would be "john@example.com", it is extended with the alias
"doe" and the sigflags segment "jzdxrpbn5iu0wca".

## Communication ACL

Each owner of an A2ID can define a policy that specifies whether or not
communication may take place with some other A2ID. The other A2ID, hereafter
"remote ID" may be specified as an exact A2ID or more broadly as an
[A2ID Selector].

The combination of a remote ID and a local ID is called a communication pair. To
answer the question about whether or not two A2IDs may communicate with each
other the pair should be on one of the four following lists:

* _Blacklist_: communication between the remote and local ID is not allowed

* _Whitelist_: communication between the remote and local ID is allowed

* _Greylist_: it is not yet decided whether communication between the remote
    and local ID is allowed or not

* _Honeypot_: communication between the remote and local ID is not allowed
    and there is no guarantee this is communicated back to the remote

A communication ACL consists of rules. Each rule is a triplet of the following
form:
    <remote selector, local ID, ACL segments>

The remote selector is an [A2ID Selector]. This selector is to be matched with
the remote ID of a communication pair in process called generalization
(explained later). The local ID is the core form of the local ID of the
communication pair. Finally ACL segments is what glues different optional
segments of the local ID to a list (explained later).

Because the remote ID of a policy is specified as an A2ID Selector it is
possible to quickly define a policy for a broad range of remote A2IDs and set
defaults. By using more specific selectors or even concrete A2IDs for the remote
a more fine-grained policy can be set and overrule broader policies.

### ACL segments

An ACL segment binds different extended forms of the local ID to a list-type.
This is done by using the first letter of a list (i.e. W for whitelist) followed
by one or more ACL segments. ACL segment notation is like the optional segment
notation of an extended local ID, with only a few exceptions:

1. Each segment must start with a *+* character.

2. If presence of a signature is required, this can be expressed by terminating
the segment with a *+*.

3. If the segment consists of only a the *+* character this is to be interpreted
as a wild-card match, matching all segments, including none.  This syntax can
optionally combined with rule 2 which would yield *++*.

This way different extended local IDs can be expressed and put on a list. I.e.
in order to whitelist all local IDs that start with the segment "dev" the
policy "%W +dev" could be set. Or in order to put all *signed* local IDs on a
greylist the policy "%G ++" should be set, which stands for the wildcard *+* and
a terminating *+* to express requirement of a signature. See [ACL grammar] for
the exact definition.

### Generalization

Any A2ID Selector, including the remote Selector can be generalized.
Generalization is the process of changing a Selector from abstract to concrete
by pulling off one part at a time. At first the localpart is trimmed down, and
once there is no more localpart, each label of the domain is cut-off. In the end
yielding the most general selector "@.". The exact details of this process can
be found in [A2ID Selector]. In order to see if a remote ID matches a remote
Selector of an ACL rule, the remote ID is generalized until a match is found or
until the ID can not be further generalized.

### Examples

Assume the following policy is set at the A2ID server of jane@example.com.

    @arpa2.net jane@example.com %W +dev
    @. jane@example.com %B +

This policy consists of two ACL rules (or triplets). The first triplet
<@arpa2.net, jane@example.com, %W +dev> expresses that communication from anyone
at arpa2.net to jane+dev@example.com is whitelisted. Remember that an ACL segment
consists of a list-type, %W in this case, and one or more ACL segments, +dev in
this case. These segments are to be combined with the local ID.

The second triplet <@., jane@example.com, %B +> specifies a catch-all remote
selector, namely "@." and a catch-all ACL segment for the local ID, the *+*
without any suffix. This rule will catch each and every form of communication
with jane@example.com as long as it is not machted by a more specific remote
selector. It effectively means that a global blacklist policy is set.

The full lookup process consists of a series of lookups on the remote ID and
local ID of each triplet, in order to find a matching ACL segment that is
designated to a list.  Each time there is no match, the remote ID is generalized
further until it equals the "@." selector and cannot be further generalized.

Now imagine mike@arpa2.net wants to communicate with jane+dev@example.com. The
first lookup is done on the original remote ID and core form of the local ID in
order to see if any ACL segment matches.

    <mike@arpa2.net, jane@example.com>

This lookup yields no ACL segments since there is no specific policy defined for the
remote mike@arpa2.net. Therefore the remote ID is generalized by one step and a
new lookup is done. The first generalization of "mike@arpa2.net" yields
"@arpa2.net". A new lookup is done with this newly formed generalized remote ID
and the unaltered core form of the local ID:

    <@arpa2.net, jane@example.com>

This lookup does yield the triplet:
    <@arpa2.net, jane@example.com, %W +dev>

Once a triplet is found, each ACL segment is combined with the local ID and
compared with the local ID of the communication pair. In this case the first
(and only) ACL segment is "+dev". It is combined with the core form of the local
ID in the triplet, and forms jane+dev@example.com. This construction is then
compaired with the original local ID of the communication pair. Since this is an
exact match the list-type %W is used, which mean communication is whitelisted.

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
