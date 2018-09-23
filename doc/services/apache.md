# Apache httpd - Design for mod_arpa2_xxx

> *How can we integrate libarpa2service with the Apache webserver?*

This is a first examination of how the work done here could connect to Apache httpd.
There is a
[module writing guide](https://httpd.apache.org/docs/2.4/developer/modguide.html)
that should prove useful.


## Transport Layer Security

The `mod_arpa2_tls` filters a connection through TLS, thus securing it and allowing
negotiation of identities.  Regardless of underlying library, the model is supportive
of client-side identities, for which we prioritise TLS-KDH for Kerberos authentication.

We also value the separation of public-key crypto from the process context of an
HTTP server, so we will take out the connection to an external daemon, presently
our TLS Pool.  Future iterations may only pass the handshake to such a daemon,
and run the bulk encryption with short-lived keys in the HTTP environment.

Identities in the ARPA2 system are always qualified with a domain name, like
`user@domain.name`.  This allows straightforward access control for external
users, which we support throughout the ARPA2 identity system.  This is a deliberate
choice to stop the need for site-specific user names and, heaven forbid, passwords.
Instead, we encourage users towards a Bring Your Own IDentity approach.

Note that `mod_arpa2_tls` will not provide certificate details, because that would
constrain the module to serving only certificate-using clients.  It will
simply provide the client and server identities as `ARPA2_CLIENT_IDENTITY` and
`ARPA2_SERVER_IDENTITY`, respectively.  The module supports a language that can
require a desired level of guarantees without getting specific about the technology
used.

The support for this kind of processing is specified in the
[filter chain](https://ci.apache.org/projects/httpd/trunk/doxygen/group__APACHE__CORE__FILTER.html)
where one may setup input and output filter endpoints.  Since TLS runs throughout
the connection, its registration would be `AP_FTYPE_CONNECTION`.

A function that adds the filter functions to a connection is called from
a callback hook installed with `ap_hook_pre_connection`.
There would some per-connection structure holding the following elements:

  * State and flags:

      - Whether client authentication has been tried

  * Sockets for plain and crypted communication with the TLS Pool
  * Established client and server identities

It's not very nice that the two ends to the TLS Pool are socket pairs.
This is something we ran into before, and it is part of the design that
allowed us to pass a connection over to another process.  Thinking of a
future with a connection just for handshaking, this ought to get simpler;
there is not even a need for a plaintext side!


## SASL Authentication

In cases where `mod_arpa2_tls` does not perform authentication through
client certificates or Kerberos tickets, there is an option of falling
back to SASL authentication.  This would be done with `mod_arpa2_sasl`
but relates to `mod_arpa2_tls` to assure an encrypted connection.

This is not standard; the approach is described in
[HTTP SASL](https://datatracker.ietf.org/doc/draft-vanrein-httpauth-sasl/)
which would offer a serious alternative, especially when it includes channel
binding.  Note that `SASL EXTERNAL` is a method for referring back to the
authentication by `mod_arpa2_tls` for which a client identity might be
found.


## Authentication and Authorisation

Authentication of the (initial) user identity is based on TLS and SASL;
authorisation on the other hand, is an internal matter based on `libarpa2acl`.
A good question is now what to authorise for, and this may differ between Apache's contexts.
A choice to communicate with either a user/group/role or a resource selects an ACL to use.
While evaluating access rights, the user identity may be degraded to a member/occupant name
for privacy towards a group/role, or it may be assigned an(other) alias for better selectivity.

To communicate with a given user/group/role, setup `CommunicateWith` statically or
extract it from the `PATH_INFO` with a regular expression.
This may for example be used to access a group's website.
For reasons of security and efficiency, we should probably specify whether we are
communicating with a user, group or role.

To access a resource, static configuration is used to setup in `ResourceUUID`.
On top of that, a `ResourceInstanceUUID` may be extracted from the `PATH_INFO`
with a regular expression.

Whether access control is based on static or dynamic information does not really
make a difference in terms of efficiency; the lookups are always made in the
database, so that changes take effect immediately.  Any optimisations that we
would do would be centralised and based on fully dynamic caching, with immediate
removal of at least those entries that may have changed during a database update.

The `arpa2acl` interface will retrieve the authorisation information for the
desired communication partner, based on the HTTP client identity.  While doing
this, it will also verify any alias, and perhaps modify it.

Apache uses
[callback hooks](https://ci.apache.org/projects/httpd/trunk/doxygen/group__hooks.html)
for authentication.  The following are run in order, and are of interest to ARPA2:

  * [access_checker](https://ci.apache.org/projects/httpd/trunk/doxygen/group__hooks.html#ga60c469c5b2e1836b349ef9ab2e6e7dde)
    is run independently of `Require` and even before authentication.  Its purpose is to apply additional access control.
    In `mod_arpa2_auth`, it could be used to preselect the ACL to use for the current request.  An attempt may be made
    to lookup caches as well, though that would not be connection-specific but rather centralised.  This cache is central
    so its entries can be cleansed from possibly changed results as soon as the database changes.

  * [check_user_id](https://ci.apache.org/projects/httpd/trunk/doxygen/group__hooks.html#ga11490a031d48bbe0efd3b2e11cd7a9e6)
    is run as demanded by `Require`.  Its purpose is to authenticate the user.
    In `mod_arpa2_auth`, it would refer to a client identity established over TLS, either via X.509 or Kerberos.
    It may therefore be more practical to integrate it with `mod_arpa2_tls` instead, or it might simply be delegated.

  * [auth_checker](https://ci.apache.org/projects/httpd/trunk/doxygen/group__hooks.html#ga5053c0adc6eb7a9557dea93fa6f74bee)
    is run as demanded by `Require`.  Its purpose is to authorise the user's intended access to a resource.
    In `mod_arpa2_auth`, it would run through the ACL while checking and possibly setting the user name to an alias
    or member/occupant name.  The access rights will be published in the `ARPA2_RIGHTS` environment variable.
    Note that the fallback right is `V` for visitor; as long as the ACL is technically reachable there should never be a
    refusal of that access right.  This helps the HTTP server to produce distinctions between server errors and
    access refusal when a resource is accessed with an unsupported method.

By default, only the following methods are permitted in correspondance with
the ACL, but they can be reconfigured as desired.

  * `POST`   requires the right `C` for creating a resource;
  * `PUT`    requires the right `W` for writing  a resource;
  * `GET`    requires the right `R` for reading  a resource;
  * `DELETE` requires the right `D` for deleting a resources.

These defaults are designed for RESTful HTTP applications, which could therefore
be run under the flexible ARPA2 identity model without any configuration beyond
the selection of an ACL!

Also note that it is really straightforward to require more refined control.
For example, a blog may configure a separate context for its update pages, and
require ARPA2 authentication to even see them.  This is a quickfix for constant
attacks on login pages that are built into applications.  The true solution of
the ARPA2 identity model is that access control is taken out of the application
layer and moved back into the transport layer, where attacks based on programming
errors in the application cannot ever gain the access that they so fraudulenty
seek.

It may be possible to specify access control rules as one would in a full-blown ARPA2
infrastructure, but specialised to a HTTP server context, but this may not scale well.


## Example: Reservoir access via WebDAV

The WebDAV protocol allows access to Reservoir, which is our object store with
metadata in LDAP and the actual blobs stored in Riak KV.  Paths to objects in
Riak KV look like

    /types/TYPE/buckets/BUCKET/keys/KEY

which will be used like

    /types/DOMAIN/buckets/RES_COLL_UUID/key/OBJ_UUID

of which a WebDAV user only sees forms like

    /RES_COLL_UUID/OBJ_UUID
    /RES_COLL_NAME/OBJ_NAME
    /RES_COLL_NAME/?SEARCH_PATTERN
    /?SEARCH_PATTERN

The web domain addressed for WebDAV determines the `DOMAIN` that will act as the
bucket type in Riak KV so it is fixed.  The application Reservoir has a fixed
Resource UUID to find its resourceClass in LDAP; the `RES_COLL_UUID` is the
resourceInstance in LDAP and serves to zoom in on the specific ACL for that
particular Resource Collection; finally, the object is found but it has no
special rights assigned to it, as these follow the holding Resource Collection.

A client visits the WebDAV service and somehow authenticates its identity.
Then, the hostname and path sent to WebDAV are used to find the ACL, and
decide on access.  WebDAV has more refined operations too, such as listing
and searching, for which more refined access rights are used.


