# ldap4pl

This package provides Prolog bindings for [OpenLDAP](http://www.openldap.org) API.

Most APIs have been implemented and the names are aligned with OpenLDAP API,
so for detailed description please check [here](http://www.openldap.org/software/man.cgi).

## Installation

Using SWI-Prolog 7 or later.

    ?- pack_install('http://git.cf.ericsson.net/ehonlia/ldap4pl.git').

Compilation on Mac OS X and GNU Linux has been verified, not on Windows.

Source code available and pull requests accepted
[here](http://git.cf.ericsson.net/ehonlia/ldap4pl).

@author Hongxin Liang <hongxin.liang@ericsson.com>

@license TBD

## Examples

To search asynchrously:

    :- use_module(library(ldap4pl)).
    :- use_module(library(ldap4pl_util)).

    search :-
        ldap_initialize(LDAP, 'ldap://example.org'),
        ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
        ldap_simple_bind_s(LDAP, 'cn=...,dc=...,dc=...,dc=...', passwd),
        ldap_search(LDAP,
            query(
                base('dc=...,dc=...,dc=...'),
                scope(ldap_scope_onelevel),
                filter('(objectClass=*)'),
                attrs([objectClass, sambaDomainName]),
                attrsonly(false)
            ),
            MsgID),
        ldap_result(LDAP, MsgID, true, Result),
        ldap_parse_result(LDAP, Result, _, _, _, _, _, false),
        ldap_parse_search_result(LDAP, Result, List),
        print_term(List, []),
        ldap_msgfree(Result),
        ldap_unbind(LDAP).

To do a simple auth:

    :- use_module(library(ldap4pl)).
    :- use_module(library(ldap4pl_util)).

    auth :-
        ldap_simple_auth('ldap://example.org',
            'cn=...,dc=...,dc=...,dc=...',
            passwd).

To add a new entry:

    :- use_module(library(ldap4pl)).
    :- use_module(library(ldap4pl_util)).

    add :-
        ldap_initialize(LDAP, 'ldap://example.org'),
        ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
        ldap_simple_bind_s(LDAP, 'cn=...,dc=...,dc=...,dc=...', passwd),
        DN = 'cn=...,ou=groups,dc=...,dc=...,dc=...',
        ldap_add_s2(LDAP, DN, _{objectClass:[posixGroup, top], cn:test, gidNumber:'20000', description:hello}),
        ldap_unbind(LDAP).

For more examples, please check source code under `examples` directory.
