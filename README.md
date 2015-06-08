# ldap4pl

This package provides Prolog bindings for [OpenLDAP](http://www.openldap.org) API.

Most APIs have been implemented and the names are aligned with OpenLDAP API,
so for detailed description please check [here](http://www.openldap.org/software/man.cgi).

Verified with OpenLDAP 2.4.x.

## Installation

Using SWI-Prolog 7 or later.

    ?- pack_install('https://github.com/EricssonResearch/ldap4pl.git').

Compilation on Mac OS X and GNU Linux has been verified, not on Windows.

Source code available and pull requests accepted
[here](https://github.com/EricssonResearch/ldap4pl).

@author Hongxin Liang <hongxin.liang@ericsson.com>

@license Apache License Version 2.0

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

## License

Copyright 2015 Ericsson

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
