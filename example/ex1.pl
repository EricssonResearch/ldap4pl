:- module(ex1, []).

:- use_module(library(ldap4pl)).

:- debug(ex1).

search :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    ldap_simple_bind_s(LDAP, 'cn=admin,dc=cf,dc=ericsson,dc=net', s3cret),
    ldap_search_ext_s(LDAP,
        query(base('dc=cf,dc=ericsson,dc=net'), scope(ldap_scope_base), attrsonly(false)),
        [], [], 0, Result),
    debug(ex1, 'Result ~w', [Result]),
    ldap_msgfree(Result),
    ldap_unbind(LDAP).