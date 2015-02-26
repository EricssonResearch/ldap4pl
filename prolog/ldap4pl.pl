:- module(ldap4pl, [
    ldap_initialize/2,
    ldap_unbind/1,
    ldap_unbind_s/1,
    ldap_unbind_ext/3,
    ldap_unbind_ext_s/3,
    ldap_bind/4,
    ldap_bind_s/4,
    ldap_simple_bind/3,
    ldap_simple_bind_s/3
]).

:- use_foreign_library(foreign(ldap4pl)).

ldap_initialize(LDAP, URI) :-
    ldap4pl_initialize(LDAP, URI).

ldap_unbind(LDAP) :-
    ldap4pl_unbind(LDAP).

ldap_unbind_s(LDAP) :-
    ldap4pl_unbind_s(LDAP).

ldap_unbind_ext(LDAP, SCTRLS, CCTRLS) :-
    ldap4pl_unbind_ext(LDAP, SCTRLS, CCTRLS).

ldap_unbind_ext_s(LDAP, SCTRLS, CCTRLS) :-
    ldap4pl_unbind_ext_s(LDAP, SCTRLS, CCTRLS).

ldap_bind(LDAP, WHO, CRED, METHOD) :-
    ldap4pl_bind(LDAP, WHO, CRED, METHOD).

ldap_bind_s(LDAP, WHO, CRED, METHOD) :-
    ldap4pl_bind_s(LDAP, WHO, CRED, METHOD).

ldap_simple_bind(LDAP, WHO, PASSWD) :-
    ldap4pl_simple_bind(LDAP, WHO, PASSWD).

ldap_simple_bind_s(LDAP, WHO, PASSWD) :-
    ldap4pl_simple_bind_s(LDAP, WHO, PASSWD).
