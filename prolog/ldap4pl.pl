:- module(ldap4pl, [
    ldap_initialize/2,
    ldap_unbind/1,
    ldap_unbind_ext/3,
    ldap_bind/4
]).

:- use_foreign_library(foreign(ldap4pl)).

ldap_initialize(LDAP, URI) :-
    ldap4pl_initialize(LDAP, URI).

ldap_unbind(LDAP) :-
    ldap4pl_unbind(LDAP).

ldap_unbind_ext(LDAP, SCTRLS, CCTRLS) :-
    ldap4pl_unbind_ext(LDAP, SCTRLS, CCTRLS).

ldap_bind(LDAP, WHO, CRED, METHOD) :-
    ldap4pl_bind(LDAP, WHO, CRED, METHOD).