:- module(ldap4pl, [
    ldap_initialize/2,
    ldap_unbind/1,
    ldap_unbind_s/1,
    ldap_unbind_ext/3,
    ldap_unbind_ext_s/3,
    ldap_bind/5,
    ldap_bind_s/4,
    ldap_simple_bind/4,
    ldap_simple_bind_s/3,
    ldap_sasl_bind/7,
    ldap_sasl_bind_s/7,
    ldap_set_option/3,
    ldap_get_option/3
]).

:- use_foreign_library(foreign(ldap4pl)).

ldap_initialize(LDAP, URI) :-
    ldap4pl_initialize(LDAP, URI).

ldap_unbind(LDAP) :-
    ldap4pl_unbind(LDAP).

ldap_unbind_s(LDAP) :-
    ldap4pl_unbind(LDAP).

ldap_unbind_ext(LDAP, SCtrls, CCtrls) :-
    ldap4pl_unbind_ext(LDAP, SCtrls, CCtrls).

ldap_unbind_ext_s(LDAP, SCtrls, CCtrls) :-
    ldap4pl_unbind_ext(LDAP, SCtrls, CCtrls).

ldap_bind(LDAP, Who, Cred, Method, MsgID) :-
    ldap4pl_bind(LDAP, Who, Cred, Method, MsgID).

ldap_bind_s(LDAP, Who, Cred, Method) :-
    ldap4pl_bind_s(LDAP, Who, Cred, Method).

ldap_simple_bind(LDAP, Who, Passwd, MsgID) :-
    ldap4pl_simple_bind(LDAP, Who, Passwd, MsgID).

ldap_simple_bind_s(LDAP, Who, Passwd) :-
    ldap4pl_simple_bind_s(LDAP, Who, Passwd).

ldap_sasl_bind(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, MsgID) :-
    ldap4pl_sasl_bind(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, MsgID).

ldap_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCredP) :-
    ldap4pl_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCredP).

ldap_set_option(LDAP, Option, Value) :-
    ldap4pl_set_option(LDAP, Option, Value).

ldap_get_option(LDAP, Option, Value) :-
    ldap4pl_get_option(LDAP, Option, Value).