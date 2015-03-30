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
    ldap_get_option/3,
    ldap_result/4,
    ldap_result/5,
    ldap_msgfree/1,
    ldap_msgtype/2,
    ldap_msgid/2,
    ldap_search_ext/7,
    ldap_search_ext/6,
    ldap_search_ext_s/7,
    ldap_search_ext_s/6,
    ldap_count_entries/3
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

ldap_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCred) :-
    ldap4pl_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCred).

ldap_set_option(LDAP, Option, Value) :-
    ldap4pl_set_option(LDAP, Option, Value).

ldap_get_option(LDAP, Option, Value) :-
    ldap4pl_get_option(LDAP, Option, Value).

ldap_result(LDAP, MsgID, All, Result) :-
    ldap4pl_result(LDAP, MsgID, All, _, Result).

ldap_result(LDAP, MsgID, All, Timeout, Result) :-
    ldap4pl_result(LDAP, MsgID, All, Timeout, Result).

ldap_msgfree(Msg) :-
    ldap4pl_msgfree(Msg).

ldap_msgtype(Msg, Type) :-
    ldap4pl_msgtype(Msg, Type).

ldap_msgid(Msg, ID) :-
    ldap4pl_msgid(Msg, ID).

ldap_search_ext(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, MsgID) :-
    ldap4pl_search_ext(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, MsgID).

ldap_search_ext(LDAP, Query, SCtrls, CCtrls, SizeLimit, MsgID) :-
    ldap4pl_search_ext(LDAP, Query, SCtrls, CCtrls, _, SizeLimit, MsgID).

ldap_search_ext_s(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, Result) :-
    ldap4pl_search_ext_s(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, Result).

ldap_search_ext_s(LDAP, Query, SCtrls, CCtrls, SizeLimit, Result) :-
    ldap4pl_search_ext_s(LDAP, Query, SCtrls, CCtrls, _, SizeLimit, Result).

ldap_count_entries(LDAP, Result, Count) :-
    ldap4pl_count_entries(LDAP, Result, Count).
