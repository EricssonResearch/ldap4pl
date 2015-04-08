:- module(ldap4pl_util, [
    ldap_parse_search_result/3,
    ldap_simple_auth/3
]).

:- use_module(library(ldap4pl)).

ldap_parse_search_result(LDAP, Result, List) :-
    iterate_entries(LDAP, Result, List).

iterate_entries(LDAP, Result, List) :-
    (   ldap_first_entry(LDAP, Result, Entry)
    ->  iterate_entries0(LDAP, Entry, List0),
        parse_entry(LDAP, Entry, Dict),
        List = [Dict|List0]
    ;   List = []
    ).

iterate_entries0(LDAP, Entry, List) :-
    (   ldap_next_entry(LDAP, Entry, NextEntry)
    ->  iterate_entries0(LDAP, NextEntry, List0),
        parse_entry(LDAP, NextEntry, Dict),
        List = [Dict|List0]
    ;   List = []
    ).

parse_entry(LDAP, Entry, Dict) :-
    iterate_attributes(LDAP, Entry, Attributes),
    ldap_get_dn(LDAP, Entry, DN),
    Dict = _{dn:DN, attributes:Attributes}.

iterate_attributes(LDAP, Entry, Attributes) :-
    (   ldap_first_attribute(LDAP, Entry, Attribute, Ber)
    ->  iterate_attributes0(LDAP, Entry, Ber, Attributes0),
        ldap_get_values(LDAP, Entry, Attribute, Values),
        Attributes = Attributes0.put(Attribute, Values)
    ;   Attributes = _{}
    ).

iterate_attributes0(LDAP, Entry, Ber, Attributes) :-
    (   ldap_next_attribute(LDAP, Entry, Attribute, Ber)
    ->  iterate_attributes0(LDAP, Entry, Ber, Attributes0),
        ldap_get_values(LDAP, Entry, Attribute, Values),
        Attributes = Attributes0.put(Attribute, Values)
    ;   ldap_ber_free(Ber, false),
        Attributes = _{}
    ).

ldap_simple_auth(URI, Who, Passwd) :-
    setup_call_cleanup(
        (ldap_initialize(LDAP, URI), ldap_set_option(LDAP, ldap_opt_protocol_version, 3)),
        ldap_simple_bind_s(LDAP, Who, Passwd),
        ldap_unbind(LDAP)
    ).