:- module(ldap4pl_util, [
    ldap_parse_search_result/3,
    ldap_simple_auth/3,
    ldap_add_s2/3,
    ldap_modify_s2/3
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

ldap_add_s2(LDAP, DN, Entry) :-
    dict_pairs(Entry, _, Pairs),
    build_ldapmod_add_list(Pairs, List),
    ldap_add_s(LDAP, DN, List).

build_ldapmod_add_list([], []) :- !.
build_ldapmod_add_list([Attribute-V|T], List) :-
    build_ldapmod_add_list(T, List0),
    (   is_list(V)
    ->  Values = V
    ;   Values = [V]
    ),
    LDAPMod = ldapmod(mod_op([ldap_mod_add]), mod_type(Attribute), mod_values(Values)),
    List = [LDAPMod|List0].

ldap_modify_s2(LDAP, DN, Operations) :-
    build_ldapmod_modify_list(Operations, List),
    ldap_modify_s(LDAP, DN, List).

build_ldapmod_modify_list([], []) :- !.
build_ldapmod_modify_list([Op-Attribute:V|T], List) :- !,
    build_ldapmod_modify_list(T, List0),
    (   is_list(V)
    ->  Values = V
    ;   Values = [V]
    ),
    atom_concat(ldap_mod_, Op, Operation),
    LDAPMod = ldapmod(mod_op([Operation]), mod_type(Attribute), mod_values(Values)),
    List = [LDAPMod|List0].
build_ldapmod_modify_list([delete-Attribute|T], List) :- !,
    build_ldapmod_modify_list(T, List0),
    LDAPMod = ldapmod(mod_op([ldap_mod_delete]), mod_type(Attribute)),
    List = [LDAPMod|List0].