:- module(ex1, []).

:- use_module(library(ldap4pl)).

:- debug(ex1).

search :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    ldap_simple_bind_s(LDAP, 'cn=admin,dc=cf,dc=ericsson,dc=net', s3cret),
    ldap_search(LDAP,
        query(
            base('dc=cf,dc=ericsson,dc=net'),
            scope(ldap_scope_onelevel),
            filter('(objectClass=*)'),
%            attrs([objectClass, sambaDomainName]),
            attrsonly(false)
        ),
        MsgId),
    ldap_result(LDAP, MsgId, true, Result),
    debug(ex1, 'Result ~w', [Result]),
    ldap_count_entries(LDAP, Result, Count),
    debug(ex1, 'Count ~w', [Count]),
    iterate_entries(LDAP, Result),
    ldap_msgfree(Result),
    ldap_unbind(LDAP).

iterate_entries(LDAP, Result) :-
    (   ldap_first_entry(LDAP, Result, Entry)
    ->  debug(ex1, 'Entry ~w', [Entry]),
        ldap_get_dn(LDAP, Entry, DN),
        debug(ex1, 'DN ~w', [DN]),
        iterate_attributes(LDAP, Entry),
        iterate_entries0(LDAP, Entry)
    ;   true
    ).

iterate_entries0(LDAP, Entry) :-
    (   ldap_next_entry(LDAP, Entry, NextEntry)
    ->  debug(ex1, 'Entry ~w', [NextEntry]),
        ldap_get_dn(LDAP, Entry, DN),
        debug(ex1, 'DN ~w', [DN]),
        iterate_attributes(LDAP, NextEntry),
        iterate_entries0(LDAP, NextEntry)
    ;   true
    ).

iterate_attributes(LDAP, Entry) :-
    (   ldap_first_attribute(LDAP, Entry, Attribute, Ber)
    ->  debug(ex1, 'Attribute ~w', [Attribute]),
        ldap_get_values(LDAP, Entry, Attribute, Values),
        debug(ex1, 'Values ~w', [Values]),
        iterate_attributes0(LDAP, Entry, Ber)
    ;   true
    ).

iterate_attributes0(LDAP, Entry, Ber) :-
    (   ldap_next_attribute(LDAP, Entry, Attribute, Ber)
    ->  debug(ex1, 'Attribute ~w', [Attribute]),
        ldap_get_values(LDAP, Entry, Attribute, Values),
        debug(ex1, 'Values ~w', [Values]),
        iterate_attributes0(LDAP, Entry, Ber)
    ;   ldap_ber_free(Ber, false)
    ).