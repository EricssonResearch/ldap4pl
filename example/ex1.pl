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
        MsgID),
    ldap_result(LDAP, MsgID, true, Result),
    debug(ex1, 'Result ~w', [Result]),
    ldap_parse_result(LDAP, Result, ErrorCode, MatchedDN, ErrorMsg, Referrals, SCtrls, false),
    debug(ex1, 'ErrorCode ~w', [ErrorCode]),
    debug(ex1, 'MatchedDN ~w', [MatchedDN]),
    debug(ex1, 'ErrorMsg ~w', [ErrorMsg]),
    debug(ex1, 'Referrals ~w', [Referrals]),
    debug(ex1, 'SCtrls ~w', [SCtrls]),
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

compare :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    ldap_compare_ext(LDAP, DN, description, berval(bv_len(18), bv_val('LDAP administrator')), [], [], MsgID),
%    ldap_abandon_ext(LDAP, MsgID, [], []),
    debug(ex1, 'MsgID ~w', [MsgID]),
    ldap_result(LDAP, MsgID, true, timeval(tv_sec(2), tv_usec(0)), Result),
    ldap_parse_result(LDAP, Result, ErrorCode, _, _, _, _, true),
    debug(ex1, 'Result ~w', [ErrorCode]),
    ldap_unbind(LDAP).

add :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    DN1 = 'cn=test,ou=groups,dc=cf,dc=ericsson,dc=net',
    ldap_add_s(LDAP, DN1, [
        ldapmod(mod_op([ldap_mod_add]), mod_type(objectClass), mod_values([posixGroup, top])),
        ldapmod(mod_op([ldap_mod_add]), mod_type(cn), mod_values([test])),
        ldapmod(mod_op([ldap_mod_add]), mod_type(gidNumber), mod_values(['20000'])),
        ldapmod(mod_op([ldap_mod_add]), mod_type(description), mod_values([hello]))
    ]),
    ldap_unbind(LDAP).

add_bval :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    DN1 = 'cn=test,ou=groups,dc=cf,dc=ericsson,dc=net',
    ldap_add_s(LDAP, DN1, [
        ldapmod(mod_op([ldap_mod_add, ldap_mod_bvalues]), mod_type(objectClass),
            mod_bvalues([berval(bv_len(10), bv_val(posixGroup)), berval(bv_len(3), bv_val(top))])),
        ldapmod(mod_op([ldap_mod_add, ldap_mod_bvalues]), mod_type(cn),
            mod_bvalues([berval(bv_len(4), bv_val(test))])),
        ldapmod(mod_op([ldap_mod_add, ldap_mod_bvalues]), mod_type(gidNumber),
            mod_bvalues([berval(bv_len(5), bv_val('20000'))])),
        ldapmod(mod_op([ldap_mod_add, ldap_mod_bvalues]), mod_type(description),
            mod_bvalues([berval(bv_len(4), bv_val(test))]))
    ]),
    ldap_unbind(LDAP).

modify :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    ldap_modify_s(LDAP, DN, [
        ldapmod(mod_op([ldap_mod_add]), mod_type(street), mod_values([hello])),
        ldapmod(mod_op([ldap_mod_delete]), mod_type(street), mod_values([hello])),
        ldapmod(mod_op([ldap_mod_replace]), mod_type(street), mod_values([goodbye, world])),
        ldapmod(mod_op([ldap_mod_delete]), mod_type(street))
    ]),
    ldap_unbind(LDAP).

delete :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    DN1 = 'cn=test,ou=groups,dc=cf,dc=ericsson,dc=net',
    ldap_delete_s(LDAP, DN1),
    ldap_unbind(LDAP).

rename :-
    ldap_initialize(LDAP, 'ldap://172.16.0.223:389'),
    debug(ex1, 'LDAP ~w', [LDAP]),
    ldap_set_option(LDAP, ldap_opt_protocol_version, 3),
    DN = 'cn=admin,dc=cf,dc=ericsson,dc=net',
    ldap_simple_bind_s(LDAP, DN, s3cret),
    DN1 = 'cn=test,ou=groups,dc=cf,dc=ericsson,dc=net',
    ignore(ldap_modrdn_s(LDAP, DN1, test_rdn)),
    ldap_get_ld_errno(ErrorCode),
    debug(ex1, 'ErrorCode ~w', [ErrorCode]),
    ldap_unbind(LDAP).
