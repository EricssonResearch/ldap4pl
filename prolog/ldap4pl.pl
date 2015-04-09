:- module(ldap4pl, [
    ldap_initialize/2,                % -LDAP, +URI
    ldap_unbind/1,                    % +LDAP
    ldap_unbind_s/1,                  % +LDAP
    ldap_unbind_ext/3,                % +LDAP, +SCtrls, +CCtrls
    ldap_unbind_ext_s/3,              % +LDAP, +SCtrls, +CCtrls
    ldap_bind/5,                      % +LDAP, +Who, +Cred, +Method, -MsgID
    ldap_bind_s/4,                    % +LDAP, +Who, +Cred, +Method
    ldap_simple_bind/4,               % +LDAP, +Who, +Passwd, -MsgID
    ldap_simple_bind_s/3,             % +LDAP, +Who, +Passwd
    ldap_sasl_bind/7,                 % +LDAP, +DN, +Mechanism, +Cred, +SCtrls, +CCtrls, -MsgID
    ldap_sasl_bind_s/7,               % +LDAP, +DN, +Mechanism, +Cred, +SCtrls, +CCtrls, -ServerCred
    ldap_parse_sasl_bind_result/4,    % +LDAP, +Result, -ServerCred, +FreeIt
    ldap_set_option/3,                % +LDAP, +Option, +Value
    ldap_get_option/3,                % +LDAP, +Option, -Value
    ldap_result/4,                    % +LDAP, +MsgID, +All, -Result
    ldap_result/5,                    % +LDAP, +MsgID, +All, +Timeout, -Result
    ldap_msgfree/1,                   % +Msg
    ldap_msgtype/2,                   % +Msg, ?Type
    ldap_msgid/2,                     % +Msg, ?ID
    ldap_search_ext/7,                % +LDAP, +Query, +SCtrls, +CCtrls, +Timeout, +SizeLimit, -MsgID
    ldap_search_ext/6,                % +LDAP, +Query, +SCtrls, +CCtrls, +SizeLimit, -MsgID
    ldap_search_ext_s/7,              % +LDAP, +Query, +SCtrls, +CCtrls, +Timeout, +SizeLimit, -Result
    ldap_search_ext_s/6,              % +LDAP, +Query, +SCtrls, +CCtrls, +SizeLimit, -Result
    ldap_search/3,                    % +LDAP, +Query, -MsgID
    ldap_search_s/3,                  % +LDAP, +Query, -Result
    ldap_search_st/4,                 % +LDAP, +Query, +Timeout, -Result
    ldap_count_entries/3,             % +LDAP, +Result, ?Count
    ldap_first_entry/3,               % +LDAP, +Result, -Entry
    ldap_next_entry/3,                % +LDAP, +Entry, -NextEntry
    ldap_first_attribute/4,           % +LDAP, +Entry, -Attribute, -Ber
    ldap_next_attribute/4,            % +LDAP, +Entry, -Attribute, +Ber
    ldap_ber_free/2,                  % +Ber, +FreeBuf
    ldap_get_values/4,                % +LDAP, +Entry, +Attribute, -Values
    ldap_get_dn/3,                    % +LDAP, +Entry, ?DN
    ldap_parse_result/8,              % +LDAP, +Result, ?ErrorCode, -MatchedDN, -ErrorMsg, -Referrals, -ServerCred, +FreeIt
    ldap_err2string/2,                % +ErrorCode, -ErrorString
    ldap_compare_ext/7,               % +LDAP, +DN, +Attribute, +BerVal, +SCtrls, +CCtrls, -MsgID
    ldap_compare_ext_s/7,             % +LDAP, +DN, +Attribute, +BerVal, +SCtrls, +CCtrls, -Result
    ldap_compare/5,                   % +LDAP, +DN, +Attribute, +Value, -MsgID
    ldap_compare_s/5,                 % +LDAP, +DN, +Attribute, +Value, -Result
    ldap_abandon_ext/4,               % +LDAP, +MsgID, +SCtrls, +CCtrls
    ldap_abandon/2,                   % +LDAP, +MsgID
    ldap_add_ext/6,                   % +LDAP, +DN, +Attributes, +SCtrls, +CCtrls, -MsgID
    ldap_add_ext_s/5,                 % +LDAP, +DN, +Attributes, +SCtrls, +CCtrls
    ldap_add/4,                       % +LDAP, +DN, +Attributes, -MsgID
    ldap_add_s/3,                     % +LDAP, +DN, +Attributes
    ldap_modify_ext/6,                % +LDAP, +DN, +Attributes, +SCtrls, +CCtrls, -MsgID
    ldap_modify_ext_s/5,              % +LDAP, +DN, +Attributes, +SCtrls, +CCtrls
    ldap_modify/4,                    % +LDAP, +DN, +Attributes, -MsgID
    ldap_modify_s/3,                  % +LDAP, +DN, +Attributes
    ldap_delete_ext/5,                % +LDAP, +DN, +SCtrls, +CCtrls, -MsgID
    ldap_delete_ext_s/4,              % +LDAP, +DN, +SCtrls, +CCtrls
    ldap_delete/3,                    % +LDAP, +DN, -MsgID
    ldap_delete_s/2,                  % +LDAP, +DN
    ldap_modrdn/4,                    % +LDAP, +DN, +NewRDN, -MsgID
    ldap_modrdn_s/3,                  % +LDAP, +DN, +NewRDN
    ldap_modrdn2/5,                   % +LDAP, +DN, +NewRDN, +DeleteOldRDN, -MsgID
    ldap_modrdn2_s/4,                 % +LDAP, +DN, +NewRDN, +DeleteOldRDN
    ldap_rename/8,                    % +LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN, +SCtrls, +CCtrls, -MsgID
    ldap_rename_s/7,                  % +LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN, +SCtrls, +CCtrls
    ldap_get_ld_errno/1,              % ?ErrorCode
    ldap_extended_operation/6,        % +LDAP, +RequestOID, +RequestData, +SCtrls, +CCtrls, -MsgID
    ldap_extended_operation_s/7,      % +LDAP, +RequestOID, +RequestData, +SCtrls, +CCtrls, -RetOID, -RetData
    ldap_is_ldap_url/1,               % +URL
    ldap_url_parse/2                  % +URL, -Desc
]).

/** <module> Prolog bindings to OpenLDAP

This module provides bindings to [OpenLDAP](http://www.openldap.org) API.
Most APIs have been implemented and the names are aligned with OpenLDAP API,
so for detailed description please check [here](http://www.openldap.org/software/man.cgi).

@author Hongxin Liang
@license TBD
@see http://www.openldap.org/
*/

:- use_foreign_library(foreign(ldap4pl)).

%% ldap_initialize(-LDAP, +URI) is semidet.
%
% Initialize the LDAP library and
% open a connection to an LDAP server.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_initialize(LDAP, URI) :-
    ldap4pl_initialize(LDAP, URI).

%% ldap_unbind(+LDAP) is semidet.
%
% Unbind from the directory, terminate
% the current association, and free the resources
% contained in the ld structure.
%
% By nature there is no asynchrous version of unbind
% and the underlying implementation is the same as
% ldap_unbind_s/1.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_unbind(LDAP) :-
    ldap4pl_unbind(LDAP).

%% ldap_unbind_s(+LDAP) is semidet.
%
% Unbind from the directory, terminate
% the current association, and free the resources
% contained in the ld structure.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_unbind_s(LDAP) :-
    ldap4pl_unbind(LDAP).

%% ldap_unbind_ext(+LDAP, +SCtrls, +CCtrls) is semidet.
%
% Unbind from the directory, terminate
% the current association, and free the resources
% contained in the ld structure.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% By nature there is no asynchrous version of unbind
% and the underlying implementation is the same as
% ldap_unbind_ext_s/3.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_unbind_ext(LDAP, SCtrls, CCtrls) :-
    ldap4pl_unbind_ext(LDAP, SCtrls, CCtrls).

%% ldap_unbind_ext_s(+LDAP, +SCtrls, +CCtrls) is semidet.
%
% Unbind from the directory, terminate
% the current association, and free the resources
% contained in the ld structure.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_unbind_ext_s(LDAP, SCtrls, CCtrls) :-
    ldap4pl_unbind_ext(LDAP, SCtrls, CCtrls).

%% ldap_bind(+LDAP, +Who, +Cred, +Method, -MsgID) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.

ldap_bind(LDAP, Who, Cred, Method, MsgID) :-
    ldap4pl_bind(LDAP, Who, Cred, Method, MsgID).

%% ldap_bind_s(+LDAP, +Who, +Cred, +Method) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_bind_s(LDAP, Who, Cred, Method) :-
    ldap4pl_bind_s(LDAP, Who, Cred, Method).

%% ldap_simple_bind(+LDAP, +Who, +Passwd, -MsgID) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.

ldap_simple_bind(LDAP, Who, Passwd, MsgID) :-
    ldap4pl_simple_bind(LDAP, Who, Passwd, MsgID).

%% ldap_simple_bind_s(+LDAP, +Who, +Passwd) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_simple_bind_s(LDAP, Who, Passwd) :-
    ldap4pl_simple_bind_s(LDAP, Who, Passwd).

%% ldap_sasl_bind(+LDAP, +DN, +Mechanism, +Cred, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_sasl_bind(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, MsgID) :-
    ldap4pl_sasl_bind(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, MsgID).

%% ldap_sasl_bind_s(+LDAP, +DN, +Mechanism, +Cred, +SCtrls, +CCtrls, -ServerCred) is semidet.
%
% After an association with an LDAP server is made using ldap_initialize/2, an
% LDAP  bind  operation  should  be performed before other operations are
% attempted over the connection.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% =ServerCred= is in the format of:
% ==
% berval(bv_len(...), bv_val(...))
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCred) :-
    ldap4pl_sasl_bind_s(LDAP, DN, Mechanism, Cred, SCtrls, CCtrls, ServerCred).

%% ldap_parse_sasl_bind_result(+LDAP, +Result, -ServerCred, +FreeIt) is semidet.
%
% Obtain any server credentials sent from the server.
%
% =ServerCred= is in the format of:
% ==
% berval(bv_len(...), bv_val(...))
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_parse_sasl_bind_result(LDAP, Result, ServerCred, FreeIt) :-
    ldap4pl_parse_sasl_bind_result(LDAP, Result, ServerCred, FreeIt).

%% ldap_set_option(+LDAP, +Option, +Value) is semidet.
%
% Provide access to options stored either in a LDAP handle
% or as global options, where applicable.
%
% Use ldap_get_ld_errno/1 to get last error.
%
% @tbd This API is not fully implemented yet and supported options are:
% ==
% LDAP_OPT_DEREF
% LDAP_OPT_DIAGNOSTIC_MESSAGE
% LDAP_OPT_MATCHED_DN
% LDAP_OPT_PROTOCOL_VERSION
% LDAP_OPT_REFERRAL_URLS
% LDAP_OPT_REFERRALS
% LDAP_OPT_RESTART
% LDAP_OPT_RESULT_CODE
% LDAP_OPT_SIZELIMIT
% LDAP_OPT_TIMELIMIT
% ==

ldap_set_option(LDAP, Option, Value) :-
    ldap4pl_set_option(LDAP, Option, Value).

%% ldap_get_option(+LDAP, +Option, -Value) is semidet.
%
% Provide access to options stored either in a LDAP handle
% or as global options, where applicable.
%
% Use ldap_get_ld_errno/1 to get last error.
%
% @tbd This API is not implemented yet.

ldap_get_option(LDAP, Option, Value) :-
    ldap4pl_get_option(LDAP, Option, Value).

%% ldap_result(+LDAP, +MsgID, +All, -Result) is semidet.
%% ldap_result(+LDAP, +MsgID, +All, +Timeout, -Result) is semidet.
%
% Wait for and return the result of
% an operation previously initiated by one of the LDAP asynchronous
% operation routines.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_result(LDAP, MsgID, All, Result) :-
    ldap4pl_result(LDAP, MsgID, All, _, Result).

ldap_result(LDAP, MsgID, All, Timeout, Result) :-
    ldap4pl_result(LDAP, MsgID, All, Timeout, Result).

%% ldap_msgfree(+Msg) is semidet.
%
% Free the memory allocated for result(s).

ldap_msgfree(Msg) :-
    ldap4pl_msgfree(Msg).

%% ldap_msgtype(+Msg, ?Type) is semidet.
%
% Return the type of a message.

ldap_msgtype(Msg, Type) :-
    ldap4pl_msgtype(Msg, Type).

%% ldap_msgid(+Msg, ?ID) is semidet.
%
% Return the message id of a message.

ldap_msgid(Msg, ID) :-
    ldap4pl_msgid(Msg, ID).

%% ldap_search_ext(+LDAP, +Query, +SCtrls, +CCtrls, +Timeout, +SizeLimit, -MsgID) is semidet.
%% ldap_search_ext(+LDAP, +Query, +SCtrls, +CCtrls, +SizeLimit, -MsgID) is semidet.
%
% Perform LDAP search operations.
%
% =Query= is in the format of:
% ==
% query(base(...), scope(...), filter(...), attrs([...]), attrsonly(false))
% ==
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_search_ext(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, MsgID) :-
    ldap4pl_search_ext(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, MsgID).

ldap_search_ext(LDAP, Query, SCtrls, CCtrls, SizeLimit, MsgID) :-
    ldap4pl_search_ext(LDAP, Query, SCtrls, CCtrls, _, SizeLimit, MsgID).

%% ldap_search_ext_s(+LDAP, +Query, +SCtrls, +CCtrls, +Timeout, +SizeLimit, -Result) is semidet.
%% ldap_search_ext_s(+LDAP, +Query, +SCtrls, +CCtrls, +SizeLimit, -Result) is semidet.
%
% Perform LDAP search operations.
%
% =Query= is in the format of:
% ==
% query(base(...), scope(...), filter(...), attrs([...]), attrsonly(false))
% ==
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_search_ext_s(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, Result) :-
    ldap4pl_search_ext_s(LDAP, Query, SCtrls, CCtrls, Timeout, SizeLimit, Result).

ldap_search_ext_s(LDAP, Query, SCtrls, CCtrls, SizeLimit, Result) :-
    ldap4pl_search_ext_s(LDAP, Query, SCtrls, CCtrls, _, SizeLimit, Result).

%% ldap_search(+LDAP, +Query, -MsgID) is semidet.
%
% Perform LDAP search operations.
%
% =Query= is in the format of:
% ==
% query(base(...), scope(...), filter(...), attrs([...]), attrsonly(false))
% ==

ldap_search(LDAP, Query, MsgID) :-
    ldap4pl_search(LDAP, Query, _, MsgID).

%% ldap_search_s(+LDAP, +Query, -Result) is semidet.
%% ldap_search_st(+LDAP, +Query, +Timeout, -Result) is semidet.
%
% Perform LDAP search operations.
%
% =Query= is in the format of:
% ==
% query(base(...), scope(...), filter(...), attrs([...]), attrsonly(false))
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_search_s(LDAP, Query, Result) :-
    ldap4pl_search_s(LDAP, Query, _, Result).

ldap_search_st(LDAP, Query, Timeout, Result) :-
    ldap4pl_search_s(LDAP, Query, Timeout, Result).

%% ldap_count_entries(+LDAP, +Result, ?Count) is semidet.
%
% Obtain a count of the number of entries in the search result.

ldap_count_entries(LDAP, Result, Count) :-
    ldap4pl_count_entries(LDAP, Result, Count).

%% ldap_first_entry(+LDAP, +Result, -Entry) is semidet.
%
% Retrieve the first entry in a chain of search results.

ldap_first_entry(LDAP, Result, Entry) :-
    ldap4pl_first_entry(LDAP, Result, Entry).

%% ldap_next_entry(+LDAP, +Entry, -NextEntry) is semidet.
%
% Retrieve the next entry following =Entry=.

ldap_next_entry(LDAP, Entry, NextEntry) :-
    ldap4pl_next_entry(LDAP, Entry, NextEntry).

%% ldap_first_attribute(+LDAP, +Entry, -Attribute, -Ber) is semidet.
%
% Retrieve the first attribute of the entry.
%
% =Ber= must be freed by calling ldap_ber_free/2 with second
% argument as =false=.

ldap_first_attribute(LDAP, Entry, Attribute, Ber) :-
    ldap4pl_first_attribute(LDAP, Entry, Attribute, Ber).

%% ldap_next_attribute(+LDAP, +Entry, -Atrribute, +Berval) is semidet.
%
% Retrieve the next attribute in the entry. =Ber= must have been
% unified by calling ldap_first_attribute/4 prior to this predicate.

ldap_next_attribute(LDAP, Entry, Attribute, Ber) :-
    ldap4pl_next_attribute(LDAP, Entry, Attribute, Ber).

%% ldap_ber_free(+Ber, +FreeBuf) is det.
%
% Frees a BerElement pointed to by =Ber=.

ldap_ber_free(Ber, FreeBuf) :-
    ldap4pl_ber_free(Ber, FreeBuf).

%% ldap_get_values(+LDAP, +Entry, +Attribute, -Values) is semidet.
%
% Get values of the attribute.

ldap_get_values(LDAP, Entry, Attribute, Values) :-
    ldap4pl_get_values(LDAP, Entry, Attribute, Values).

%% ldap_get_dn(+LDAP, +Entry, ?DN) is semidet.
%
% Get DN of the entry.

ldap_get_dn(LDAP, Entry, DN) :-
    ldap4pl_get_dn(LDAP, Entry, DN).

%% ldap_parse_result(+LDAP, +Result, ?ErrorCode, -MatchedDN, -ErrorMsg, -Referrals, -SCtrls, +FreeIt) is semidet.
%
% Extract information from a result message.
% =SCtrls= is an array of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_parse_result(LDAP, Result, ErrorCode, MatchedDN, ErrorMsg,
                  Referrals, SCtrls, FreeIt) :-
    ldap4pl_parse_result(LDAP, Result, ErrorCode, MatchedDN, ErrorMsg,
                         Referrals, SCtrls, FreeIt).

%% ldap_err2string(+ErrorMsg, -ErrorString) is semidet.
%
% Provides short description of the various
% codes returned by routines in this library.

ldap_err2string(ErrorCode, ErrorString) :-
    ldap4pl_err2string(ErrorCode, ErrorString).

%% ldap_compare_ext(+LDAP, +DN, +Attribute, +BerVal, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP compare operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_compare_ext(LDAP, DN, Attribute, BerVal, SCtrls, CCtrls, MsgID) :-
    ldap4pl_compare_ext(LDAP, DN, Attribute, BerVal, SCtrls, CCtrls, MsgID).

%% ldap_compare_ext_s(+LDAP, +DN, +Attribute, +BerVal, +SCtrls, +CCtrls, -Result) is semidet.
%
% Perform an LDAP compare operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_compare_ext_s(LDAP, DN, Attribute, BerVal, SCtrls, CCtrls, Result) :-
    ldap4pl_compare_ext_s(LDAP, DN, Attribute, BerVal, SCtrls, CCtrls, Result).

%% ldap_compare(+LDAP, +DN, +Attribute, +Value, -MsgID) is semidet.
%
% Perform an LDAP compare operation.

ldap_compare(LDAP, DN, Attribute, Value, MsgID) :-
    ldap4pl_compare(LDAP, DN, Attribute, Value, MsgID).

%% ldap_compare_s(+LDAP, +DN, +Attribute, +Value, -Result) is semidet.
%
% Perform an LDAP compare operation.

ldap_compare_s(LDAP, DN, Attribute, Value, Result) :-
    ldap4pl_compare_s(LDAP, DN, Attribute, Value, Result).

%% ldap_abandon_ext(+LDAP, +MsgID, +SCtrls, +CCtrls) is semidet.
%
% Send a LDAP Abandon request for an operation in progress.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_abandon_ext(LDAP, MsgID, SCtrls, CCtrls) :-
    ldap4pl_abandon_ext(LDAP, MsgID, SCtrls, CCtrls).

%% ldap_abandon(+LDAP, +MsgID) is semidet.
%
% Send a LDAP Abandon request for an operation in progress.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_abandon(LDAP, MsgID) :-
    ldap4pl_abandon_ext(LDAP, MsgID, [], []).

%% ldap_add_ext(+LDAP, +DN, +Attributes, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP add operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_add_ext(LDAP, DN, Attributes, SCtrls, CCtrls, MsgID) :-
    ldap4pl_add_ext(LDAP, DN, Attributes, SCtrls, CCtrls, MsgID).

%% ldap_add_ext_s(+LDAP, +DN, +Attributes, +SCtrls, +CCtrls) is semidet.
%
% Perform an LDAP add operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_add_ext_s(LDAP, DN, Attributes, SCtrls, CCtrls) :-
    ldap4pl_add_ext_s(LDAP, DN, Attributes, SCtrls, CCtrls).

%% ldap_add(+LDAP, +DN, +Attributes, -MsgID) is semidet.
%
% Perform an LDAP add operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==

ldap_add(LDAP, DN, Attributes, MsgID) :-
    ldap4pl_add_ext(LDAP, DN, Attributes, [], [], MsgID).

%% ldap_add_s(+LDAP, +DN, +Attributes) is semidet.
%
% Perform an LDAP add operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_add_s(LDAP, DN, Attributes) :-
    ldap4pl_add_ext_s(LDAP, DN, Attributes, [], []).

%% ldap_modify_ext(+LDAP, +DN, +Attributes, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP modify operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
% To delete an attribute completely, simply skip =mod_values=.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_modify_ext(LDAP, DN, Attributes, SCtrls, CCtrls, MsgID) :-
    ldap4pl_modify_ext(LDAP, DN, Attributes, SCtrls, CCtrls, MsgID).

%% ldap_modify_ext_s(+LDAP, +DN, +Attributes, +SCtrls, +CCtrls) is semidet.
%
% Perform an LDAP modify operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
% To delete an attribute completely, simply skip =mod_values=.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_modify_ext_s(LDAP, DN, Attributes, SCtrls, CCtrls) :-
    ldap4pl_modify_ext_s(LDAP, DN, Attributes, SCtrls, CCtrls).

%% ldap_modify(+LDAP, +DN, +Attributes, -MsgID) is semidet.
%
% Perform an LDAP modify operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
% To delete an attribute completely, simply skip =mod_values=.

ldap_modify(LDAP, DN, Attributes, MsgID) :-
    ldap4pl_modify_ext(LDAP, DN, Attributes, [], [], MsgID).

%% ldap_modify_s(+LDAP, +DN, +Attributes) is semidet.
%
% Perform an LDAP modify operation.
%
% =Attributes= is an array of terms in the format of:
% ==
% ldapmod(
%     mod_op([ldap_mod_add]),
%     mod_type(objectClass),
%     mod_values([posixGroup, top])
% )
% ==
% To delete an attribute completely, simply skip =mod_values=.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_modify_s(LDAP, DN, Attributes) :-
    ldap4pl_modify_ext_s(LDAP, DN, Attributes, [], []).

%% ldap_delete_ext(+LDAP, +DN, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP delete operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_delete_ext(LDAP, DN, SCtrls, CCtrls, MsgID) :-
    ldap4pl_delete_ext(LDAP, DN, SCtrls, CCtrls, MsgID).

%% ldap_delete_ext_s(+LDAP, +DN, +SCtrls, +CCtrls) is semidet.
%
% Perform an LDAP delete operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_delete_ext_s(LDAP, DN, SCtrls, CCtrls) :-
    ldap4pl_delete_ext_s(LDAP, DN, SCtrls, CCtrls).

%% ldap_delete(+LDAP, +DN, -MsgID) is semidet.
%
% Perform an LDAP delete operation.

ldap_delete(LDAP, DN, MsgID) :-
    ldap4pl_delete_ext(LDAP, DN, [], [], MsgID).

%% ldap_delete_s(+LDAP, +DN) is semidet.
%
% Perform an LDAP delete operation.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_delete_s(LDAP, DN) :-
    ldap4pl_delete_ext_s(LDAP, DN, [], []).

%% ldap_modrdn(+LDAP, +DN, +NewRDN, -MsgID) is semidet.
%
% Perform an LDAP rename operation.

ldap_modrdn(LDAP, DN, NewRDN, MsgID) :-
    ldap4pl_modrdn(LDAP, DN, NewRDN, MsgID).

%% ldap_modrdn_s(+LDAP, +DN, +NewRDN) is semidet.
%
% Perform an LDAP rename operation.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_modrdn_s(LDAP, DN, NewRDN) :-
    ldap4pl_modrdn_s(LDAP, DN, NewRDN).

%% ldap_modrdn2(+LDAP, +DN, +NewRDN, +DeleteOldRDN, -MsgID) is semidet.
%
% Perform an LDAP rename operation.

ldap_modrdn2(LDAP, DN, NewRDN, DeleteOldRDN, MsgID) :-
    ldap4pl_modrdn2(LDAP, DN, NewRDN, DeleteOldRDN, MsgID).

%% ldap_modrdn2_s(+LDAP, +DN, +NewRDN, +DeleteOldRDN) is semidet.
%
% Perform an LDAP rename operation.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_modrdn2_s(LDAP, DN, NewRDN, DeleteOldRDN) :-
    ldap4pl_modrdn2_s(LDAP, DN, NewRDN, DeleteOldRDN).

%% ldap_rename(+LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP rename operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_rename(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, SCtrls, CCtrls, MsgID) :-
    ldap4pl_rename(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, SCtrls, CCtrls, MsgID).

%% ldap_rename_s(+LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN, +SCtrls, +CCtrls) is semidet.
%
% Perform an LDAP rename operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_rename_s(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, SCtrls, CCtrls) :-
    ldap4pl_rename_s(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, SCtrls, CCtrls).

%% ldap_rename2(+LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN, -MsgID) is semidet.
%
% Perform an LDAP rename operation.

ldap_rename2(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, MsgID) :-
    ldap4pl_rename(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, [], [], MsgID).

%% ldap_rename2_s(+LDAP, +DN, +NewRDN, +NewSuperior, +DeleteOldRDN) is semidet.
%
% Perform an LDAP rename operation.
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_rename2_s(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN) :-
    ldap4pl_rename_s(LDAP, DN, NewRDN, NewSuperior, DeleteOldRDN, [], []).

%% ldap_get_ld_errno(?ErrorCode) is semidet.
%
% Get last LDAP operation error.

ldap_get_ld_errno(ErrorCode) :-
    ldap4pl_get_ld_errno(ErrorCode).

%% ldap_extended_operation(+LDAP, +RequestOID, +RequestData, +SCtrls, +CCtrls, -MsgID) is semidet.
%
% Perform an LDAP extended operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==

ldap_extended_operation(LDAP, RequestOID, RequestData, SCtrls, CCtrls, MsgID) :-
    ldap4pl_extended_operation(LDAP, RequestOID, RequestData, SCtrls, CCtrls, MsgID).

%% ldap_extended_operation_s(+LDAP, +RequestOID, +RequestData, +SCtrls, +CCtrls, -RetOID, -RetData) is semidet.
%
% Perform an LDAP extended operation.
%
% =SCtrls= and =CCtrls= are arrays of terms in the format
% of:
% ==
% ldapcontrol(
%     ldctl_oid(...),
%     ldctl_value(bv_len(...), bv_val(...)),
%     ldctl_iscritical(true)
% )
% ==
%
% Use ldap_get_ld_errno/1 to get last error.

ldap_extended_operation_s(LDAP, RequestOID, RequestData, SCtrls, CCtrls, RetOID, RetData) :-
    ldap4pl_extended_operation_s(LDAP, RequestOID, RequestData, SCtrls, CCtrls, RetOID, RetData).

%% ldap_is_ldap_url(+URL) is semidet.
%
% Check if =URL= is a valid LDAP URL.

ldap_is_ldap_url(URL) :-
    ldap4pl_is_ldap_url(URL).

%% ldap_url_parse(+URL, -Desc) is semidet.
%
% Breaks down an LDAP URL passed in url into its component pieces.
%
% =Desc= is in the format of:
% ==
% lud(
%     lud_scheme(ldap),
%     lud_host(''),
%     lud_port(389),
%     lud_dn(''),
%     lud_attrs([]),
%     lud_scope(0),
%     lud_filter(''),
%     lud_exts([]),
%     lud_crit_exts(0)
% )
% ==

ldap_url_parse(URL, Desc) :-
    ldap4pl_url_parse(URL, Desc).