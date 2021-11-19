/* Copyright 2015 Ericsson

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sys/time.h>
#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <ldap.h>

#ifdef O_DEBUG
#define DEBUG(g) g
#else
#define DEBUG(g)
#endif

typedef struct timeval TimeVal;

static atom_t ATOM_timeval;
static atom_t ATOM_tv_sec;
static atom_t ATOM_tv_usec;

static atom_t ATOM_ldapcontrol;
static atom_t ATOM_ldctl_oid;
static atom_t ATOM_ldctl_value;
static atom_t ATOM_bv_len;
static atom_t ATOM_bv_val;
static atom_t ATOM_ldctl_iscritical;

static atom_t ATOM_berval;

static atom_t ATOM_ldap_auth_none;
static atom_t ATOM_ldap_auth_simple;
static atom_t ATOM_ldap_auth_sasl;
static atom_t ATOM_ldap_auth_krbv4;
static atom_t ATOM_ldap_auth_krbv41;
static atom_t ATOM_ldap_auth_krbv42;

static atom_t ATOM_ldap_opt_protocol_version;
static atom_t ATOM_ldap_opt_deref;
static atom_t ATOM_ldap_opt_diagnostic_message;
static atom_t ATOM_ldap_opt_matched_dn;
static atom_t ATOM_ldap_opt_referral_urls;
static atom_t ATOM_ldap_opt_referrals;
static atom_t ATOM_ldap_opt_restart;
static atom_t ATOM_ldap_opt_result_code;
static atom_t ATOM_ldap_opt_sizelimit;
static atom_t ATOM_ldap_opt_timelimit;

static atom_t ATOM_ldap_deref_never;
static atom_t ATOM_ldap_deref_searching;
static atom_t ATOM_ldap_deref_finding;
static atom_t ATOM_ldap_deref_always;
static atom_t ATOM_ldap_opt_off;
static atom_t ATOM_ldap_opt_on;

static atom_t ATOM_ldap_res_bind;
static atom_t ATOM_ldap_res_search_entry;
static atom_t ATOM_ldap_res_search_reference;
static atom_t ATOM_ldap_res_search_result;
static atom_t ATOM_ldap_res_modify;
static atom_t ATOM_ldap_res_add;
static atom_t ATOM_ldap_res_delete;
static atom_t ATOM_ldap_res_moddn;
static atom_t ATOM_ldap_res_compare;
static atom_t ATOM_ldap_res_extended;
static atom_t ATOM_ldap_res_intermediate;

static atom_t ATOM_query;
static atom_t ATOM_base;
static atom_t ATOM_scope;
static atom_t ATOM_filter;
static atom_t ATOM_attrs;
static atom_t ATOM_attrsonly;
static atom_t ATOM_ldap_scope_base;
static atom_t ATOM_ldap_scope_onelevel;
static atom_t ATOM_ldap_scope_subtree;
static atom_t ATOM_ldap_scope_children;

static atom_t ATOM_ldap_success;
static atom_t ATOM_ldap_operations_error;
static atom_t ATOM_ldap_protocol_error;
static atom_t ATOM_ldap_timelimit_exceeded;
static atom_t ATOM_ldap_sizelimit_exceeded;
static atom_t ATOM_ldap_compare_false;
static atom_t ATOM_ldap_compare_true;
static atom_t ATOM_ldap_strong_auth_not_supported;
static atom_t ATOM_ldap_strong_auth_required;
static atom_t ATOM_ldap_partial_results;
static atom_t ATOM_ldap_no_such_attribute;
static atom_t ATOM_ldap_undefined_type;
static atom_t ATOM_ldap_inappropriate_matching;
static atom_t ATOM_ldap_constraint_violation;
static atom_t ATOM_ldap_type_or_value_exists;
static atom_t ATOM_ldap_invalid_syntax;
static atom_t ATOM_ldap_no_such_object;
static atom_t ATOM_ldap_alias_problem;
static atom_t ATOM_ldap_invalid_dn_syntax;
static atom_t ATOM_ldap_is_leaf;
static atom_t ATOM_ldap_alias_deref_problem;
static atom_t ATOM_ldap_inappropriate_auth;
static atom_t ATOM_ldap_invalid_credentials;
static atom_t ATOM_ldap_insufficient_access;
static atom_t ATOM_ldap_busy;
static atom_t ATOM_ldap_unavailable;
static atom_t ATOM_ldap_unwilling_to_perform;
static atom_t ATOM_ldap_loop_detect;
static atom_t ATOM_ldap_naming_violation;
static atom_t ATOM_ldap_object_class_violation;
static atom_t ATOM_ldap_not_allowed_on_nonleaf;
static atom_t ATOM_ldap_not_allowed_on_rdn;
static atom_t ATOM_ldap_already_exists;
static atom_t ATOM_ldap_no_object_class_mods;
static atom_t ATOM_ldap_other;

static atom_t ATOM_ldapmod;
static atom_t ATOM_mod_op;
static atom_t ATOM_mod_type;
static atom_t ATOM_mod_bvalues;
static atom_t ATOM_mod_values;
static atom_t ATOM_ldap_mod_op;
static atom_t ATOM_ldap_mod_add;
static atom_t ATOM_ldap_mod_delete;
static atom_t ATOM_ldap_mod_replace;
static atom_t ATOM_ldap_mod_bvalues;

static atom_t ATOM_lud;
static atom_t ATOM_lud_scheme;
static atom_t ATOM_lud_host;
static atom_t ATOM_lud_port;
static atom_t ATOM_lud_dn;
static atom_t ATOM_lud_attrs;
static atom_t ATOM_lud_scope;
static atom_t ATOM_lud_filter;
static atom_t ATOM_lud_exts;
static atom_t ATOM_lud_crit_exts;

static functor_t FUNCTOR_berval;
static functor_t FUNCTOR_bv_len;
static functor_t FUNCTOR_bv_val;

static functor_t FUNCTOR_ldapcontrol;
static functor_t FUNCTOR_ldctl_oid;
static functor_t FUNCTOR_ldctl_value;
static functor_t FUNCTOR_ldctl_iscritical;

static functor_t FUNCTOR_lud;
static functor_t FUNCTOR_lud_scheme;
static functor_t FUNCTOR_lud_host;
static functor_t FUNCTOR_lud_port;
static functor_t FUNCTOR_lud_dn;
static functor_t FUNCTOR_lud_attrs;
static functor_t FUNCTOR_lud_scope;
static functor_t FUNCTOR_lud_filter;
static functor_t FUNCTOR_lud_exts;
static functor_t FUNCTOR_lud_crit_exts;

static __thread int ld_errno;

int get_list_size(term_t list, int* size) {
    int _size = 0;
    *size = _size;
    term_t tail = PL_copy_term_ref(list);
    term_t head = PL_new_term_ref();
    while (PL_get_list(tail, head, tail)) {
        ++_size;
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    *size = _size;
    PL_succeed;
}

int map_option(atom_t option, int* option_int) {
    int result = TRUE;
    if (option == ATOM_ldap_opt_deref) {
        *option_int = LDAP_OPT_DEREF;
    } else if (option == ATOM_ldap_opt_diagnostic_message) {
        *option_int = LDAP_OPT_DIAGNOSTIC_MESSAGE;
    } else if (option == ATOM_ldap_opt_matched_dn) {
        *option_int = LDAP_OPT_MATCHED_DN;
    } else if (option == ATOM_ldap_opt_referral_urls) {
        *option_int = LDAP_OPT_REFERRAL_URLS;
    } else if (option == ATOM_ldap_opt_referrals) {
        *option_int = LDAP_OPT_REFERRALS;
    } else if (option == ATOM_ldap_opt_protocol_version) {
        *option_int = LDAP_OPT_PROTOCOL_VERSION;
    } else if (option == ATOM_ldap_opt_restart) {
        *option_int = LDAP_OPT_RESTART;
    } else if (option == ATOM_ldap_opt_result_code) {
        *option_int = LDAP_OPT_RESULT_CODE;
    } else if (option == ATOM_ldap_opt_sizelimit) {
        *option_int = LDAP_OPT_SIZELIMIT;
    } else if (option == ATOM_ldap_opt_timelimit) {
        *option_int = LDAP_OPT_TIMELIMIT;
    } else {
        result = FALSE;
    }
    return result;
}

int map_auth_method(atom_t method, int* method_int) {
    int result = TRUE;
    if (method == ATOM_ldap_auth_none) {
        *method_int = LDAP_AUTH_NONE;
    } else if (method == ATOM_ldap_auth_simple) {
        *method_int = LDAP_AUTH_SIMPLE;
    } else if (method == ATOM_ldap_auth_sasl) {
        *method_int = LDAP_AUTH_SASL;
    } else if (method == ATOM_ldap_auth_krbv4) {
        *method_int = LDAP_AUTH_KRBV4;
    } else if (method == ATOM_ldap_auth_krbv41) {
        *method_int = LDAP_AUTH_KRBV41;
    } else if (method == ATOM_ldap_auth_krbv42) {
        *method_int = LDAP_AUTH_KRBV42;
    } else {
        result = FALSE;
    }
    return result;
}

int map_msg_type(int type, term_t type_t) {
    switch (type) {
    case LDAP_RES_BIND:
        return PL_unify_atom(type_t, ATOM_ldap_res_bind);
    case LDAP_RES_SEARCH_ENTRY:
        return PL_unify_atom(type_t, ATOM_ldap_res_search_entry);
    case LDAP_RES_SEARCH_REFERENCE:
        return PL_unify_atom(type_t, ATOM_ldap_res_search_reference);
    case LDAP_RES_SEARCH_RESULT:
        return PL_unify_atom(type_t, ATOM_ldap_res_search_result);
    case LDAP_RES_MODIFY:
        return PL_unify_atom(type_t, ATOM_ldap_res_modify);
    case LDAP_RES_ADD:
        return PL_unify_atom(type_t, ATOM_ldap_res_add);
    case LDAP_RES_DELETE:
        return PL_unify_atom(type_t, ATOM_ldap_res_delete);
    case LDAP_RES_MODDN:
        return PL_unify_atom(type_t, ATOM_ldap_res_moddn);
    case LDAP_RES_COMPARE:
        return PL_unify_atom(type_t, ATOM_ldap_res_compare);
    case LDAP_RES_EXTENDED:
        return PL_unify_atom(type_t, ATOM_ldap_res_extended);
    case LDAP_RES_INTERMEDIATE:
        return PL_unify_atom(type_t, ATOM_ldap_res_intermediate);
    default:
        PL_fail;
    }
}

int map_error_code(int errcode, term_t errcode_t) {
    switch (errcode) {
    case LDAP_SUCCESS:
        return PL_unify_atom(errcode_t, ATOM_ldap_success);
    case LDAP_OPERATIONS_ERROR:
        return PL_unify_atom(errcode_t, ATOM_ldap_operations_error);
    case LDAP_PROTOCOL_ERROR:
        return PL_unify_atom(errcode_t, ATOM_ldap_protocol_error);
    case LDAP_TIMELIMIT_EXCEEDED:
        return PL_unify_atom(errcode_t, ATOM_ldap_timelimit_exceeded);
    case LDAP_SIZELIMIT_EXCEEDED:
        return PL_unify_atom(errcode_t, ATOM_ldap_sizelimit_exceeded);
    case LDAP_COMPARE_FALSE:
        return PL_unify_atom(errcode_t, ATOM_ldap_compare_false);
    case LDAP_COMPARE_TRUE:
        return PL_unify_atom(errcode_t, ATOM_ldap_compare_true);
    case LDAP_STRONG_AUTH_NOT_SUPPORTED:
        return PL_unify_atom(errcode_t, ATOM_ldap_strong_auth_not_supported);
    case LDAP_STRONG_AUTH_REQUIRED:
        return PL_unify_atom(errcode_t, ATOM_ldap_strong_auth_required);
    case LDAP_PARTIAL_RESULTS:
        return PL_unify_atom(errcode_t, ATOM_ldap_partial_results);
    case LDAP_NO_SUCH_ATTRIBUTE:
        return PL_unify_atom(errcode_t, ATOM_ldap_no_such_attribute);
    case LDAP_UNDEFINED_TYPE:
        return PL_unify_atom(errcode_t, ATOM_ldap_undefined_type);
    case LDAP_INAPPROPRIATE_MATCHING:
        return PL_unify_atom(errcode_t, ATOM_ldap_inappropriate_matching);
    case LDAP_CONSTRAINT_VIOLATION:
        return PL_unify_atom(errcode_t, ATOM_ldap_constraint_violation);
    case LDAP_TYPE_OR_VALUE_EXISTS:
        return PL_unify_atom(errcode_t, ATOM_ldap_type_or_value_exists);
    case LDAP_INVALID_SYNTAX:
        return PL_unify_atom(errcode_t, ATOM_ldap_invalid_syntax);
    case LDAP_NO_SUCH_OBJECT:
        return PL_unify_atom(errcode_t, ATOM_ldap_no_such_object);
    case LDAP_ALIAS_PROBLEM:
        return PL_unify_atom(errcode_t, ATOM_ldap_alias_problem);
    case LDAP_INVALID_DN_SYNTAX:
        return PL_unify_atom(errcode_t, ATOM_ldap_invalid_dn_syntax);
    case LDAP_IS_LEAF:
        return PL_unify_atom(errcode_t, ATOM_ldap_is_leaf);
    case LDAP_ALIAS_DEREF_PROBLEM:
        return PL_unify_atom(errcode_t, ATOM_ldap_alias_deref_problem);
    case LDAP_INAPPROPRIATE_AUTH:
        return PL_unify_atom(errcode_t, ATOM_ldap_inappropriate_auth);
    case LDAP_INVALID_CREDENTIALS:
        return PL_unify_atom(errcode_t, ATOM_ldap_invalid_credentials);
    case LDAP_INSUFFICIENT_ACCESS:
        return PL_unify_atom(errcode_t, ATOM_ldap_insufficient_access);
    case LDAP_BUSY:
        return PL_unify_atom(errcode_t, ATOM_ldap_busy);
    case LDAP_UNAVAILABLE:
        return PL_unify_atom(errcode_t, ATOM_ldap_unavailable);
    case LDAP_UNWILLING_TO_PERFORM:
        return PL_unify_atom(errcode_t, ATOM_ldap_unwilling_to_perform);
    case LDAP_LOOP_DETECT:
        return PL_unify_atom(errcode_t, ATOM_ldap_loop_detect);
    case LDAP_NAMING_VIOLATION:
        return PL_unify_atom(errcode_t, ATOM_ldap_naming_violation);
    case LDAP_OBJECT_CLASS_VIOLATION:
        return PL_unify_atom(errcode_t, ATOM_ldap_object_class_violation);
    case LDAP_NOT_ALLOWED_ON_NONLEAF:
        return PL_unify_atom(errcode_t, ATOM_ldap_not_allowed_on_nonleaf);
    case LDAP_NOT_ALLOWED_ON_RDN:
        return PL_unify_atom(errcode_t, ATOM_ldap_not_allowed_on_rdn);
    case LDAP_ALREADY_EXISTS:
        return PL_unify_atom(errcode_t, ATOM_ldap_already_exists);
    case LDAP_NO_OBJECT_CLASS_MODS:
        return PL_unify_atom(errcode_t, ATOM_ldap_no_object_class_mods);
    case LDAP_OTHER:
        return PL_unify_atom(errcode_t, ATOM_ldap_other);
    default:
        PL_fail;
    }
}

int map_error_code_atom(atom_t errcode, int* errcode_int) {
    int result = TRUE;
    if (errcode == ATOM_ldap_success) {
        *errcode_int = LDAP_SUCCESS;
    } else if (errcode == ATOM_ldap_operations_error) {
        *errcode_int = LDAP_OPERATIONS_ERROR;
    } else if (errcode == ATOM_ldap_protocol_error) {
        *errcode_int = LDAP_PROTOCOL_ERROR;
    } else if (errcode == ATOM_ldap_timelimit_exceeded) {
        *errcode_int = LDAP_TIMELIMIT_EXCEEDED;
    } else if (errcode == ATOM_ldap_sizelimit_exceeded) {
        *errcode_int = LDAP_SIZELIMIT_EXCEEDED;
    } else if (errcode == ATOM_ldap_compare_false) {
        *errcode_int = LDAP_COMPARE_FALSE;
    } else if (errcode == ATOM_ldap_compare_true) {
        *errcode_int = LDAP_COMPARE_TRUE;
    } else if (errcode == ATOM_ldap_strong_auth_not_supported) {
        *errcode_int = LDAP_STRONG_AUTH_NOT_SUPPORTED;
    } else if (errcode == ATOM_ldap_strong_auth_required) {
        *errcode_int = LDAP_STRONG_AUTH_REQUIRED;
    } else if (errcode == ATOM_ldap_partial_results) {
        *errcode_int = LDAP_PARTIAL_RESULTS;
    } else if (errcode == ATOM_ldap_no_such_attribute) {
        *errcode_int = LDAP_NO_SUCH_ATTRIBUTE;
    } else if (errcode == ATOM_ldap_undefined_type) {
        *errcode_int = LDAP_UNDEFINED_TYPE;
    } else if (errcode == ATOM_ldap_inappropriate_matching) {
        *errcode_int = LDAP_INAPPROPRIATE_MATCHING;
    } else if (errcode == ATOM_ldap_constraint_violation) {
        *errcode_int = LDAP_CONSTRAINT_VIOLATION;
    } else if (errcode == ATOM_ldap_type_or_value_exists) {
        *errcode_int = LDAP_TYPE_OR_VALUE_EXISTS;
    } else if (errcode == ATOM_ldap_invalid_syntax) {
        *errcode_int = LDAP_INVALID_SYNTAX;
    } else if (errcode == ATOM_ldap_no_such_object) {
        *errcode_int = LDAP_NO_SUCH_OBJECT;
    } else if (errcode == ATOM_ldap_alias_problem) {
        *errcode_int = LDAP_ALIAS_PROBLEM;
    } else if (errcode == ATOM_ldap_invalid_dn_syntax) {
        *errcode_int = LDAP_INVALID_DN_SYNTAX;
    } else if (errcode == ATOM_ldap_is_leaf) {
        *errcode_int = LDAP_IS_LEAF;
    } else if (errcode == ATOM_ldap_alias_deref_problem) {
        *errcode_int = LDAP_ALIAS_DEREF_PROBLEM;
    } else if (errcode == ATOM_ldap_inappropriate_auth) {
        *errcode_int = LDAP_INAPPROPRIATE_AUTH;
    } else if (errcode == ATOM_ldap_invalid_credentials) {
        *errcode_int = LDAP_INVALID_CREDENTIALS;
    } else if (errcode == ATOM_ldap_insufficient_access) {
        *errcode_int = LDAP_INSUFFICIENT_ACCESS;
    } else if (errcode == ATOM_ldap_busy) {
        *errcode_int = LDAP_BUSY;
    } else if (errcode == ATOM_ldap_unavailable) {
        *errcode_int = LDAP_UNAVAILABLE;
    } else if (errcode == ATOM_ldap_unwilling_to_perform) {
        *errcode_int = LDAP_UNWILLING_TO_PERFORM;
    } else if (errcode == ATOM_ldap_loop_detect) {
        *errcode_int = LDAP_LOOP_DETECT;
    } else if (errcode == ATOM_ldap_naming_violation) {
        *errcode_int = LDAP_NAMING_VIOLATION;
    } else if (errcode == ATOM_ldap_object_class_violation) {
        *errcode_int = LDAP_OBJECT_CLASS_VIOLATION;
    } else if (errcode == ATOM_ldap_not_allowed_on_nonleaf) {
        *errcode_int = LDAP_NOT_ALLOWED_ON_NONLEAF;
    } else if (errcode == ATOM_ldap_not_allowed_on_rdn) {
        *errcode_int = LDAP_NOT_ALLOWED_ON_RDN;
    } else if (errcode == ATOM_ldap_already_exists) {
        *errcode_int = LDAP_ALREADY_EXISTS;
    } else if (errcode == ATOM_ldap_no_object_class_mods) {
        *errcode_int = LDAP_NO_OBJECT_CLASS_MODS;
    } else if (errcode == ATOM_ldap_other) {
        *errcode_int = LDAP_OTHER;
    } else {
        result = FALSE;
    }
    return result;
}

int map_scope(atom_t scope, int* scope_int) {
    int result = TRUE;
    if (scope == ATOM_ldap_scope_base) {
        *scope_int = LDAP_SCOPE_BASE;
    } else if (scope == ATOM_ldap_scope_onelevel) {
        *scope_int = LDAP_SCOPE_ONELEVEL;
    } else if (scope == ATOM_ldap_scope_subtree) {
        *scope_int = LDAP_SCOPE_SUBTREE;
    } else if (scope == ATOM_ldap_scope_children) {
        *scope_int = LDAP_SCOPE_CHILDREN;
    } else {
        result = FALSE;
    }
    return result;
}

/*
 * berval(bv_len(12), bv_val(atom))
 */
int build_BerValue(term_t berval_t, BerValue** berval) {
    BerValue* _berval = malloc(sizeof (BerValue));
    memset(_berval, 0, sizeof (BerValue));

    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(berval_t, &name, &arity)) {
        PL_type_error("compound", berval_t);
        goto error;
    }

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, berval_t, arg_t)) {
            PL_type_error("compound", berval_t);
            goto error;
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        if (arg_name == ATOM_bv_len) {
            term_t bv_len_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, bv_len_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            long bv_len;
            if (!PL_get_long(bv_len_t, &bv_len)) {
                PL_type_error("number", bv_len_t);
                goto error;
            }
            _berval->bv_len = bv_len;
        } else if (arg_name == ATOM_bv_val) {
            term_t bv_val_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, bv_val_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            char* bv_val;
            if (!PL_get_atom_chars(bv_val_t, &bv_val)) {
                PL_type_error("atom", bv_val_t);
                goto error;
            }
            _berval->bv_val = bv_val;
        }
    }

    *berval = _berval;
    PL_succeed;

error:
    free(_berval);
    PL_fail;
}

int build_BerValue_t(BerValue* berval, term_t berval_t) {
    term_t bv_len_t = PL_new_term_ref();
    if (!PL_unify_term(bv_len_t, PL_FUNCTOR, FUNCTOR_bv_len, PL_LONG, berval->bv_len)) {
        PL_fail;
    }
    term_t bv_val_t = PL_new_term_ref();
    if (!PL_unify_term(bv_val_t, PL_FUNCTOR, FUNCTOR_bv_val, PL_CHARS, berval->bv_val)) {
        PL_fail;
    }

    return PL_unify_term(berval_t, PL_FUNCTOR, FUNCTOR_berval, PL_TERM, bv_len_t, PL_TERM, bv_val_t);
}

/*
 * ldctl_value(bv_len(12), bv_val(atom))
 */
int build_ldctl_value(term_t ldctl_value_t, LDAPControl* ctrl) {
    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(ldctl_value_t, &name, &arity)) {
        return PL_type_error("compound", ldctl_value_t);
    }

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, ldctl_value_t, arg_t)) {
            return PL_type_error("compound", ldctl_value_t);
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            return PL_type_error("compound", arg_t);
        }

        if (arg_name == ATOM_bv_len) {
            term_t bv_len_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, bv_len_t)) {
                return PL_type_error("compound", arg_t);
            }

            long bv_len;
            if (!PL_get_long(bv_len_t, &bv_len)) {
                return PL_type_error("number", bv_len_t);
            }
            ctrl->ldctl_value.bv_len = bv_len;
        } else if (arg_name == ATOM_bv_val) {
            term_t bv_val_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, bv_val_t)) {
                return PL_type_error("compound", arg_t);
            }

            char* bv_val;
            if (!PL_get_atom_chars(bv_val_t, &bv_val)) {
                return PL_type_error("atom", bv_val_t);
            }
            ctrl->ldctl_value.bv_val = bv_val;
        }
    }

    PL_succeed;
}

/*
 * ldapcontrol(
 *   ldctl_oid(atom),
 *   ldctl_value(bv_len(12), bv_val(atom)),
 *   ldctl_iscritical(true)
 * )
 */
int build_LDAPControl(term_t ctrl_t, LDAPControl** ctrl) {
    LDAPControl* _ctrl = malloc(sizeof (LDAPControl));
    memset(_ctrl, 0, sizeof (LDAPControl));

    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(ctrl_t, &name, &arity)) {
        PL_type_error("compound", ctrl_t);
        goto error;
    }

    if (name != ATOM_ldapcontrol) {
        PL_domain_error(PL_atom_chars(name), name);
        goto error;
    }

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, ctrl_t, arg_t)) {
            PL_type_error("compound", ctrl_t);
            goto error;
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        if (arg_name == ATOM_ldctl_oid) {
            term_t ldctl_oid_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, ldctl_oid_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            char* ldctl_oid;
            if (!PL_get_atom_chars(ldctl_oid_t, &ldctl_oid)) {
                PL_type_error("atom", ldctl_oid_t);
                goto error;
            }
            _ctrl->ldctl_oid = ldctl_oid;
        } else if (arg_name == ATOM_ldctl_value) {
            if (!build_ldctl_value(arg_t, _ctrl)) {
                goto error;
            }
        } else if (arg_name == ATOM_ldctl_iscritical) {
            term_t ldctl_iscritical_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, ldctl_iscritical_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            int ldctl_iscritical;
            if (!PL_get_bool(ldctl_iscritical_t, &ldctl_iscritical)) {
                PL_type_error("bool", ldctl_iscritical_t);
                goto error;
            }
            _ctrl->ldctl_iscritical = (char) ldctl_iscritical;
        }
    }

    *ctrl = _ctrl;
    PL_succeed;

error:
    free(_ctrl);
    PL_fail;
}

void free_LDAPControl_array(LDAPControl** array) {
    if (array) {
        for (LDAPControl** i = array; *i; ++i) {
            free(*i);
        }
        free(array);
    }
}

int build_LDAPControl_array(term_t ctrls_t, LDAPControl*** array) {
    int size;
    if (!get_list_size(ctrls_t, &size)) {
        PL_fail;
    }

    if (size == 0) {
        PL_succeed;
    }

    LDAPControl** _array = malloc((size + 1) * sizeof (LDAPControl*));
    memset(_array, 0, (size + 1) * sizeof (LDAPControl*));

    term_t tail = PL_copy_term_ref(ctrls_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!build_LDAPControl(head, &_array[i++])) {
            free_LDAPControl_array(_array);
            PL_fail;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;

    *array = _array;
    PL_succeed;
}

/*
 * ldapcontrol(
 *   ldctl_oid(atom),
 *   ldctl_value(bv_len(12), bv_val(atom)),
 *   ldctl_iscritical(true)
 * )
 */
int build_LDAPControl_t(LDAPControl* ctrl, term_t ctrl_t) {
    term_t ldctl_oid_t = PL_new_term_ref();
    if (!PL_unify_term(ldctl_oid_t, PL_FUNCTOR, FUNCTOR_ldctl_oid, PL_CHARS, ctrl->ldctl_oid)) {
        PL_fail;
    }

    term_t ldctl_value_t = PL_new_term_ref();
    if (!build_BerValue_t(&ctrl->ldctl_value, ldctl_value_t)) {
        PL_fail;
    }

    term_t ldctl_iscritical_t = PL_new_term_ref();
    if (!PL_unify_term(ldctl_iscritical_t, PL_FUNCTOR, FUNCTOR_ldctl_iscritical, PL_BOOL, ctrl->ldctl_oid)) {
        PL_fail;
    }

    return PL_unify_term(ctrl_t, PL_FUNCTOR, FUNCTOR_ldapcontrol, PL_TERM, ldctl_oid_t,
                         PL_TERM, ldctl_value_t, PL_TERM, ldctl_iscritical_t);
}

int build_LDAPControl_t_array(LDAPControl** array, term_t ctrls_t) {
    term_t l = PL_copy_term_ref(ctrls_t);
    term_t a = PL_new_term_ref();

    for (LDAPControl** i = array; *i; ++i) {
        if (!PL_unify_list(l, a, l) ||
            !build_LDAPControl_t(*i, a))
            PL_fail;
    }

    return PL_unify_nil(l);
}

/*
 * timeval(tv_sec(100), tv_usec(100))
 */
int build_timeval(term_t timeval_t, TimeVal** timeval) {
    TimeVal* _timeval = malloc(sizeof (TimeVal));
    memset(_timeval, 0, sizeof (TimeVal));

    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(timeval_t, &name, &arity)) {
        PL_type_error("compound", timeval_t);
        goto error;
    }

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, timeval_t, arg_t)) {
            PL_type_error("compound", timeval_t);
            goto error;
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        if (arg_name == ATOM_tv_sec) {
            term_t tv_sec_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, tv_sec_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            time_t tv_sec;
            if (!PL_get_long(tv_sec_t, &tv_sec)) {
                PL_type_error("number", tv_sec_t);
                goto error;
            }
            _timeval->tv_sec = tv_sec;
        } else if (arg_name == ATOM_tv_usec) {
            term_t tv_usec_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, tv_usec_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            suseconds_t tv_usec;
#ifdef __linux__
            if (!PL_get_long(tv_usec_t, &tv_usec)) {
#else
            if (!PL_get_integer(tv_usec_t, &tv_usec)) {
#endif
                PL_type_error("number", tv_usec_t);
                goto error;
            }
            _timeval->tv_usec = tv_usec;
        }
    }

    *timeval = _timeval;
    PL_succeed;

error:
    free(_timeval);
    PL_fail;
}

int build_chars_array(term_t array_t, char*** array) {
    int _size;
    if (!get_list_size(array_t, &_size)) {
        PL_fail;
    }

    if (_size == 0) {
        PL_succeed;
    }

    int size = _size + 1;

    char** _array = malloc(size * sizeof (char*));
    memset(_array, 0, size * sizeof (char*));

    term_t tail = PL_copy_term_ref(array_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!PL_get_atom_chars(head, &_array[i++])) {
            free(_array);
            PL_fail;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;

    *array = _array;
    PL_succeed;
}

int build_chars_t_array(char** array, term_t array_t) {
    term_t l = PL_copy_term_ref(array_t);
    term_t a = PL_new_term_ref();

    for (char** i = array; *i; ++i) {
        if (!PL_unify_list(l, a, l) ||
            !PL_unify_atom_chars(a, *i))
            PL_fail;
    }

    return PL_unify_nil(l);
}

/*
 * query(base(), scope(), filter(), attrs([]), attrsonly())
 */
int build_query_conditions(term_t query_t, char** base, int* scope, char** filter, char*** attrs, int* attrsonly) {
    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(query_t, &name, &arity)) {
        PL_type_error("compound", query_t);
        goto error;
    }

    if (name != ATOM_query) {
        PL_domain_error(PL_atom_chars(name), name);
        goto error;
    }

    char** _attrs = NULL;

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, query_t, arg_t)) {
            PL_type_error("compound", query_t);
            goto error;
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        if (arg_name == ATOM_base) {
            term_t base_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, base_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }
            if (!PL_get_atom_chars(base_t, base)) {
                PL_type_error("atom", base_t);
                goto error;
            }
        } else if (arg_name == ATOM_scope) {
            term_t scope_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, scope_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }
            atom_t _scope;
            if (!PL_get_atom(scope_t, &_scope)) {
                PL_type_error("atom", scope_t);
                goto error;
            }
            if (!map_scope(_scope, scope)) {
                PL_domain_error("valid scope required", scope_t);
                goto error;
            }
        } else if (arg_name == ATOM_filter) {
            term_t filter_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, filter_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }
            if (!PL_get_atom_chars(filter_t, filter)) {
                PL_type_error("atom", filter_t);
                goto error;
            }
        } else if (arg_name == ATOM_attrs) {
            term_t attrs_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, attrs_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }
            if (!PL_is_variable(attrs_t)) {
                if (!build_chars_array(attrs_t, &_attrs)) {
                    goto error;
                }
            }
        } else if (arg_name == ATOM_attrsonly) {
            term_t attrsonly_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, attrsonly_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }
            if (!PL_get_bool(attrsonly_t, attrsonly)) {
                PL_type_error("atom", attrsonly_t);
                goto error;
            }
        }
    }

    *attrs = _attrs;
    PL_succeed;

error:
    free(_attrs);
    PL_fail;
}

void free_BerValue_array(BerValue** array) {
    if (array) {
        for (BerValue** i = array; *i; ++i) {
            free(*i);
        }
        free(array);
    }
}

void free_LDAPMod_array(LDAPMod** array) {
    if (array) {
        for (LDAPMod** i = array; *i; ++i) {
            LDAPMod* mod = *i;
            if (mod->mod_op & LDAP_MOD_BVALUES) {
                free_BerValue_array(mod->mod_bvalues);
            } else {
                free(mod->mod_values);
            }
            free(mod);
        }
        free(array);
    }
}

int build_mod_op(term_t mod_op_t, int* mod_op) {
    term_t tail = PL_copy_term_ref(mod_op_t);
    term_t head = PL_new_term_ref();
    int _mod_op = 0;
    while (PL_get_list(tail, head, tail)) {
        atom_t op;
        if (!PL_get_atom(head, &op)) {
            return PL_type_error("atom", head);
        }

        int op_int;
        if (op == ATOM_ldap_mod_add) {
            op_int = LDAP_MOD_ADD;
        } else if (op == ATOM_ldap_mod_delete) {
            op_int = LDAP_MOD_DELETE;
        } else if (op == ATOM_ldap_mod_replace) {
            op_int = LDAP_MOD_REPLACE;
        } else if (op == ATOM_ldap_mod_bvalues) {
            op_int = LDAP_MOD_BVALUES;
        } else {
            PL_fail;
        }

        _mod_op |= op_int;
    }
    *mod_op = _mod_op;
    PL_succeed;
}

int build_mod_bvalues(term_t mod_bvalues_t, BerValue*** array) {
    int size;
    if (!get_list_size(mod_bvalues_t, &size)) {
        PL_fail;
    }

    if (size == 0) {
        PL_succeed;
    }

    BerValue** _array = malloc((size + 1) * sizeof (BerValue*));
    memset(_array, 0, (size + 1) * sizeof (BerValue*));

    term_t tail = PL_copy_term_ref(mod_bvalues_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!build_BerValue(head, &_array[i++])) {
            free_BerValue_array(_array);
            PL_fail;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;

    *array = _array;
    PL_succeed;
}

int build_mod_values(term_t mod_values_t, char*** array) {
    int size;
    if (!get_list_size(mod_values_t, &size)) {
        PL_fail;
    }

    if (size == 0) {
        PL_succeed;
    }

    char** _array = malloc((size + 1) * sizeof (char*));
    memset(_array, 0, (size + 1) * sizeof (char*));

    term_t tail = PL_copy_term_ref(mod_values_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!PL_get_atom_chars(head, &_array[i++])) {
            free(_array);
            PL_fail;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;

    *array = _array;
    PL_succeed;
}

/*
 * ldapmod(
 *     mod_op([ldap_mod_add, ldap_mod_bvalues]),
 *     mod_type(attr_name),
 *     mod_bvalues([
 *         berval(bv_len(5), bv_val(hello)),
 *         berval(bv_len(5), bv_val(world))
 *     ])
 * )
 */
int build_LDAPMod(term_t ldapmod_t, LDAPMod** ldapmod) {
    LDAPMod* _ldapmod = malloc(sizeof (LDAPMod));
    memset(_ldapmod, 0, sizeof (LDAPMod));

    atom_t name;
    size_t arity;
    if (!PL_get_compound_name_arity(ldapmod_t, &name, &arity)) {
        PL_type_error("compound", ldapmod_t);
        goto error;
    }

    if (name != ATOM_ldapmod) {
        PL_domain_error(PL_atom_chars(name), name);
        goto error;
    }

    for (size_t i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, ldapmod_t, arg_t)) {
            PL_type_error("compound", ldapmod_t);
            goto error;
        }

        atom_t arg_name;
        size_t arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        if (arg_name == ATOM_mod_op) {
            term_t mod_op_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, mod_op_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            int mod_op;
            if (!build_mod_op(mod_op_t, &mod_op)) {
                goto error;
            }

            _ldapmod->mod_op = mod_op;
        } else if (arg_name == ATOM_mod_type) {
            term_t mod_type_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, mod_type_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            char* mod_type;
            if (!PL_get_atom_chars(mod_type_t, &mod_type)) {
                PL_type_error("atom", mod_type_t);
                goto error;
            }

            _ldapmod->mod_type = mod_type;
        } else if (arg_name == ATOM_mod_bvalues) {
            term_t mod_bvalues_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, mod_bvalues_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            BerValue** _mod_bvalues;
            if (!build_mod_bvalues(mod_bvalues_t, &_mod_bvalues)) {
                goto error;
            }
            _ldapmod->mod_bvalues = _mod_bvalues;
        }  else if (arg_name == ATOM_mod_values) {
            term_t mod_values_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, mod_values_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            char** _mod_values;
            if (!build_mod_values(mod_values_t, &_mod_values)) {
                goto error;
            }

            _ldapmod->mod_values = _mod_values;
        }
    }

    *ldapmod = _ldapmod;
    PL_succeed;

error:
    free(_ldapmod);
    PL_fail;
}

int build_LDAPMod_array(term_t attrs_t, LDAPMod*** array) {
    int size;
    if (!get_list_size(attrs_t, &size)) {
        PL_fail;
    }

    if (size == 0) {
        PL_succeed;
    }

    LDAPMod** _array = malloc((size + 1) * sizeof (LDAPMod*));
    memset(_array, 0, (size + 1) * sizeof (LDAPMod*));

    term_t tail = PL_copy_term_ref(attrs_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!build_LDAPMod(head, &_array[i++])) {
            free_LDAPMod_array(_array);
            PL_fail;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;

    *array = _array;
    PL_succeed;
}

int build_lud_t(LDAPURLDesc* lud, term_t lud_t) {
    term_t lud_scheme_t = PL_new_term_ref();
    if (!PL_unify_term(lud_scheme_t, PL_FUNCTOR, FUNCTOR_lud_scheme, PL_CHARS, lud->lud_scheme)) {
        PL_fail;
    }

    term_t lud_host_t = PL_new_term_ref();
    char* host = lud->lud_host ? lud->lud_host : "";
    if (!PL_unify_term(lud_host_t, PL_FUNCTOR, FUNCTOR_lud_host, PL_CHARS, host)) {
        PL_fail;
    }

    term_t lud_port_t = PL_new_term_ref();
    if (!PL_unify_term(lud_port_t, PL_FUNCTOR, FUNCTOR_lud_port, PL_INT, lud->lud_port)) {
        PL_fail;
    }

    term_t lud_dn_t = PL_new_term_ref();
    char* dn = lud->lud_dn ? lud->lud_dn : "";
    if (!PL_unify_term(lud_dn_t, PL_FUNCTOR, FUNCTOR_lud_dn, PL_CHARS, dn)) {
        PL_fail;
    }

    term_t attrs_t = PL_new_term_ref();
    if (lud->lud_attrs) {
        if (!build_chars_t_array(lud->lud_attrs, attrs_t)) {
            PL_fail;
        }
    } else {
        if (!PL_unify_nil(attrs_t)) {
            PL_fail;
        }
    }
    term_t lud_attrs_t = PL_new_term_ref();
    if (!PL_unify_term(lud_attrs_t, PL_FUNCTOR, FUNCTOR_lud_attrs, PL_TERM, attrs_t)) {
        PL_fail;
    }

    term_t lud_scope_t = PL_new_term_ref();
    if (!PL_unify_term(lud_scope_t, PL_FUNCTOR, FUNCTOR_lud_scope, PL_INT, lud->lud_scope)) {
        PL_fail;
    }

    term_t lud_filter_t = PL_new_term_ref();
    char* filter = lud->lud_filter ? lud->lud_filter : "";
    if (!PL_unify_term(lud_filter_t, PL_FUNCTOR, FUNCTOR_lud_filter, PL_CHARS, filter)) {
        PL_fail;
    }

    term_t exts_t = PL_new_term_ref();
    if (lud->lud_exts) {
        if (!build_chars_t_array(lud->lud_exts, exts_t)) {
            PL_fail;
        }
    } else {
        if (!PL_unify_nil(exts_t)) {
            PL_fail;
        }
    }
    term_t lud_exts_t = PL_new_term_ref();
    if (!PL_unify_term(lud_exts_t, PL_FUNCTOR, FUNCTOR_lud_exts, PL_TERM, exts_t)) {
        PL_fail;
    }

    term_t lud_crit_exts_t = PL_new_term_ref();
    if (!PL_unify_term(lud_crit_exts_t, PL_FUNCTOR, FUNCTOR_lud_crit_exts, PL_INT, lud->lud_crit_exts)) {
        PL_fail;
    }

    return PL_unify_term(lud_t, PL_FUNCTOR, FUNCTOR_lud,
                         PL_TERM, lud_scheme_t,
                         PL_TERM, lud_host_t,
                         PL_TERM, lud_port_t,
                         PL_TERM, lud_dn_t,
                         PL_TERM, lud_attrs_t,
                         PL_TERM, lud_scope_t,
                         PL_TERM, lud_filter_t,
                         PL_TERM, lud_exts_t,
                         PL_TERM, lud_crit_exts_t);
}

int ldap4pl_bind0(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    atom_t method;
    if (!PL_get_atom(method_t, &method)) {
        return PL_type_error("atom", method_t);
    }

    int method_int;
    if (!map_auth_method(method, &method_int)) {
        return PL_domain_error("valid method required", method_t);
    }

    char* who;
    if (!PL_get_atom_chars(who_t, &who)) {
        return PL_type_error("atom", who_t);
    }
    char* cred;
    if (!PL_get_atom_chars(cred_t, &cred)) {
        return PL_type_error("atom", cred_t);
    }

    int result = !synchronous ? ldap_bind(ldap, who, cred, method_int) :
        !(ld_errno = ldap_bind_s(ldap, who, cred, method_int));
    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : result;
}

int ldap4pl_simple_bind0(term_t ldap_t, term_t who_t, term_t passwd_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* who;
    if (!PL_get_atom_chars(who_t, &who)) {
        return PL_type_error("atom", who_t);
    }
    char* passwd;
    if (!PL_get_atom_chars(passwd_t, &passwd)) {
        return PL_type_error("atom", passwd_t);
    }

    int result = !synchronous ? ldap_simple_bind(ldap, who, passwd) :
        !(ld_errno = ldap_simple_bind_s(ldap, who, passwd));
    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : result;
}

int ldap4pl_sasl_bind0(term_t ldap_t, term_t dn_t, term_t mechanism_t,
                       term_t cred_t, term_t sctrls_t, term_t cctrls_t,
                       term_t msgid_t, term_t servercred_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(servercred_t)) {
        return PL_uninstantiation_error(servercred_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }
    char* mechanism;
    if (!PL_get_atom_chars(mechanism_t, &mechanism)) {
        return PL_type_error("atom", mechanism_t);
    }

    BerValue* cred;
    if (!build_BerValue(cred_t, &cred)) {
        PL_fail;
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        free(cred);
        PL_fail;
    }

    int msgid;
    BerValue* servercred;
    int result = !synchronous ?
        ldap_sasl_bind(ldap, dn, mechanism, cred, sctrls, cctrls, &msgid) :
        !(ld_errno = ldap_sasl_bind_s(ldap, dn, mechanism, cred, sctrls, cctrls, &servercred));

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);
    free(cred);

    if (!synchronous) {
        return result != -1 && PL_unify_integer(msgid_t, msgid);
    } else {
        int final_result = result && build_BerValue_t(servercred, servercred_t);
        if (result) {
            ber_bvfree(servercred);
        }
        return final_result;
    }
}

int ldap4pl_set_option0(LDAP* ldap, int option, term_t invalue_t) {
    switch (option) {
    case LDAP_OPT_PROTOCOL_VERSION:
    case LDAP_OPT_RESULT_CODE:
    case LDAP_OPT_SIZELIMIT:
    case LDAP_OPT_TIMELIMIT: {
        int invalue;
        if (PL_get_integer(invalue_t, &invalue)) {
            return !(ld_errno = ldap_set_option(ldap, option, &invalue));
        }
        break;
    }
    case LDAP_OPT_DIAGNOSTIC_MESSAGE:
    case LDAP_OPT_MATCHED_DN: {
        char* invalue;
        if (PL_get_atom_chars(invalue_t, &invalue)) {
            return !(ld_errno = ldap_set_option(ldap, option, invalue));
        }
        break;
    }
    case LDAP_OPT_DEREF: {
        atom_t invalue_a;
        if (!PL_get_atom(invalue_t, &invalue_a)) {
            return PL_type_error("atom", invalue_t);
        }
        int invalue;
        if (invalue_a == ATOM_ldap_deref_never) {
            invalue = LDAP_DEREF_NEVER;
        } else if (invalue_a == ATOM_ldap_deref_searching) {
            invalue = LDAP_DEREF_SEARCHING;
        } else if (invalue_a == ATOM_ldap_deref_finding) {
            invalue = LDAP_DEREF_FINDING;
        } else if (invalue_a == ATOM_ldap_deref_always) {
            invalue = LDAP_DEREF_ALWAYS;
        } else {
            PL_fail;
        }
        return !(ld_errno = ldap_set_option(ldap, option, &invalue));
    }
    case LDAP_OPT_REFERRALS:
    case LDAP_OPT_RESTART: {
        atom_t invalue_a;
        if (!PL_get_atom(invalue_t, &invalue_a)) {
            return PL_type_error("atom", invalue_t);
        }
        if (invalue_a == ATOM_ldap_opt_on) {
            return !(ld_errno = ldap_set_option(ldap, option, LDAP_OPT_ON));
        } else if (invalue_a == ATOM_ldap_opt_off) {
            return !(ld_errno = ldap_set_option(ldap, option, LDAP_OPT_OFF));
        } else {
            PL_fail;
        }
    }
    case LDAP_OPT_REFERRAL_URLS: {
        char** invalue;
        if (build_chars_array(invalue_t, &invalue)) {
            return !(ld_errno = ldap_set_option(ldap, option, invalue));
        }
        break;
    }
    }
    PL_fail;
}

int ldap4pl_get_option0(LDAP* ldap, int option, term_t outvalue_t) {
    switch (option) {
    case LDAP_OPT_PROTOCOL_VERSION:
    case LDAP_OPT_RESULT_CODE:
    case LDAP_OPT_SIZELIMIT:
    case LDAP_OPT_TIMELIMIT: {
        int outvalue;
        if (!(ld_errno = ldap_get_option(ldap, option, &outvalue))) {
            return PL_unify_integer(outvalue_t, outvalue);
        }
        break;
    }
    case LDAP_OPT_DIAGNOSTIC_MESSAGE:
    case LDAP_OPT_MATCHED_DN: {
        char* outvalue;
        if (!(ld_errno = ldap_get_option(ldap, option, &outvalue))) {
            int result = PL_unify_atom_chars(outvalue_t, outvalue);
            ldap_memfree(outvalue);
            return result;
        }
        break;
    }
    case LDAP_OPT_DEREF: {
        int outvalue;
        if (!(ld_errno = ldap_get_option(ldap, option, &outvalue))) {
            switch (outvalue) {
            case LDAP_DEREF_NEVER:
                return PL_unify_atom(outvalue_t, ATOM_ldap_deref_never);
            case LDAP_DEREF_SEARCHING:
                return PL_unify_atom(outvalue_t, ATOM_ldap_deref_searching);
            case LDAP_DEREF_FINDING:
                return PL_unify_atom(outvalue_t, ATOM_ldap_deref_finding);
            case LDAP_DEREF_ALWAYS:
                return PL_unify_atom(outvalue_t, ATOM_ldap_deref_always);
            }
        }
        break;
    }
    case LDAP_OPT_REFERRALS:
    case LDAP_OPT_RESTART: {
        int outvalue;
        if (!(ld_errno = ldap_get_option(ldap, option, &outvalue))) {
            if (outvalue) {
                return PL_unify_atom(outvalue_t, ATOM_ldap_opt_on);
            } else {
                return PL_unify_atom(outvalue_t, ATOM_ldap_opt_off);
            }
        }
        break;
    }
    case LDAP_OPT_REFERRAL_URLS: {
        char** outvalue;
        if (!(ld_errno = ldap_get_option(ldap, option, &outvalue))) {
            int result = build_chars_t_array(outvalue, outvalue_t);
            ldap_memvfree((void**) outvalue);
            return result;
        }
        break;
    }
    }
    PL_fail;
}

int ldap4pl_search_ext0(term_t ldap_t, term_t query_t, term_t sctrls_t,
                        term_t cctrls_t, term_t timeout_t, term_t sizelimit_t,
                        term_t msgid_t, term_t res_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(res_t)) {
        return PL_uninstantiation_error(res_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* base = NULL;
    int scope = LDAP_SCOPE_DEFAULT;
    char* filter = NULL;
    char** attrs = NULL;
    int attrsonly = -1;
    if (!build_query_conditions(query_t, &base, &scope, &filter, &attrs, &attrsonly)) {
        PL_fail;
    }

    if (!base) {
        free(attrs);
        return PL_domain_error("base is missing", query_t);
    }

    if (attrsonly == -1) {
        free(attrs);
        return PL_domain_error("attrsonly is missing", query_t);
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        free(attrs);
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        free(attrs);
        PL_fail;
    }

    TimeVal* timeout = NULL;
    if (!PL_is_variable(timeout_t)) {
        if (!build_timeval(timeout_t, &timeout)) {
            free_LDAPControl_array(cctrls);
            free_LDAPControl_array(sctrls);
            free(attrs);
            PL_fail;
        }
    }

    int sizelimit;
    if (!PL_get_integer(sizelimit_t, &sizelimit)) {
        free_LDAPControl_array(cctrls);
        free_LDAPControl_array(sctrls);
        free(timeout);
        free(attrs);
        return PL_type_error("atom", sizelimit_t);
    }

    int msgid;
    LDAPMessage* res;
    int result = !synchronous ?
        ldap_search_ext(ldap, base, scope, filter, attrs, attrsonly, sctrls, cctrls, timeout, sizelimit, &msgid) :
        !(ld_errno = ldap_search_ext_s(ldap, base, scope, filter, attrs, attrsonly, sctrls, cctrls, timeout, sizelimit, &res));

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);
    free(timeout);
    free(attrs);

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, msgid)) : (result && PL_unify_pointer(res_t, res));
}

int ldap4pl_search0(term_t ldap_t, term_t query_t,
                    term_t timeout_t, term_t msgid_t,
                    term_t res_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(res_t)) {
        return PL_uninstantiation_error(res_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* base = NULL;
    int scope = LDAP_SCOPE_DEFAULT;
    char* filter = NULL;
    char** attrs = NULL;
    int attrsonly = -1;
    if (!build_query_conditions(query_t, &base, &scope, &filter, &attrs, &attrsonly)) {
        PL_fail;
    }

    if (!base) {
        free(attrs);
        return PL_domain_error("base is missing", query_t);
    }

    if (attrsonly == -1) {
        free(attrs);
        return PL_domain_error("attrsonly is missing", query_t);
    }

    TimeVal* timeout = NULL;
    if (!PL_is_variable(timeout_t)) {
        if (!build_timeval(timeout_t, &timeout)) {
            free(attrs);
            PL_fail;
        }
    }

    int msgid;
    LDAPMessage* res;
    int result = !synchronous ?
        ldap_search(ldap, base, scope, filter, attrs, attrsonly) :
        (timeout == NULL ?
         !(ld_errno = ldap_search_s(ldap, base, scope, filter, attrs, attrsonly, &res)) :
         !(ld_errno = ldap_search_st(ldap, base, scope, filter, attrs, attrsonly, timeout, &res)));

    free(timeout);
    free(attrs);

    if (!synchronous) {
        return result != -1 && PL_unify_integer(msgid_t, result);
    } else {
        return result && PL_unify_pointer(res_t, res);
    }
}

int ldap4pl_compare_ext0(term_t ldap_t, term_t dn_t, term_t attribute_t, term_t berval_t,
                         term_t sctrls_t, term_t cctrls_t, term_t msgid_t, term_t res_t,
                         int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(res_t)) {
        return PL_uninstantiation_error(res_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    char* attribute;
    if (!PL_get_atom_chars(attribute_t, &attribute)) {
        return PL_type_error("atom", attribute_t);
    }

    BerValue* berval;
    if (!build_BerValue(berval_t, &berval)) {
        PL_fail;
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        free(berval);
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        free(berval);
        PL_fail;
    }

    int msgid;
    int result = !synchronous ?
        ldap_compare_ext(ldap, dn, attribute, berval, sctrls, cctrls, &msgid) :
        ldap_compare_ext_s(ldap, dn, attribute, berval, sctrls, cctrls);

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);
    free(berval);

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : map_error_code(result, res_t);
}

int ldap4pl_compare0(term_t ldap_t, term_t dn_t,
                     term_t attribute_t, term_t value_t, term_t msgid_t,
                     term_t res_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(res_t)) {
        return PL_uninstantiation_error(res_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    char* attribute;
    if (!PL_get_atom_chars(attribute_t, &attribute)) {
        return PL_type_error("atom", attribute_t);
    }

    char* value;
    if (!PL_get_atom_chars(value_t, &value)) {
        return PL_type_error("atom", value_t);
    }

    int result = !synchronous ?
        ldap_compare(ldap, dn, attribute, value) :
        ldap_compare_s(ldap, dn, attribute, value);

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : map_error_code(result, res_t);
}

int ldap4pl_update_ext0(term_t ldap_t, term_t dn_t, term_t attrs_t,
                        term_t sctrls_t, term_t cctrls_t, term_t msgid_t,
                        int synchronous, int operation) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    LDAPMod** attrs = NULL;
    if (operation != LDAP_MOD_DELETE) {
        if (!build_LDAPMod_array(attrs_t, &attrs)) {
            PL_fail;
        }
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        free_LDAPMod_array(attrs);
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        free_LDAPMod_array(attrs);
        PL_fail;
    }

    int msgid;
    int result;
    if (operation == LDAP_MOD_ADD) {
        result = !synchronous ?
            ldap_add_ext(ldap, dn, attrs, sctrls, cctrls, &msgid) :
            !(ld_errno = ldap_add_ext_s(ldap, dn, attrs, sctrls, cctrls));
    } else if (operation == LDAP_MOD_REPLACE) {
        result = !synchronous ?
            ldap_modify_ext(ldap, dn, attrs, sctrls, cctrls, &msgid) :
            !(ld_errno = ldap_modify_ext_s(ldap, dn, attrs, sctrls, cctrls));
    } else {
        result = !synchronous ?
            ldap_delete_ext(ldap, dn, sctrls, cctrls, &msgid) :
            !(ld_errno = ldap_delete_ext_s(ldap, dn, sctrls, cctrls));
    }

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);
    free_LDAPMod_array(attrs);

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, msgid)) : result;
}

int ldap4pl_modrdn0(term_t ldap_t, term_t dn_t, term_t newrdn_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    char* newrdn;
    if (!PL_get_atom_chars(newrdn_t, &newrdn)) {
        return PL_type_error("atom", newrdn_t);
    }

    int result;
    result = !synchronous ?
        ldap_modrdn(ldap, dn, newrdn) :
        !(ld_errno = ldap_modrdn_s(ldap, dn, newrdn));

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : result;
}

int ldap4pl_modrdn20(term_t ldap_t, term_t dn_t, term_t newrdn_t, term_t deleteoldrdn_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    char* newrdn;
    if (!PL_get_atom_chars(newrdn_t, &newrdn)) {
        return PL_type_error("atom", newrdn_t);
    }

    int deleteoldrdn;
    if (!PL_get_bool(deleteoldrdn_t, &deleteoldrdn)) {
        return PL_type_error("bool", deleteoldrdn_t);
    }

    int result;
    result = !synchronous ?
        ldap_modrdn2(ldap, dn, newrdn, deleteoldrdn) :
        !(ld_errno = ldap_modrdn2_s(ldap, dn, newrdn, deleteoldrdn));

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, result)) : result;
}

int ldap4pl_rename0(term_t ldap_t, term_t dn_t, term_t newrdn_t,
                    term_t newsuperior_t, term_t deleteoldrdn_t,
                    term_t sctrls_t, term_t cctrls_t,
                    term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* dn;
    if (!PL_get_atom_chars(dn_t, &dn)) {
        return PL_type_error("atom", dn_t);
    }

    char* newrdn;
    if (!PL_get_atom_chars(newrdn_t, &newrdn)) {
        return PL_type_error("atom", newrdn_t);
    }

    char* newsuperior;
    if (!PL_get_atom_chars(newsuperior_t, &newsuperior)) {
        return PL_type_error("atom", newsuperior_t);
    }

    int deleteoldrdn;
    if (!PL_get_bool(deleteoldrdn_t, &deleteoldrdn)) {
        return PL_type_error("bool", deleteoldrdn_t);
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        PL_fail;
    }

    int msgid;
    int result;
    result = !synchronous ?
        ldap_rename(ldap, dn, newrdn, newsuperior, deleteoldrdn, sctrls, cctrls, &msgid) :
        !(ld_errno = ldap_rename_s(ldap, dn, newrdn, newsuperior, deleteoldrdn, sctrls, cctrls));

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);

    return !synchronous ? (result != -1 && PL_unify_integer(msgid_t, msgid)) : result;
}

int ldap4pl_extended_operation0(term_t ldap_t, term_t requestoid_t, term_t requestdata_t,
                                term_t sctrls_t, term_t cctrls_t, term_t msgid_t,
                                term_t retoid_t, term_t retdata_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(retoid_t)) {
        return PL_uninstantiation_error(retoid_t);
    }

    if (synchronous && !PL_is_variable(retdata_t)) {
        return PL_uninstantiation_error(retdata_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* requestoid;
    if (!PL_get_atom_chars(requestoid_t, &requestoid)) {
        return PL_type_error("atom", requestoid_t);
    }

    BerValue* requestdata;
    if (!build_BerValue(requestdata_t, &requestdata)) {
        PL_fail;
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        free(requestdata);
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        free(requestdata);
        PL_fail;
    }

    int msgid;
    char* retoid;
    BerValue* retdata;
    int result;
    result = !synchronous ?
        ldap_extended_operation(ldap, requestoid, requestdata, sctrls, cctrls, &msgid) :
        !(ld_errno = ldap_extended_operation_s(ldap, requestoid, requestdata,
                                               sctrls, cctrls, &retoid, &retdata));

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);
    free(requestdata);

    if (!synchronous) {
        return result != 1 && PL_unify_integer(msgid_t, msgid);
    } else {
        int final_result = result && PL_unify_atom_chars(retoid_t, retoid) &&
            build_BerValue_t(retdata, retdata_t);
        if (result) {
            ldap_memfree(retoid);
            ber_bvfree(retdata);
        }
        return final_result;
    }
}

static foreign_t ldap4pl_initialize(term_t ldap_t, term_t uri_t) {
    if (!PL_is_variable(ldap_t)) {
        return PL_uninstantiation_error(ldap_t);
    }

    char* uri;
    if (!PL_get_atom_chars(uri_t, &uri)) {
        return PL_type_error("atom", uri_t);
    }

    DEBUG(Sdprintf("connecting to %s\n", uri));

    LDAP* ldap;
    if ((ld_errno = ldap_initialize(&ldap, uri)) != 0) {
        PL_fail;
    }

    return PL_unify_pointer(ldap_t, ldap);
}

static foreign_t ldap4pl_unbind(term_t ldap_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    return !(ld_errno = ldap_unbind_s(ldap));
}

static foreign_t ldap4pl_unbind_ext(term_t ldap_t, term_t sctrls_t, term_t cctrls_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        PL_fail;
    }

    int result = ldap_unbind_ext_s(ldap, sctrls, cctrls);

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);

    return !result;
}

static foreign_t ldap4pl_bind(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t, term_t msgid_t) {
    return ldap4pl_bind0(ldap_t, who_t, cred_t, method_t, msgid_t, FALSE);
}

static foreign_t ldap4pl_bind_s(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t) {
    return ldap4pl_bind0(ldap_t, who_t, cred_t, method_t, (term_t) NULL, TRUE);
}

static foreign_t ldap4pl_simple_bind(term_t ldap_t, term_t who_t, term_t passwd_t, term_t msgid_t) {
    return ldap4pl_simple_bind0(ldap_t, who_t, passwd_t, msgid_t, FALSE);
}

static foreign_t ldap4pl_simple_bind_s(term_t ldap_t, term_t who_t, term_t passwd_t) {
    return ldap4pl_simple_bind0(ldap_t, who_t, passwd_t, (term_t) NULL, TRUE);
}

static foreign_t ldap4pl_sasl_bind(term_t ldap_t, term_t dn_t, term_t mechanism_t,
                                   term_t cred_t, term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_sasl_bind0(ldap_t, dn_t, mechanism_t, cred_t, sctrls_t, cctrls_t, msgid_t, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_sasl_bind_s(term_t ldap_t, term_t dn_t, term_t mechanism_t,
                                     term_t cred_t, term_t sctrls_t, term_t cctrls_t, term_t servercred_t) {
    return ldap4pl_sasl_bind0(ldap_t, dn_t, mechanism_t, cred_t, sctrls_t, cctrls_t, (term_t) NULL, servercred_t, TRUE);
}

static foreign_t ldap4pl_parse_sasl_bind_result(term_t ldap_t, term_t res_t, term_t servercred_t, term_t freeit_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* result;
    if (!PL_get_pointer(res_t, (void**) &result)) {
        return PL_type_error("pointer", res_t);
    }

    int freeit;
    if (!PL_get_bool(freeit_t, &freeit)) {
        return PL_type_error("bool", freeit_t);
    }

    BerValue* servercred;
    if ((ld_errno = ldap_parse_sasl_bind_result(ldap, result, &servercred, freeit)) != 0) {
        PL_fail;
    }

    int tmp = build_BerValue_t(servercred, servercred_t);
    ber_bvfree(servercred);
    return tmp;
}

static foreign_t ldap4pl_set_option(term_t ldap_t, term_t option_t, term_t invalue_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    atom_t option;
    if (!PL_get_atom(option_t, &option)) {
        return PL_type_error("atom", option_t);
    }

    int option_int;
    if (!map_option(option, &option_int)) {
        return PL_type_error("number", option_t);
    }

    return ldap4pl_set_option0(ldap, option_int, invalue_t);
}

static foreign_t ldap4pl_get_option(term_t ldap_t, term_t option_t, term_t outvalue_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    atom_t option;
    if (!PL_get_atom(option_t, &option)) {
        return PL_type_error("atom", option_t);
    }

    int option_int;
    if (!map_option(option, &option_int)) {
        return PL_type_error("number", option_t);
    }

    return ldap4pl_get_option0(ldap, option_int, outvalue_t);
}

static foreign_t ldap4pl_result(term_t ldap_t, term_t msgid_t, term_t all_t, term_t timeout_t, term_t res_t) {
    if (!PL_is_variable(res_t)) {
        return PL_uninstantiation_error(res_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int msgid;
    if (!PL_get_integer(msgid_t, &msgid)) {
        return PL_type_error("number", msgid_t);
    }

    int all;
    if (!PL_get_bool(all_t, &all)) {
        return PL_type_error("bool", all_t);
    }

    LDAPMessage* result;
    if (PL_is_variable(timeout_t)) {
        if (ldap_result(ldap, msgid, all, NULL, &result) == -1) {
            PL_fail;
        }
    } else {
        TimeVal* timeout;
        if (!build_timeval(timeout_t, &timeout)) {
            PL_fail;
        }

        if (ldap_result(ldap, msgid, all, timeout, &result) <= 0) {
            free(timeout);
            PL_fail;
        }
        free(timeout);
    }

    return PL_unify_pointer(res_t, result);
}

static foreign_t ldap4pl_msgfree(term_t msg_t) {
    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    return ldap_msgfree(msg) != -1;
}

static foreign_t ldap4pl_msgtype(term_t msg_t, term_t type_t) {
    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    int result;
    if ((result = ldap_msgtype(msg)) == -1) {
        PL_fail;
    }

    return map_msg_type(result, type_t);
}

static foreign_t ldap4pl_msgid(term_t msg_t, term_t id_t) {
    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    int result;
    if ((result = ldap_msgid(msg)) == -1) {
        PL_fail;
    }

    return PL_unify_integer(id_t, result);
}

static foreign_t ldap4pl_search_ext(term_t ldap_t, term_t query_t, term_t sctrls_t,
                                    term_t cctrls_t, term_t timeout_t, term_t sizelimit_t,
                                    term_t msgid_t) {
    return ldap4pl_search_ext0(ldap_t, query_t, sctrls_t,
                               cctrls_t, timeout_t, sizelimit_t, msgid_t, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_search_ext_s(term_t ldap_t, term_t query_t, term_t sctrls_t,
                                      term_t cctrls_t, term_t timeout_t, term_t sizelimit_t,
                                      term_t res_t) {
    return ldap4pl_search_ext0(ldap_t, query_t, sctrls_t,
                               cctrls_t, timeout_t, sizelimit_t, (term_t) NULL, res_t, TRUE);
}

static foreign_t ldap4pl_search(term_t ldap_t, term_t query_t, term_t timeout, term_t msgid_t) {
    return ldap4pl_search0(ldap_t, query_t, timeout, msgid_t, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_search_s(term_t ldap_t, term_t query_t, term_t timeout, term_t res_t) {
    return ldap4pl_search0(ldap_t, query_t, timeout, (term_t) NULL, res_t, TRUE);
}

static foreign_t ldap4pl_count_entries(term_t ldap_t, term_t res_t, term_t count_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* res;
    if (!PL_get_pointer(res_t, (void**) &res)) {
        return PL_type_error("pointer", res_t);
    }

    int count;
    if ((count = ldap_count_entries(ldap, res)) == -1) {
        PL_fail;
    }

    return PL_unify_integer(count_t, count);
}

static foreign_t ldap4pl_first_entry(term_t ldap_t, term_t res_t, term_t entry_t) {
    if (!PL_is_variable(entry_t)) {
        return PL_uninstantiation_error(entry_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* res;
    if (!PL_get_pointer(res_t, (void**) &res)) {
        return PL_type_error("pointer", res_t);
    }

    LDAPMessage* entry;
    if (!(entry = ldap_first_entry(ldap, res))) {
        PL_fail;
    }

    return PL_unify_pointer(entry_t, entry);
}

static foreign_t ldap4pl_next_entry(term_t ldap_t, term_t entry_t, term_t next_entry_t) {
    if (!PL_is_variable(next_entry_t)) {
        return PL_uninstantiation_error(next_entry_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* entry;
    if (!PL_get_pointer(entry_t, (void**) &entry)) {
        return PL_type_error("pointer", entry_t);
    }

    LDAPMessage* next_entry;
    if (!(next_entry = ldap_next_entry(ldap, entry))) {
        PL_fail;
    }

    return PL_unify_pointer(next_entry_t, next_entry);
}

static foreign_t ldap4pl_first_attribute(term_t ldap_t, term_t entry_t, term_t attribute_t, term_t ber_t) {
    if (!PL_is_variable(attribute_t)) {
        return PL_uninstantiation_error(attribute_t);
    }

    if (!PL_is_variable(ber_t)) {
        return PL_uninstantiation_error(ber_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* entry;
    if (!PL_get_pointer(entry_t, (void**) &entry)) {
        return PL_type_error("pointer", entry_t);
    }

    char* attribute;
    BerElement* ber;
    if (!(attribute = ldap_first_attribute(ldap, entry, &ber))) {
        PL_fail;
    }

    int result = PL_unify_atom_chars(attribute_t, attribute) & PL_unify_pointer(ber_t, ber);
    ldap_memfree(attribute);

    return result;
}

static foreign_t ldap4pl_next_attribute(term_t ldap_t, term_t entry_t, term_t attribute_t, term_t ber_t) {
    if (!PL_is_variable(attribute_t)) {
        return PL_uninstantiation_error(attribute_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* entry;
    if (!PL_get_pointer(entry_t, (void**) &entry)) {
        return PL_type_error("pointer", entry_t);
    }

    BerElement* ber;
    if (!PL_get_pointer(ber_t, (void**) &ber)) {
        return PL_type_error("pointer", ber_t);
    }

    char* attribute;
    if (!(attribute = ldap_next_attribute(ldap, entry, ber))) {
        PL_fail;
    }

    int result = PL_unify_atom_chars(attribute_t, attribute);
    ldap_memfree(attribute);

    return result;
}

static foreign_t ldap4pl_ber_free(term_t ber_t, term_t freebuf_t) {
    BerElement* ber;
    if (!PL_get_pointer(ber_t, (void**) &ber)) {
        return PL_type_error("pointer", ber_t);
    }

    int freebuf;
    if (!PL_get_bool(freebuf_t, &freebuf)) {
        return PL_type_error("bool", freebuf_t);
    }

    ber_free(ber, freebuf);
    PL_succeed;
}

// TODO: support binary values
static foreign_t ldap4pl_get_values(term_t ldap_t, term_t entry_t, term_t attribute_t, term_t values_t) {
    if (!PL_is_variable(values_t)) {
        return PL_uninstantiation_error(values_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* entry;
    if (!PL_get_pointer(entry_t, (void**) &entry)) {
        return PL_type_error("pointer", entry_t);
    }

    char* attribute;
    if (!PL_get_atom_chars(attribute_t, (char**) &attribute)) {
        return PL_type_error("pointer", attribute_t);
    }

    BerValue** bervals;
    if (!(bervals = ldap_get_values_len(ldap, entry, attribute))) {
        PL_fail;
    }

    int length = ldap_count_values_len(bervals);
    char** values = malloc(((length + 1) * sizeof (char*)));
    memset(values, 0, (length + 1) * sizeof (char*));
    for (int i = 0; i < length; ++i) {
        values[i] = bervals[i]->bv_val;
    }

    int result = build_chars_t_array(values, values_t);
    free(values);
    ldap_value_free_len(bervals);

    return result;
}

static foreign_t ldap4pl_get_dn(term_t ldap_t, term_t entry_t, term_t dn_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* entry;
    if (!PL_get_pointer(entry_t, (void**) &entry)) {
        return PL_type_error("pointer", entry_t);
    }

    char* dn;
    if (!(dn = ldap_get_dn(ldap, entry))) {
        PL_fail;
    }

    int result = PL_unify_atom_chars(dn_t, dn);
    ldap_memfree(dn);
    return result;
}

static foreign_t ldap4pl_parse_result(term_t ldap_t, term_t res_t, term_t errcode_t,
                                      term_t matcheddn_t, term_t errmsg_t, term_t referrals_t,
                                      term_t sctrls_t, term_t freeit_t) {
    if (!PL_is_variable(matcheddn_t)) {
        return PL_uninstantiation_error(matcheddn_t);
    }

    if (!PL_is_variable(errmsg_t)) {
        return PL_uninstantiation_error(errmsg_t);
    }

    if (!PL_is_variable(referrals_t)) {
        return PL_uninstantiation_error(referrals_t);
    }
    if (!PL_is_variable(sctrls_t)) {
        return PL_uninstantiation_error(sctrls_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* result;
    if (!PL_get_pointer(res_t, (void**) &result)) {
        return PL_type_error("pointer", res_t);
    }

    int freeit;
    if (!PL_get_bool(freeit_t, &freeit)) {
        return PL_type_error("bool", freeit_t);
    }

    int errcode;
    char* matcheddn = NULL;
    char* errmsg = NULL;
    char** referrals = NULL;
    LDAPControl** sctrls = NULL;
    if ((ld_errno = ldap_parse_result(ldap, result, &errcode,
                                      &matcheddn, &errmsg, &referrals,
                                      &sctrls, freeit)) != 0) {
        goto error;
    }

    if (!map_error_code(errcode, errcode_t)) {
        goto error;
    }

    if (matcheddn) {
        if (!PL_unify_atom_chars(matcheddn_t, matcheddn)) {
            goto error;
        }
    }

    if (errmsg) {
        if (!PL_unify_atom_chars(errmsg_t, errmsg)) {
            goto error;
        }
    }

    if (referrals) {
        if (!build_chars_t_array(referrals, referrals_t)) {
            goto error;
        }
    }

    if (sctrls) {
        if (!build_LDAPControl_t_array(sctrls, sctrls_t)) {
            goto error;
        }
    }

    ldap_memfree(matcheddn);
    ldap_memfree(errmsg);
    ldap_memvfree((void**) referrals);
    ldap_controls_free(sctrls);
    PL_succeed;

error:
    ldap_memfree(matcheddn);
    ldap_memfree(errmsg);
    ldap_memvfree((void**) referrals);
    ldap_controls_free(sctrls);
    PL_fail;
}

static foreign_t ldap4pl_err2string(term_t errcode_t, term_t errstring_t) {
    if (!PL_is_variable(errstring_t)) {
        return PL_uninstantiation_error(errstring_t);
    }

    atom_t errcode;
    if (!PL_get_atom(errcode_t, &errcode)) {
        return PL_type_error("atom", errcode_t);
    }

    int errcode_int;
    if (!map_error_code_atom(errcode, &errcode_int)) {
        PL_fail;
    }

    char* errstring;
    if (!(errstring = ldap_err2string(errcode_int))) {
        PL_fail;
    }

    return PL_unify_atom_chars(errstring_t, errstring);
}

static foreign_t ldap4pl_compare_ext(term_t ldap_t, term_t dn_t, term_t attribute_t, term_t berval_t,
                                     term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_compare_ext0(ldap_t, dn_t, attribute_t, berval_t, sctrls_t, cctrls_t, msgid_t, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_compare_ext_s(term_t ldap_t, term_t dn_t, term_t attribute_t, term_t berval_t,
                                       term_t sctrls_t, term_t cctrls_t, term_t res_t) {
    return ldap4pl_compare_ext0(ldap_t, dn_t, attribute_t, berval_t, sctrls_t, cctrls_t, (term_t) NULL, res_t, TRUE);
}

static foreign_t ldap4pl_compare(term_t ldap_t, term_t dn_t, term_t attribute_t, term_t value_t, term_t msgid_t) {
    return ldap4pl_compare0(ldap_t, dn_t, attribute_t, value_t,  msgid_t, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_compare_s(term_t ldap_t, term_t dn_t, term_t attribute_t, term_t value_t, term_t res_t) {
    return ldap4pl_compare0(ldap_t, dn_t, attribute_t, value_t, (term_t) NULL, res_t, TRUE);
}

static foreign_t ldap4pl_abandon_ext(term_t ldap_t, term_t msgid_t, term_t sctrls_t, term_t cctrls_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int msgid;
    if (!PL_get_integer(msgid_t, &msgid)) {
        return PL_type_error("number", msgid_t);
    }

    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls)) {
        PL_fail;
    }

    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls)) {
        free_LDAPControl_array(sctrls);
        PL_fail;
    }

    ld_errno = ldap_abandon_ext(ldap, msgid, sctrls, cctrls);

    free_LDAPControl_array(sctrls);
    free_LDAPControl_array(cctrls);

    return !ld_errno;
}

static foreign_t ldap4pl_add_ext(term_t ldap_t, term_t dn_t, term_t attrs_t,
                                 term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, attrs_t, sctrls_t, cctrls_t, msgid_t, FALSE, LDAP_MOD_ADD);
}

static foreign_t ldap4pl_add_ext_s(term_t ldap_t, term_t dn_t, term_t attrs_t,
                                   term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, attrs_t, sctrls_t, cctrls_t, (term_t) NULL, TRUE, LDAP_MOD_ADD);
}

static foreign_t ldap4pl_modify_ext(term_t ldap_t, term_t dn_t, term_t attrs_t,
                                 term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, attrs_t, sctrls_t, cctrls_t, msgid_t, FALSE, LDAP_MOD_REPLACE);
}

static foreign_t ldap4pl_modify_ext_s(term_t ldap_t, term_t dn_t, term_t attrs_t,
                                   term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, attrs_t, sctrls_t, cctrls_t, (term_t) NULL, TRUE, LDAP_MOD_REPLACE);
}

static foreign_t ldap4pl_delete_ext(term_t ldap_t, term_t dn_t,
                                 term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, (term_t) NULL, sctrls_t, cctrls_t, msgid_t, FALSE, LDAP_MOD_DELETE);
}

static foreign_t ldap4pl_delete_ext_s(term_t ldap_t, term_t dn_t,
                                   term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_update_ext0(ldap_t, dn_t, (term_t) NULL, sctrls_t, cctrls_t, (term_t) NULL, TRUE, LDAP_MOD_DELETE);
}

static foreign_t ldap4pl_modrdn(term_t ldap_t, term_t dn_t, term_t newrdn_t, term_t msgid_t) {
    return ldap4pl_modrdn0(ldap_t, dn_t, newrdn_t, msgid_t, FALSE);
}

static foreign_t ldap4pl_modrdn_s(term_t ldap_t, term_t dn_t, term_t newrdn_t) {
    return ldap4pl_modrdn0(ldap_t, dn_t, newrdn_t, (term_t) NULL, TRUE);
}

static foreign_t ldap4pl_modrdn2(term_t ldap_t, term_t dn_t, term_t newrdn_t, term_t deleteoldrdn_t, term_t msgid_t) {
    return ldap4pl_modrdn20(ldap_t, dn_t, newrdn_t, deleteoldrdn_t, msgid_t, FALSE);
}

static foreign_t ldap4pl_modrdn2_s(term_t ldap_t, term_t dn_t, term_t newrdn_t, term_t deleteoldrdn_t) {
    return ldap4pl_modrdn20(ldap_t, dn_t, newrdn_t, deleteoldrdn_t, (term_t) NULL, TRUE);
}

static foreign_t ldap4pl_rename(term_t ldap_t, term_t dn_t, term_t newrdn_t,
                                term_t newsuperior_t, term_t deleteoldrdn_t,
                                term_t sctrls_t, term_t cctrls_t,
                                term_t msgid_t) {
    return ldap4pl_rename0(ldap_t, dn_t, newrdn_t, newsuperior_t, deleteoldrdn_t, sctrls_t, cctrls_t, msgid_t, FALSE);
}

static foreign_t ldap4pl_rename_s(term_t ldap_t, term_t dn_t, term_t newrdn_t,
                                  term_t newsuperior_t, term_t deleteoldrdn_t,
                                  term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_rename0(ldap_t, dn_t, newrdn_t, newsuperior_t, deleteoldrdn_t, sctrls_t, cctrls_t, (term_t) NULL, TRUE);
}

static foreign_t ldap4pl_get_ld_errno(term_t ld_errno_t) {
    return map_error_code(ld_errno, ld_errno_t);
}

static foreign_t ldap4pl_extended_operation(term_t ldap_t, term_t requestoid_t, term_t requestdata_t,
                                            term_t sctrls_t, term_t cctrls_t, term_t msgid_t) {
    return ldap4pl_extended_operation0(ldap_t, requestoid_t, requestdata_t, sctrls_t, cctrls_t, msgid_t,
                                       (term_t) NULL, (term_t) NULL, FALSE);
}

static foreign_t ldap4pl_extended_operation_s(term_t ldap_t, term_t requestoid_t, term_t requestdata_t,
                                              term_t sctrls_t, term_t cctrls_t, term_t retoid_t,
                                              term_t retdata_t) {
    return ldap4pl_extended_operation0(ldap_t, requestoid_t, requestdata_t, sctrls_t, cctrls_t, (term_t) NULL,
                                       retoid_t, retdata_t, TRUE);
}

static foreign_t ldap4pl_is_ldap_url(term_t url_t) {
    char* url;
    if (!PL_get_atom_chars(url_t, &url)) {
        return PL_type_error("atom", url_t);
    }

    return ldap_is_ldap_url(url);
}

static foreign_t ldap4pl_url_parse(term_t url_t, term_t lud_t) {
    if (!PL_is_variable(lud_t)) {
        return PL_uninstantiation_error(lud_t);
    }

    char* url;
    if (!PL_get_atom_chars(url_t, &url)) {
        return PL_type_error("atom", url_t);
    }

    LDAPURLDesc* lud;
    int result = !(ld_errno = ldap_url_parse(url, &lud));
    int final_result = result && build_lud_t(lud, lud_t);
    if (result) {
        ldap_free_urldesc(lud);
    }
    return final_result;
}

static void init_constants() {
    ATOM_timeval = PL_new_atom("timeval");
    ATOM_tv_sec = PL_new_atom("tv_sec");
    ATOM_tv_usec = PL_new_atom("tv_usec");

    ATOM_ldapcontrol = PL_new_atom("ldapcontrol");
    ATOM_ldctl_oid = PL_new_atom("ldctl_oid");
    ATOM_ldctl_value = PL_new_atom("ldctl_value");
    ATOM_bv_len = PL_new_atom("bv_len");
    ATOM_bv_val = PL_new_atom("bv_val");
    ATOM_ldctl_iscritical = PL_new_atom("ldctl_iscritical");

    ATOM_berval = PL_new_atom("berval");

    ATOM_ldap_auth_none = PL_new_atom("ldap_auth_none");
    ATOM_ldap_auth_simple = PL_new_atom("ldap_auth_simple");
    ATOM_ldap_auth_sasl = PL_new_atom("ldap_auth_sasl");
    ATOM_ldap_auth_krbv4 = PL_new_atom("ldap_auth_krbv4");
    ATOM_ldap_auth_krbv41 = PL_new_atom("ldap_auth_krbv41");
    ATOM_ldap_auth_krbv42 = PL_new_atom("ldap_auth_krbv42");

    ATOM_ldap_opt_protocol_version = PL_new_atom("ldap_opt_protocol_version");
    ATOM_ldap_opt_deref = PL_new_atom("ldap_opt_deref");
    ATOM_ldap_opt_diagnostic_message = PL_new_atom("ldap_opt_diagnostic_message");
    ATOM_ldap_opt_matched_dn = PL_new_atom("ldap_opt_matched_dn");
    ATOM_ldap_opt_referral_urls = PL_new_atom("ldap_opt_referral_urls");
    ATOM_ldap_opt_referrals = PL_new_atom("ldap_opt_referrals");
    ATOM_ldap_opt_restart = PL_new_atom("ldap_opt_restart");
    ATOM_ldap_opt_result_code = PL_new_atom("ldap_opt_result_code");
    ATOM_ldap_opt_sizelimit = PL_new_atom("ldap_opt_sizelimit");
    ATOM_ldap_opt_timelimit = PL_new_atom("ldap_opt_timelimit");

    ATOM_ldap_deref_never = PL_new_atom("ldap_deref_never");
    ATOM_ldap_deref_searching = PL_new_atom("ldap_deref_searching");
    ATOM_ldap_deref_finding = PL_new_atom("ldap_deref_finding");
    ATOM_ldap_deref_always = PL_new_atom("ldap_deref_always");
    ATOM_ldap_opt_off = PL_new_atom("ldap_opt_off");
    ATOM_ldap_opt_on = PL_new_atom("ldap_opt_on");

    ATOM_ldap_res_bind = PL_new_atom("ldap_res_bind");
    ATOM_ldap_res_search_entry = PL_new_atom("ldap_res_search_entry");
    ATOM_ldap_res_search_reference = PL_new_atom("ldap_res_search_reference");
    ATOM_ldap_res_search_result = PL_new_atom("ldap_res_search_result");
    ATOM_ldap_res_modify = PL_new_atom("ldap_res_modify");
    ATOM_ldap_res_add = PL_new_atom("ldap_res_add");
    ATOM_ldap_res_delete = PL_new_atom("ldap_res_delete");
    ATOM_ldap_res_moddn = PL_new_atom("ldap_res_moddn");
    ATOM_ldap_res_compare = PL_new_atom("ldap_res_compare");
    ATOM_ldap_res_extended = PL_new_atom("ldap_res_extended");
    ATOM_ldap_res_intermediate = PL_new_atom("ldap_res_intermediate");

    ATOM_query = PL_new_atom("query");
    ATOM_base = PL_new_atom("base");
    ATOM_scope = PL_new_atom("scope");
    ATOM_filter = PL_new_atom("filter");
    ATOM_attrs = PL_new_atom("attrs");
    ATOM_attrsonly = PL_new_atom("attrsonly");
    ATOM_ldap_scope_base = PL_new_atom("ldap_scope_base");
    ATOM_ldap_scope_onelevel = PL_new_atom("ldap_scope_onelevel");
    ATOM_ldap_scope_subtree = PL_new_atom("ldap_scope_subtree");
    ATOM_ldap_scope_children = PL_new_atom("ldap_scope_children");

    ATOM_ldap_success = PL_new_atom("ldap_success");
    ATOM_ldap_operations_error = PL_new_atom("ldap_operations_error");
    ATOM_ldap_protocol_error = PL_new_atom("ldap_protocol_error");
    ATOM_ldap_timelimit_exceeded = PL_new_atom("ldap_timelimit_exceeded");
    ATOM_ldap_sizelimit_exceeded = PL_new_atom("ldap_sizelimit_exceeded");
    ATOM_ldap_compare_false = PL_new_atom("ldap_compare_false");
    ATOM_ldap_compare_true = PL_new_atom("ldap_compare_true");
    ATOM_ldap_strong_auth_not_supported = PL_new_atom("ldap_strong_auth_not_supported");
    ATOM_ldap_strong_auth_required = PL_new_atom("ldap_strong_auth_required");
    ATOM_ldap_partial_results = PL_new_atom("ldap_partial_results");
    ATOM_ldap_no_such_attribute = PL_new_atom("ldap_no_such_attribute");
    ATOM_ldap_undefined_type = PL_new_atom("ldap_undefined_type");
    ATOM_ldap_inappropriate_matching = PL_new_atom("ldap_inappropriate_matching");
    ATOM_ldap_constraint_violation = PL_new_atom("ldap_constraint_violation");
    ATOM_ldap_type_or_value_exists = PL_new_atom("ldap_type_or_value_exists");
    ATOM_ldap_invalid_syntax = PL_new_atom("ldap_invalid_syntax");
    ATOM_ldap_no_such_object = PL_new_atom("ldap_no_such_object");
    ATOM_ldap_alias_problem = PL_new_atom("ldap_alias_problem");
    ATOM_ldap_invalid_dn_syntax = PL_new_atom("ldap_invalid_dn_syntax");
    ATOM_ldap_is_leaf = PL_new_atom("ldap_is_leaf");
    ATOM_ldap_alias_deref_problem = PL_new_atom("ldap_alias_deref_problem");
    ATOM_ldap_inappropriate_auth = PL_new_atom("ldap_inappropriate_auth");
    ATOM_ldap_invalid_credentials = PL_new_atom("ldap_invalid_credentials");
    ATOM_ldap_insufficient_access = PL_new_atom("ldap_insufficient_access");
    ATOM_ldap_busy = PL_new_atom("ldap_busy");
    ATOM_ldap_unavailable = PL_new_atom("ldap_unavailable");
    ATOM_ldap_unwilling_to_perform = PL_new_atom("ldap_unwilling_to_perform");
    ATOM_ldap_loop_detect = PL_new_atom("ldap_loop_detect");
    ATOM_ldap_naming_violation = PL_new_atom("ldap_naming_violation");
    ATOM_ldap_object_class_violation = PL_new_atom("ldap_object_class_violation");
    ATOM_ldap_not_allowed_on_nonleaf = PL_new_atom("ldap_not_allowed_on_nonleaf");
    ATOM_ldap_not_allowed_on_rdn = PL_new_atom("ldap_not_allowed_on_rdn");
    ATOM_ldap_already_exists = PL_new_atom("ldap_already_exists");
    ATOM_ldap_no_object_class_mods = PL_new_atom("ldap_no_object_class_mods");
    ATOM_ldap_other = PL_new_atom("ldap_other");

    ATOM_ldapmod = PL_new_atom("ldapmod");
    ATOM_mod_op = PL_new_atom("mod_op");
    ATOM_mod_type = PL_new_atom("mod_type");
    ATOM_mod_bvalues = PL_new_atom("mod_bvalues");
    ATOM_mod_values = PL_new_atom("mod_values");
    ATOM_ldap_mod_op = PL_new_atom("ldap_mod_op");
    ATOM_ldap_mod_add = PL_new_atom("ldap_mod_add");
    ATOM_ldap_mod_delete = PL_new_atom("ldap_mod_delete");
    ATOM_ldap_mod_replace = PL_new_atom("ldap_mod_replace");
    ATOM_ldap_mod_bvalues = PL_new_atom("ldap_mod_bvalues");

    ATOM_lud = PL_new_atom("lud");
    ATOM_lud_scheme = PL_new_atom("lud_scheme");
    ATOM_lud_host = PL_new_atom("lud_host");
    ATOM_lud_port = PL_new_atom("lud_port");
    ATOM_lud_dn = PL_new_atom("lud_dn");
    ATOM_lud_attrs = PL_new_atom("lud_attrs");
    ATOM_lud_scope = PL_new_atom("lud_scope");
    ATOM_lud_filter = PL_new_atom("lud_filter");
    ATOM_lud_exts = PL_new_atom("lud_exts");
    ATOM_lud_crit_exts = PL_new_atom("lud_crit_exts");

    FUNCTOR_bv_len = PL_new_functor(ATOM_bv_len, 1);
    FUNCTOR_bv_val = PL_new_functor(ATOM_bv_val, 1);

    FUNCTOR_berval = PL_new_functor(ATOM_berval, 2);

    FUNCTOR_ldapcontrol = PL_new_functor(ATOM_ldapcontrol, 3);
    FUNCTOR_ldctl_oid = PL_new_functor(ATOM_ldctl_oid, 1);
    FUNCTOR_ldctl_value = PL_new_functor(ATOM_ldctl_value, 2);
    FUNCTOR_ldctl_iscritical = PL_new_functor(ATOM_ldctl_iscritical, 1);

    FUNCTOR_lud = PL_new_functor(ATOM_lud, 9);
    FUNCTOR_lud_scheme = PL_new_functor(ATOM_lud_scheme, 1);
    FUNCTOR_lud_host = PL_new_functor(ATOM_lud_host, 1);
    FUNCTOR_lud_port = PL_new_functor(ATOM_lud_port, 1);
    FUNCTOR_lud_dn = PL_new_functor(ATOM_lud_dn, 1);
    FUNCTOR_lud_attrs = PL_new_functor(ATOM_lud_attrs, 1);
    FUNCTOR_lud_scope = PL_new_functor(ATOM_lud_scope, 1);
    FUNCTOR_lud_filter = PL_new_functor(ATOM_lud_filter, 1);
    FUNCTOR_lud_exts = PL_new_functor(ATOM_lud_exts, 1);
    FUNCTOR_lud_crit_exts = PL_new_functor(ATOM_lud_crit_exts, 1);
}

install_t install_ldap4pl() {
    init_constants();

    PL_register_foreign("ldap4pl_initialize", 2, ldap4pl_initialize, 0);
    PL_register_foreign("ldap4pl_unbind", 1, ldap4pl_unbind, 0);
    PL_register_foreign("ldap4pl_unbind_ext", 4, ldap4pl_unbind_ext, 0);
    PL_register_foreign("ldap4pl_bind", 5, ldap4pl_bind, 0);
    PL_register_foreign("ldap4pl_bind_s", 4, ldap4pl_bind_s, 0);
    PL_register_foreign("ldap4pl_simple_bind", 4, ldap4pl_simple_bind, 0);
    PL_register_foreign("ldap4pl_simple_bind_s", 3, ldap4pl_simple_bind_s, 0);
    PL_register_foreign("ldap4pl_sasl_bind", 7, ldap4pl_sasl_bind, 0);
    PL_register_foreign("ldap4pl_sasl_bind_s", 7, ldap4pl_sasl_bind_s, 0);
    PL_register_foreign("ldap4pl_parse_sasl_bind_result", 4, ldap4pl_parse_sasl_bind_result, 0);
    PL_register_foreign("ldap4pl_set_option", 3, ldap4pl_set_option, 0);
    PL_register_foreign("ldap4pl_get_option", 3, ldap4pl_get_option, 0);
    PL_register_foreign("ldap4pl_result", 5, ldap4pl_result, 0);
    PL_register_foreign("ldap4pl_msgfree", 1, ldap4pl_msgfree, 0);
    PL_register_foreign("ldap4pl_msgtype", 2, ldap4pl_msgtype, 0);
    PL_register_foreign("ldap4pl_msgid", 2, ldap4pl_msgid, 0);
    PL_register_foreign("ldap4pl_search_ext", 7, ldap4pl_search_ext, 0);
    PL_register_foreign("ldap4pl_search_ext_s", 7, ldap4pl_search_ext_s, 0);
    PL_register_foreign("ldap4pl_search", 4, ldap4pl_search, 0);
    PL_register_foreign("ldap4pl_search_s", 4, ldap4pl_search_s, 0);
    PL_register_foreign("ldap4pl_count_entries", 3, ldap4pl_count_entries, 0);
    PL_register_foreign("ldap4pl_first_entry", 3, ldap4pl_first_entry, 0);
    PL_register_foreign("ldap4pl_next_entry", 3, ldap4pl_next_entry, 0);
    PL_register_foreign("ldap4pl_first_attribute", 4, ldap4pl_first_attribute, 0);
    PL_register_foreign("ldap4pl_next_attribute", 4, ldap4pl_next_attribute, 0);
    PL_register_foreign("ldap4pl_ber_free", 2, ldap4pl_ber_free, 0);
    PL_register_foreign("ldap4pl_get_values", 4, ldap4pl_get_values, 0);
    PL_register_foreign("ldap4pl_get_dn", 3, ldap4pl_get_dn, 0);
    PL_register_foreign("ldap4pl_parse_result", 8, ldap4pl_parse_result, 0);
    PL_register_foreign("ldap4pl_err2string", 2, ldap4pl_err2string, 0);
    PL_register_foreign("ldap4pl_compare_ext", 7, ldap4pl_compare_ext, 0);
    PL_register_foreign("ldap4pl_compare_ext_s", 7, ldap4pl_compare_ext_s, 0);
    PL_register_foreign("ldap4pl_compare", 5, ldap4pl_compare, 0);
    PL_register_foreign("ldap4pl_compare_s", 5, ldap4pl_compare_s, 0);
    PL_register_foreign("ldap4pl_abandon_ext", 4, ldap4pl_abandon_ext, 0);
    PL_register_foreign("ldap4pl_add_ext", 6, ldap4pl_add_ext, 0);
    PL_register_foreign("ldap4pl_add_ext_s", 5, ldap4pl_add_ext_s, 0);
    PL_register_foreign("ldap4pl_modify_ext", 6, ldap4pl_modify_ext, 0);
    PL_register_foreign("ldap4pl_modify_ext_s", 5, ldap4pl_modify_ext_s, 0);
    PL_register_foreign("ldap4pl_delete_ext", 5, ldap4pl_delete_ext, 0);
    PL_register_foreign("ldap4pl_delete_ext_s", 4, ldap4pl_delete_ext_s, 0);
    PL_register_foreign("ldap4pl_modrdn", 4, ldap4pl_modrdn, 0);
    PL_register_foreign("ldap4pl_modrdn_s", 3, ldap4pl_modrdn_s, 0);
    PL_register_foreign("ldap4pl_modrdn2", 5, ldap4pl_modrdn2, 0);
    PL_register_foreign("ldap4pl_modrdn2_s", 4, ldap4pl_modrdn2_s, 0);
    PL_register_foreign("ldap4pl_rename", 8, ldap4pl_rename, 0);
    PL_register_foreign("ldap4pl_rename_s", 7, ldap4pl_rename_s, 0);
    PL_register_foreign("ldap4pl_get_ld_errno", 1, ldap4pl_get_ld_errno, 0);
    PL_register_foreign("ldap4pl_extended_operation", 6, ldap4pl_extended_operation, 0);
    PL_register_foreign("ldap4pl_extended_operation_s", 7, ldap4pl_extended_operation_s, 0);
    PL_register_foreign("ldap4pl_is_ldap_url", 1, ldap4pl_is_ldap_url, 0);
    PL_register_foreign("ldap4pl_url_parse", 2, ldap4pl_url_parse, 0);
}
