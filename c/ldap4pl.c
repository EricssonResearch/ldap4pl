#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <ldap.h>
#include <string.h>

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
static atom_t ATOM_berval;
static atom_t ATOM_bv_len;
static atom_t ATOM_bv_val;
static atom_t ATOM_ldctl_iscritical;

static functor_t FUNCTOR_berval;
static functor_t FUNCTOR_bv_len;
static functor_t FUNCTOR_bv_val;

static atom_t ATOM_ldap_auth_none;
static atom_t ATOM_ldap_auth_simple;
static atom_t ATOM_ldap_auth_sasl;
static atom_t ATOM_ldap_auth_krbv4;
static atom_t ATOM_ldap_auth_krbv41;
static atom_t ATOM_ldap_auth_krbv42;

static atom_t ATOM_ldap_opt_protocol_version;

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
    return TRUE;
}

int map_option(atom_t option, int* option_int) {
    int result = TRUE;
    if (option == ATOM_ldap_opt_protocol_version) {
        *option_int = LDAP_OPT_PROTOCOL_VERSION;
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
        return FALSE;
    }
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
    int arity;
    if (!PL_get_compound_name_arity(berval_t, &name, &arity)) {
        PL_type_error("compound", berval_t);
        goto error;
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, berval_t, arg_t)) {
            PL_type_error("compound", berval_t);
            goto error;
        }

        atom_t arg_name;
        int arity1;
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
    return TRUE;

error:
    free(_berval);
    return FALSE;
}

int build_BerValue_t(BerValue* berval, term_t berval_t) {
    term_t bv_len_t = PL_new_term_ref();
    if (!PL_unify_term(bv_len_t, PL_FUNCTOR, FUNCTOR_bv_len, PL_LONG, berval->bv_len)) {
        return FALSE;
    }
    term_t bv_val_t = PL_new_term_ref();
    if (!PL_unify_term(bv_val_t, PL_FUNCTOR, FUNCTOR_bv_val, PL_CHARS, berval->bv_val)) {
        return FALSE;
    }

    return PL_unify_term(berval_t, PL_FUNCTOR, FUNCTOR_berval, PL_TERM, bv_len_t, PL_TERM, bv_val_t);
}

/*
 * berval(bv_len(12), bv_val(atom))
 */
int build_BerValue_for_LDAPControl(term_t berval_t, LDAPControl* ctrl) {
    atom_t name;
    int arity;
    if (!PL_get_compound_name_arity(berval_t, &name, &arity)) {
        return PL_type_error("compound", berval_t);
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, berval_t, arg_t)) {
            return PL_type_error("compound", berval_t);
        }

        atom_t arg_name;
        int arity1;
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

    return TRUE;
}

/*
 * ldapcontrol(
 *   ldctl_oid(atom),
 *   berval(bv_len(12), bv_val(atom)),
 *   ldctl_iscritical(c)
 * )
 */
int build_LDAPControl(term_t ctrl_t, LDAPControl** ctrl) {
    LDAPControl* _ctrl = malloc(sizeof (LDAPControl));
    memset(_ctrl, 0, sizeof (LDAPControl));

    atom_t name;
    int arity;
    if (!PL_get_compound_name_arity(ctrl_t, &name, &arity)) {
        PL_type_error("compound", ctrl_t);
        goto error;
    }

    if (name != ATOM_ldapcontrol) {
        PL_domain_error(PL_atom_chars(name), name);
        goto error;
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, ctrl_t, arg_t)) {
            PL_type_error("compound", ctrl_t);
            goto error;
        }

        atom_t arg_name;
        int arity1;
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
        } else if (arg_name == ATOM_berval) {
            if (!build_BerValue_for_LDAPControl(arg_t, _ctrl)) {
                goto error;
            }
        } else if (arg_name == ATOM_ldctl_iscritical) {
            term_t ldctl_iscritical_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, ldctl_iscritical_t)) {
                PL_type_error("compound", arg_t);
                goto error;
            }

            char* ldctl_iscritical;
            if (!PL_get_atom_chars(ldctl_iscritical_t, &ldctl_iscritical)) {
                PL_type_error("atom", ldctl_iscritical_t);
                goto error;
            }
            _ctrl->ldctl_iscritical = ldctl_iscritical[0];
        }
    }

    *ctrl = _ctrl;
    return TRUE;

error:
    free(ctrl);
    return FALSE;
}

void free_LDAPControl_array(LDAPControl** array, int size) {
    if (size) {
        for (int i = 0; i < size; ++i) {
            free(array[i]);
        }
        free(array);
    }
}

int build_LDAPControl_array(term_t ctrls_t, LDAPControl*** array, int* size) {
    if (!get_list_size(ctrls_t, size)) {
        return FALSE;
    }

    if (*size == 0) {
        return TRUE;
    }

    LDAPControl** _array = malloc(*size * sizeof (LDAPControl*));
    memset(_array, 0, sizeof (LDAPControl*) * (*size));

    term_t tail = PL_copy_term_ref(ctrls_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!build_LDAPControl(head, &_array[i++])) {
            free_LDAPControl_array(_array, i - 1);
            return FALSE;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }

    *array = _array;
    return TRUE;
}

/*
 * timeval(tv_sec(100), tv_usec(100))
 */
int build_timeval(term_t timeval_t, TimeVal** timeval) {
    TimeVal* _timeval = malloc(sizeof (TimeVal));
    memset(_timeval, 0, sizeof (TimeVal));

    atom_t name;
    int arity;
    if (!PL_get_compound_name_arity(timeval_t, &name, &arity)) {
        PL_type_error("compound", timeval_t);
        goto error;
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, timeval_t, arg_t)) {
            PL_type_error("compound", timeval_t);
            goto error;
        }

        atom_t arg_name;
        int arity1;
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
            if (!PL_get_integer(tv_usec_t, &tv_usec)) {
                PL_type_error("number", tv_usec_t);
                goto error;
            }
            _timeval->tv_usec = tv_usec;
        }
    }

    *timeval = _timeval;
    return TRUE;

error:
    free(_timeval);
    return FALSE;
}

int build_chars_array(term_t array_t, char*** array) {
    int _size;
    if (!get_list_size(array_t, &_size)) {
        return FALSE;
    }

    if (_size == 0) {
        return TRUE;
    }

    int size = _size + 1;

    char** _array = malloc(size * sizeof (char*));
    memset(_array, 0, sizeof (char*) * size);

    term_t tail = PL_copy_term_ref(array_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        if (!PL_get_atom_chars(head, &_array[i++])) {
            free(_array);
            return FALSE;
        }
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    _array[i] = NULL;
    
    *array = _array;
    return TRUE;
}

/*
 * query(base(), scope(), filter(), attrs([]), attrsonly())
 */
int build_query_conditions(term_t query_t, char** base, int* scope, char** filter, char*** attrs, int* attrsonly) {
    atom_t name;
    int arity;
    if (!PL_get_compound_name_arity(query_t, &name, &arity)) {
        PL_type_error("compound", query_t);
        goto error;
    }

    if (name != ATOM_query) {
        PL_domain_error(PL_atom_chars(name), name);
        goto error;
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, query_t, arg_t)) {
            PL_type_error("compound", query_t);
            goto error;
        }

        atom_t arg_name;
        int arity1;
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
                if (!build_chars_array(attrs_t, attrs)) {
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

    return TRUE;

error:
    free(*attrs);
    return FALSE;
}

int ldap4pl_unbind_ext0(term_t ldap_t, term_t sctrls_t, term_t cctrls_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int sctrls_size;
    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls, &sctrls_size)) {
        return FALSE;
    }

    int cctrls_size;
    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls, &cctrls_size)) {
        free_LDAPControl_array(sctrls, sctrls_size);
        return FALSE;
    }

    int result = !synchronous ? ldap_unbind_ext(ldap, sctrls, cctrls) : !ldap_unbind_ext_s(ldap, sctrls, cctrls);

    free_LDAPControl_array(sctrls, sctrls_size);
    free_LDAPControl_array(cctrls, cctrls_size);

    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, result);
    } else {
        return result;
    }
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

    int result = !synchronous ? ldap_bind(ldap, who, cred, method_int) : !ldap_bind_s(ldap, who, cred, method_int);
    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, result);
    } else {
        return result;
    }
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

    int result = !synchronous ? ldap_simple_bind(ldap, who, passwd) : !ldap_simple_bind_s(ldap, who, passwd);
    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, result);
    } else {
        return result;
    }
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
        return FALSE;
    }
    
    int sctrls_size;
    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls, &sctrls_size)) {
        return FALSE;
    }

    int cctrls_size;
    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls, &cctrls_size)) {
        free_LDAPControl_array(sctrls, sctrls_size);
        free(cred);
        return FALSE;
    }

    int msgid;
    BerValue* servercred;
    int result = !synchronous ?
        !ldap_sasl_bind(ldap, dn, mechanism, cred, sctrls, cctrls, &msgid) :
        !ldap_sasl_bind_s(ldap, dn, mechanism, cred, sctrls, cctrls, &servercred);

    free_LDAPControl_array(sctrls, sctrls_size);
    free_LDAPControl_array(cctrls, cctrls_size);
    free(cred);

    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, msgid);
    } else {
        int final_result = result & build_BerValue_t(servercred, servercred_t);
        if (result) {
            ber_bvfree(servercred);
        }
        return final_result;
    }
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
        return FALSE;
    }

    if (!base) {
        free(attrs);
        return PL_domain_error("base is missing", query_t);
    }

    if (attrsonly == -1) {
        free(attrs);
        return PL_domain_error("attrsonly is missing", query_t);
    }

    int sctrls_size;
    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls, &sctrls_size)) {
        free(attrs);
        return FALSE;
    }

    int cctrls_size;
    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls, &cctrls_size)) {
        free_LDAPControl_array(sctrls, sctrls_size);
        free(attrs);
        return FALSE;
    }

    TimeVal* timeout = NULL;
    if (!PL_is_variable(timeout_t)) {
        if (!build_timeval(timeout_t, &timeout)) {
            free_LDAPControl_array(cctrls, cctrls_size);
            free_LDAPControl_array(sctrls, sctrls_size);
            free(attrs);
            return FALSE;
        }
        free(timeout);
    }

    int sizelimit;
    if (!PL_get_integer(sizelimit_t, &sizelimit)) {
        free_LDAPControl_array(cctrls, cctrls_size);
        free_LDAPControl_array(sctrls, sctrls_size);
        free(timeout);
        free(attrs);
        return PL_type_error("atom", sizelimit_t);
    }

    int msgid;
    LDAPMessage* res;
    int result = !synchronous ?
        !ldap_search_ext(ldap, base, scope, filter, attrs, attrsonly, sctrls, cctrls, timeout, sizelimit, &msgid) :
        !ldap_search_ext_s(ldap, base, scope, filter, attrs, attrsonly, sctrls, cctrls, timeout, sizelimit, &res);

    free_LDAPControl_array(sctrls, sctrls_size);
    free_LDAPControl_array(cctrls, cctrls_size);
    free(timeout);
    free(attrs);

    return result & (!synchronous ? PL_unify_integer(msgid_t, msgid) : PL_unify_pointer(res_t, res));
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
    if (ldap_initialize(&ldap, uri)) {
        return FALSE;
    }

    return PL_unify_pointer(ldap_t, ldap);
}

static foreign_t ldap4pl_unbind(term_t ldap_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    return !ldap_unbind(ldap);
}

static foreign_t ldap4pl_unbind_ext(term_t ldap_t, term_t sctrls_t, term_t cctrls_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int sctrls_size;
    LDAPControl** sctrls = NULL;
    if (!build_LDAPControl_array(sctrls_t, &sctrls, &sctrls_size)) {
        return FALSE;
    }

    int cctrls_size;
    LDAPControl** cctrls = NULL;
    if (!build_LDAPControl_array(cctrls_t, &cctrls, &cctrls_size)) {
        free_LDAPControl_array(sctrls, sctrls_size);
        return FALSE;
    }

    int result = ldap_unbind_ext(ldap, sctrls, cctrls);

    free_LDAPControl_array(sctrls, sctrls_size);
    free_LDAPControl_array(cctrls, cctrls_size);

    return result;
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

static foreign_t ldap4pl_parse_sasl_bind_result(term_t ldap_t, term_t msg_t, term_t servercred_t, term_t freeit_t) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    int freeit;
    if (!PL_get_bool(freeit_t, &freeit)) {
        return PL_type_error("bool", freeit_t);
    }

    BerValue* servercred;
    if (!ldap_parse_sasl_bind_result(ldap, msg, &servercred, freeit)) {
        return FALSE;
    }

    int result = build_BerValue_t(servercred, servercred_t);
    ber_bvfree(servercred);
    return result;
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

    if (PL_is_atom(invalue_t)) {
        char* invalue;
        if (PL_get_atom_chars(invalue_t, &invalue)) {
            return !ldap_set_option(ldap, option, &invalue);
        }
    }

    if (PL_is_integer(invalue_t)) {
        int invalue;
        if (PL_get_integer(invalue_t, &invalue)) {
            int r = ldap_set_option(ldap, option_int, &invalue);
            return !r;
        }
    }

    if (PL_is_float(invalue_t)) {
        double invalue;
        if (PL_get_float(invalue_t, &invalue)) {
            return !ldap_set_option(ldap, option, &invalue);
        }
    }

    return FALSE;
}

// TODO: implement
static foreign_t ldap4pl_get_option(term_t ldap_t, term_t option_t, term_t outvalue_t) {
    return TRUE;
}

static foreign_t ldap4pl_result(term_t ldap_t, term_t msgid_t, term_t all_t, term_t timeout_t, term_t result_t) {
    if (!PL_is_variable(result_t)) {
        return PL_uninstantiation_error(result_t);
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
            return FALSE;
        }
    } else {
        TimeVal* timeout;
        if (!build_timeval(timeout_t, &timeout)) {
            return FALSE;
        }

        if (ldap_result(ldap, msgid, all, timeout, &result) <= 0) {
            free(timeout);
            return FALSE;
        }
        free(timeout);
    }

    return PL_unify_pointer(result_t, result);
}

static foreign_t ldap4pl_msgfree(term_t msg_t) {
    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    return ldap_msgfree(msg) == -1 ? FALSE : TRUE;
}

static foreign_t ldap4pl_msgtype(term_t msg_t, term_t type_t) {
    LDAPMessage* msg;
    if (!PL_get_pointer(msg_t, (void**) &msg)) {
        return PL_type_error("pointer", msg_t);
    }

    int result;
    if ((result = ldap_msgtype(msg)) == -1) {
        return FALSE;
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
        return FALSE;
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

static foreign_t ldap4pl_count_entries(term_t ldap_t, term_t res_t, term_t count_t) {
    if (!PL_is_variable(count_t)) {
        return PL_uninstantiation_error(count_t);
    }

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
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
    return TRUE;
}

static void init_constants() {
    ATOM_timeval = PL_new_atom("timeval");
    ATOM_tv_sec = PL_new_atom("tv_sec");
    ATOM_tv_usec = PL_new_atom("tv_usec");

    ATOM_ldapcontrol = PL_new_atom("ldapcontrol");
    ATOM_ldctl_oid = PL_new_atom("ldctl_oid");
    ATOM_berval = PL_new_atom("berval");
    ATOM_bv_len = PL_new_atom("bv_len");
    ATOM_bv_val = PL_new_atom("bv_val");
    ATOM_ldctl_iscritical = PL_new_atom("ldctl_iscritical");

    ATOM_ldap_auth_none = PL_new_atom("ldap_auth_none");
    ATOM_ldap_auth_simple = PL_new_atom("ldap_auth_simple");
    ATOM_ldap_auth_sasl = PL_new_atom("ldap_auth_sasl");
    ATOM_ldap_auth_krbv4 = PL_new_atom("ldap_auth_krbv4");
    ATOM_ldap_auth_krbv41 = PL_new_atom("ldap_auth_krbv41");
    ATOM_ldap_auth_krbv42 = PL_new_atom("ldap_auth_krbv42");

    ATOM_ldap_opt_protocol_version = PL_new_atom("ldap_opt_protocol_version");

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

    FUNCTOR_berval = PL_new_functor(ATOM_berval, 2);
    FUNCTOR_bv_len = PL_new_functor(ATOM_bv_len, 1);
    FUNCTOR_bv_val = PL_new_functor(ATOM_bv_val, 1);
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
    PL_register_foreign("ldap4pl_set_option", 3, ldap4pl_set_option, 0);
    PL_register_foreign("ldap4pl_get_option", 3, ldap4pl_get_option, 0);
    PL_register_foreign("ldap4pl_result", 5, ldap4pl_result, 0);
    PL_register_foreign("ldap4pl_msgfree", 1, ldap4pl_msgfree, 0);
    PL_register_foreign("ldap4pl_msgtype", 2, ldap4pl_msgtype, 0);
    PL_register_foreign("ldap4pl_msgid", 2, ldap4pl_msgid, 0);
    PL_register_foreign("ldap4pl_search_ext", 7, ldap4pl_search_ext, 0);
    PL_register_foreign("ldap4pl_search_ext_s", 7, ldap4pl_search_ext_s, 0);
    PL_register_foreign("ldap4pl_count_entries", 3, ldap4pl_count_entries, 0);
    PL_register_foreign("ldap4pl_first_entry", 3, ldap4pl_first_entry, 0);
    PL_register_foreign("ldap4pl_next_entry", 3, ldap4pl_next_entry, 0);
    PL_register_foreign("ldap4pl_first_attribute", 4, ldap4pl_first_attribute, 0);
    PL_register_foreign("ldap4pl_next_attribute", 4, ldap4pl_next_attribute, 0);
    PL_register_foreign("ldap4pl_ber_free", 2, ldap4pl_ber_free, 0);
}
