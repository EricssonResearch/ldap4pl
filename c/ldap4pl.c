#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <ldap.h>
#include <string.h>

#ifdef O_DEBUG
#define DEBUG(g) g
#else
#define DEBUG(g)
#endif

static atom_t ATOM_ldapcontrol;
static atom_t ATOM_ldctl_oid;
static atom_t ATOM_berval;
static atom_t ATOM_bv_len;
static atom_t ATOM_bv_val;
static atom_t ATOM_ldctl_iscritical;

static atom_t ATOM_ldap_auth_none;
static atom_t ATOM_ldap_auth_simple;
static atom_t ATOM_ldap_auth_sasl;
static atom_t ATOM_ldap_auth_krbv4;
static atom_t ATOM_ldap_auth_krbv41;
static atom_t ATOM_ldap_auth_krbv42;

static atom_t ATOM_ldap_opt_protocol_version;

void free_LDAPControl_array(LDAPControl** array, int size) {
    for (int i = 0; i < size; ++i) {
        free(array[i]);
    }
    free(array);
}

int get_list_size(term_t list) {
    int size = 0;
    term_t tail = PL_copy_term_ref(list);
    term_t head = PL_new_term_ref();
    while (PL_get_list(tail, head, tail)) {
        ++size;
    }
    if (!PL_get_nil(tail)) {
        return PL_type_error("list", tail);
    }
    return size;
}

/*
 * berval(bv_len(12), bv_val(atom))
 */
BerValue* build_BerValue(term_t berval_t) {
    BerValue* berval = malloc(sizeof (BerValue));
    memset(berval, 0, sizeof (BerValue));

    atom_t name_t;
    int arity;
    if (!PL_get_compound_name_arity(berval_t, &name_t, &arity)) {
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
            berval->bv_len = bv_len;
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
            berval->bv_val = bv_val;
        }
    }

    return berval;

error:
    free(berval);
    return NULL;
}

/*
 * berval(bv_len(12), bv_val(atom))
 */
int build_BerValue_for_LDAPControl(term_t berval_t, LDAPControl* ctrl) {
    atom_t name_t;
    int arity;
    if (!PL_get_compound_name_arity(berval_t, &name_t, &arity)) {
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
LDAPControl* build_LDAPControl(term_t ctrl_t) {
    LDAPControl* ctrl = malloc(sizeof (LDAPControl));
    memset(ctrl, 0, sizeof (LDAPControl));

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
            ctrl->ldctl_oid = ldctl_oid;
        } else if (arg_name == ATOM_berval) {
            if (!build_BerValue_for_LDAPControl(arg_t, ctrl)) {
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
            ctrl->ldctl_iscritical = ldctl_iscritical[0];
        }
    }

    return ctrl;

error:
    free(ctrl);
    return NULL;
}

LDAPControl** build_LDAPControl_array(term_t ctrls_t, int* size) {
    *size = get_list_size(ctrls_t);
    if (!*size) {
        return NULL;
    }

    LDAPControl** array = malloc(*size * sizeof (LDAPControl*));
    memset(array, 0, sizeof (LDAPControl*) * (*size));

    term_t tail = PL_copy_term_ref(ctrls_t);
    term_t head = PL_new_term_ref();
    int i = 0;
    while (PL_get_list(tail, head, tail)) {
        array[i++] = build_LDAPControl(head);
    }
    if (!PL_get_nil(tail)) {
        PL_type_error("list", tail);
        return NULL;
    }

    return array;
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

int ldap4pl_unbind_ext0(term_t ldap_t, term_t sctrls_t, term_t cctrls_t, term_t msgid_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int sctrls_size;
    int cctrls_size;
    LDAPControl** sctrls = build_LDAPControl_array(sctrls_t, &sctrls_size);
    LDAPControl** cctrls = build_LDAPControl_array(cctrls_t, &cctrls_size);
    if ((!sctrls && sctrls_size) || (!cctrls && cctrls_size)) {
        if (sctrls) {
            free_LDAPControl_array(sctrls, sctrls_size);
        }
        if (cctrls) {
            free_LDAPControl_array(cctrls, cctrls_size);
        }
        return FALSE;
    }

    int result = !synchronous? ldap_unbind_ext(ldap, sctrls, cctrls) : !ldap_unbind_ext_s(ldap, sctrls, cctrls);

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

    int result = !synchronous? ldap_bind(ldap, who, cred, method_int) : !ldap_bind_s(ldap, who, cred, method_int);
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

    int result = !synchronous? ldap_simple_bind(ldap, who, passwd) : !ldap_simple_bind_s(ldap, who, passwd);
    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, result);
    } else {
        return result;
    }
}

int ldap4pl_sasl_bind0(term_t ldap_t, term_t dn_t, term_t mechanism_t,
                       term_t cred_t, term_t sctrls_t, term_t cctrls_t,
                       term_t msgid_t, term_t servercredp_t, int synchronous) {
    if (!synchronous && !PL_is_variable(msgid_t)) {
        return PL_uninstantiation_error(msgid_t);
    }

    if (synchronous && !PL_is_variable(servercredp_t)) {
        return PL_uninstantiation_error(servercredp_t);
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

    BerValue* cred = build_BerValue(cred_t);
    if (!cred) {
        return FALSE;
    }
    
    int sctrls_size;
    int cctrls_size;
    LDAPControl** sctrls = build_LDAPControl_array(sctrls_t, &sctrls_size);
    LDAPControl** cctrls = build_LDAPControl_array(cctrls_t, &cctrls_size);
    if ((!sctrls && sctrls_size) || (!cctrls && cctrls_size)) {
        if (sctrls) {
            free_LDAPControl_array(sctrls, sctrls_size);
        }
        if (cctrls) {
            free_LDAPControl_array(cctrls, cctrls_size);
        }
        free(cred);
        return FALSE;
    }

    int msgid;
    BerValue* servercredp;
    int result = !synchronous?
        !ldap_sasl_bind(ldap, dn, mechanism, cred, sctrls, cctrls, &msgid) :
        !ldap_sasl_bind_s(ldap, dn, mechanism, cred, sctrls, cctrls, &servercredp);

    free_LDAPControl_array(sctrls, sctrls_size);
    free_LDAPControl_array(cctrls, cctrls_size);
    free(cred);

    if (!synchronous) {
        return result & PL_unify_integer(msgid_t, msgid);
    } else {
        return result & PL_unify_pointer(servercredp_t, servercredp);
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
    int cctrls_size;
    LDAPControl** sctrls = build_LDAPControl_array(sctrls_t, &sctrls_size);
    LDAPControl** cctrls = build_LDAPControl_array(cctrls_t, &cctrls_size);
    if ((!sctrls && sctrls_size) || (!cctrls && cctrls_size)) {
        if (sctrls) {
            free_LDAPControl_array(sctrls, sctrls_size);
        }
        if (cctrls) {
            free_LDAPControl_array(cctrls, cctrls_size);
        }
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
                                     term_t cred_t, term_t sctrls_t, term_t cctrls_t, term_t servercredp_t) {
    return ldap4pl_sasl_bind0(ldap_t, dn_t, mechanism_t, cred_t, sctrls_t, cctrls_t, (term_t) NULL, servercredp_t, TRUE);
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

static foreign_t ldap4pl_get_option(term_t ldap_t, term_t option_t, term_t outvalue_t) {
    if (!PL_is_variable(outvalue_t)) {
        return PL_uninstantiation_error(outvalue_t);
    }

    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    int option;
    if (!PL_get_integer(option_t, &option)) {
        return PL_type_error("number", option_t);
    }

    return TRUE;
}

static void init_constants() {
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
}
