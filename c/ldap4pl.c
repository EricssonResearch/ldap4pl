#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <ldap.h>
#include <string.h>

#ifdef O_DEBUG
#define DEBUG(g) g
#else
#define DEBUG(g)
#endif

#define LDAPCONTROL "ldapcontrol"
#define LDCTL_OID "ldctl_oid"
#define BERVAL "berval"
#define BV_LEN "bv_len"
#define BV_VAL "bv_val"
#define LDCTL_ISCRITICAL "ldctl_iscritical"

#define AUTH_NONE "auth_none"
#define AUTH_SIMPLE "auth_simple"
#define AUTH_SASL "auth_sasl"
#define AUTH_KRBV4 "auth_krbv4"
#define AUTH_KRBV41 "auth_krbv41"
#define AUTH_KRBV42 "auth_krbv42"

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

        atom_t arg_name_t;
        int arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name_t, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        const char* arg_name = PL_atom_chars(arg_name_t);

        if (!strcmp(arg_name, BV_LEN)) {
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
        } else if (!strcmp(arg_name, BV_VAL)) {
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

        atom_t arg_name_t;
        int arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name_t, &arity1)) {
            return PL_type_error("compound", arg_t);
        }

        const char* arg_name = PL_atom_chars(arg_name_t);

        if (!strcmp(arg_name, BV_LEN)) {
            term_t bv_len_t = PL_new_term_ref();
            if (!PL_get_arg(1, arg_t, bv_len_t)) {
                return PL_type_error("compound", arg_t);
            }

            long bv_len;
            if (!PL_get_long(bv_len_t, &bv_len)) {
                return PL_type_error("number", bv_len_t);
            }
            ctrl->ldctl_value.bv_len = bv_len;
        } else if (!strcmp(arg_name, BV_VAL)) {
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
    memset(ctrl, 0, sizeof (LDAPCONTROL));

    atom_t name_t;
    int arity;
    if (!PL_get_compound_name_arity(ctrl_t, &name_t, &arity)) {
        PL_type_error("compound", ctrl_t);
        goto error;
    }

    const char* name = PL_atom_chars(name_t);
    if (strcmp(name, LDAPCONTROL)) {
        PL_domain_error(LDAPCONTROL, name_t);
        goto error;
    }

    for (int i = 1; i <= arity; ++i) {
        term_t arg_t = PL_new_term_ref();
        if (!PL_get_arg(i, ctrl_t, arg_t)) {
            PL_type_error("compound", ctrl_t);
            goto error;
        }

        atom_t arg_name_t;
        int arity1;
        if (!PL_get_compound_name_arity(arg_t, &arg_name_t, &arity1)) {
            PL_type_error("compound", arg_t);
            goto error;
        }

        const char* arg_name = PL_atom_chars(arg_name_t);

        if (!strcmp(arg_name, LDCTL_OID)) {
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
        } else if (!strcmp(arg_name, BERVAL)) {
            if (!build_BerValue_for_LDAPControl(arg_t, ctrl)) {
                goto error;
            }
        } else if (!strcmp(arg_name, LDCTL_ISCRITICAL)) {
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

    return array;
}

int map_auth_method(char* method, int* method_int) {
    int result = TRUE;
    if (!strcmp(method, AUTH_NONE)) {
        *method_int = LDAP_AUTH_NONE;
    } else if (!strcmp(method, AUTH_SIMPLE)) {
        *method_int = LDAP_AUTH_SIMPLE;
    } else if (!strcmp(method, AUTH_SASL)) {
        *method_int = LDAP_AUTH_SASL;
    } else if (!strcmp(method, AUTH_KRBV4)) {
        *method_int = LDAP_AUTH_KRBV4;
    } else if (!strcmp(method, AUTH_KRBV41)) {
        *method_int = LDAP_AUTH_KRBV41;
    } else if (!strcmp(method, AUTH_KRBV42)) {
        *method_int = LDAP_AUTH_KRBV42;
    } else {
        result = FALSE;
    }
    return result;
}

int ldap4pl_unbind0(term_t ldap_t, int synchronous) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    if (!synchronous) {
        return !ldap_unbind(ldap);
    } else {
        return !ldap_unbind_s(ldap);
    }
}

int ldap4pl_unbind_ext0(term_t ldap_t, term_t sctrls_t, term_t cctrls_t, int synchronous) {
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
    } else {
        int result;
        if (!synchronous) {
            result = !ldap_unbind_ext(ldap, sctrls, cctrls);
        } else {
            result = !ldap_unbind_ext_s(ldap, sctrls, cctrls);
        }

        free_LDAPControl_array(sctrls, sctrls_size);
        free_LDAPControl_array(cctrls, cctrls_size);

        return result;
    }
}

int ldap4pl_bind0(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t, int synchronous) {
    LDAP* ldap;
    if (!PL_get_pointer(ldap_t, (void**) &ldap)) {
        return PL_type_error("pointer", ldap_t);
    }

    char* method;
    if (!PL_get_atom_chars(method_t, &method)) {
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

    if (!synchronous) {
        return !ldap_bind(ldap, who, cred, method_int);
    } else {
        return !ldap_bind_s(ldap, who, cred, method_int);
    }
}

int ldap4pl_simple_bind0(term_t ldap_t, term_t who_t, term_t passwd_t, int synchronous) {
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

    if (!synchronous) {
        return !ldap_simple_bind(ldap, who, passwd);
    } else {
        return !ldap_simple_bind_s(ldap, who, passwd);
    }
}


static foreign_t ldap4pl_initialize(term_t ldap_t, term_t uri_t) {
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
    return ldap4pl_unbind0(ldap_t, FALSE);
}

static foreign_t ldap4pl_unbind_s(term_t ldap_t) {
    return ldap4pl_unbind0(ldap_t, TRUE);
}

static foreign_t ldap4pl_unbind_ext(term_t ldap_t, term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_unbind_ext0(ldap_t, sctrls_t, cctrls_t, FALSE);
}

static foreign_t ldap4pl_unbind_ext_s(term_t ldap_t, term_t sctrls_t, term_t cctrls_t) {
    return ldap4pl_unbind_ext0(ldap_t, sctrls_t, cctrls_t, TRUE);
}

static foreign_t ldap4pl_bind(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t) {
    return ldap4pl_bind0(ldap_t, who_t, cred_t, method_t, FALSE);
}

static foreign_t ldap4pl_bind_s(term_t ldap_t, term_t who_t, term_t cred_t, term_t method_t) {
    return ldap4pl_bind0(ldap_t, who_t, cred_t, method_t, TRUE);
}

static foreign_t ldap4pl_simple_bind(term_t ldap_t, term_t who_t, term_t passwd_t) {
    return ldap4pl_simple_bind0(ldap_t, who_t, passwd_t, FALSE);
}

static foreign_t ldap4pl_simple_bind_s(term_t ldap_t, term_t who_t, term_t passwd_t) {
    return ldap4pl_simple_bind0(ldap_t, who_t, passwd_t, TRUE);
}

install_t install_ldap4pl() {
    PL_register_foreign("ldap4pl_initialize", 2, ldap4pl_initialize, 0);
    PL_register_foreign("ldap4pl_unbind", 1, ldap4pl_unbind, 0);
    PL_register_foreign("ldap4pl_unbind_s", 1, ldap4pl_unbind_s, 0);
    PL_register_foreign("ldap4pl_unbind_ext", 3, ldap4pl_unbind_ext, 0);
    PL_register_foreign("ldap4pl_unbind_ext_s", 3, ldap4pl_unbind_ext_s, 0);
    PL_register_foreign("ldap4pl_bind", 4, ldap4pl_bind, 0);
    PL_register_foreign("ldap4pl_bind_s", 4, ldap4pl_bind_s, 0);
    PL_register_foreign("ldap4pl_simple_bind", 3, ldap4pl_simple_bind, 0);
    PL_register_foreign("ldap4pl_simple_bind_s", 3, ldap4pl_simple_bind_s, 0);
}
