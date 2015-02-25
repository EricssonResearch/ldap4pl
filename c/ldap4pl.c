#include <SWI-Prolog.h>
#include <SWI-Stream.h>
#include <ldap.h>

#ifdef O_DEBUG
#define DEBUG(g) g
#else
#define DEBUG(g)
#endif

static foreign_t ldap4pl_initialize(term_t ldap_t, term_t uri_t) {
    char* uri;
    if (!PL_get_atom_chars(uri_t, &uri)) {
        return PL_type_error("atom", uri_t);
    }

    DEBUG(Sdprintf("%s\n", uri));

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

install_t install_ldap4pl() {
    PL_register_foreign("ldap4pl_initialize", 2, ldap4pl_initialize, 0);
    PL_register_foreign("ldap4pl_unbind", 1, ldap4pl_unbind, 0);
}
