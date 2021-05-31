/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#ifndef mod_tls_version_h
#define mod_tls_version_h

#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#undef PACKAGE_STRING
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT

/**
 * @macro
 * Version number of the md module as c string
 */
#define MOD_TLS_VERSION "0.6.1"

/**
 * @macro
 * Numerical representation of the version number of the md module
 * release. This is a 24 bit number with 8 bits for major number, 8 bits
 * for minor and 8 bits for patch. Version 1.2.3 becomes 0x010203.
 */
#define MOD_TLS_VERSION_NUM 0x000601

#endif /* mod_md_md_version_h */
