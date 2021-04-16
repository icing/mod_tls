/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_proto_h
#define tls_proto_h

#define TLS_VERSION_1_2   0x0303
#define TLS_VERSION_1_3   0x0304

/**
 * Specify a certificate via files or PEM data.
 */
typedef struct {
    const char *cert_file;
    const char *pkey_file;
    const char *cert_pem;
    const char *pkey_pem;
} tls_cert_spec_t;

/**
 * The PEM data of a certificate and its key.
 */
typedef struct {
    char *cert_pem_bytes;
    size_t cert_pem_len;
    char *pkey_pem_bytes;
    size_t pkey_pem_len;
} tls_util_cert_pem_t;


/**
 * Load the PEM data for a certificate file and key file as given in `cert`.
 */
apr_status_t tls_proto_load_pem(apr_pool_t *p, tls_cert_spec_t *cert,
    tls_util_cert_pem_t **ppem);

/**
 * Load a rustls certified key from PEM data.
 */
apr_status_t tls_proto_load_certified_key(
    apr_pool_t *p, server_rec *s,
    tls_cert_spec_t *spec, const rustls_certified_key **pckey);

typedef struct {
    apr_uint16_t id;
    const char *name;
    const char *alias;
} tls_cipher_t;

struct tls_proto_conf_t {
    apr_array_header_t *supported_versions; /* supported protocol versions (apr_uint16_t) */
    apr_hash_t *known_ciphers_by_name; /* hash by name of known tls_cipher_t* */
    apr_hash_t *known_ciphers_by_id; /* hash by id of known tls_cipher_t* */
    apr_hash_t *rustls_ciphers_by_id; /* hash by id of rustls rustls_supported_ciphersuite* */
    apr_array_header_t *supported_cipher_ids; /* cipher ids (apr_uint16_t) supported by rustls */
};
typedef struct tls_proto_conf_t tls_proto_conf_t;

tls_proto_conf_t *tls_proto_init(apr_pool_t *p, server_rec *s);

apr_status_t tls_proto_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s);

apr_uint16_t tls_proto_get_version_by_name(tls_proto_conf_t *conf, const char *name);

const char *tls_proto_get_version_name(
    tls_proto_conf_t *conf, apr_uint16_t id, apr_pool_t *pool);

apr_array_header_t *tls_proto_create_versions_plus(
    tls_proto_conf_t *conf, apr_uint16_t min_version, apr_pool_t *pool);

apr_status_t tls_proto_get_cipher_by_name(
    tls_proto_conf_t *conf, const char *name, apr_uint16_t *pcipher);

int tls_proto_is_cipher_supported(tls_proto_conf_t *conf, apr_uint16_t cipher);

const char *tls_proto_get_cipher_name(
    tls_proto_conf_t *conf, apr_uint16_t cipher, apr_pool_t *pool);

const char *tls_proto_get_cipher_names(
    tls_proto_conf_t *conf, const apr_array_header_t *ciphers, apr_pool_t *pool);

apr_array_header_t *tls_proto_get_rustls_suites(
    tls_proto_conf_t *conf, const apr_array_header_t *ids, apr_pool_t *pool);

#endif /* tls_proto_h */