/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_proto_h
#define tls_proto_h

#include "tls_util.h"


#define TLS_VERSION_1_2   0x0303
#define TLS_VERSION_1_3   0x0304

/**
 * The PEM data of a certificate and its key.
 */
typedef struct {
    tls_data_t cert_pem;
    tls_data_t pkey_pem;
} tls_cert_pem_t;

/**
 * Specify a certificate via files or PEM data.
 */
typedef struct {
    const char *cert_file; /* file path, relative to ap_root */
    const char *pkey_file; /* file path, relative to ap_root */
    const char *cert_pem;  /* NUL-terminated PEM string */
    const char *pkey_pem;  /* NUL-terminated PEM string */
} tls_cert_spec_t;

/**
 * Load the PEM data for a certificate file and key file as given in `cert`.
 */
apr_status_t tls_proto_load_pem(
    apr_pool_t *p, const tls_cert_spec_t *cert, tls_cert_pem_t **ppem);

/**
 * Load a rustls certified key from a certificate specification.
 * The returned `rustls_certified_key` is owned by the caller.
 * @param p the memory pool to use
 * @param spec the specification for the certificate (file or PEM data)
 * @param cert_pem return the PEM data used for loading the certificates, optional
 * @param pckey the loaded certified key on return
 */
apr_status_t tls_proto_load_certified_key(
    apr_pool_t *p, const tls_cert_spec_t *spec,
    const char **pcert_pem, const rustls_certified_key **pckey);

/**
 * A registry of rustls_certified_key* by identifier.
 */
typedef struct tls_cert_reg_t tls_cert_reg_t;
struct  tls_cert_reg_t{
    apr_pool_t *pool;
    apr_hash_t *id2entry;
    apr_hash_t *key2entry;
};

/**
 * Create a new registry with lifetime based on the memory pool.
 * The registry will take care of its memory and allocated keys when
 * the pool is destroyed.
 */
tls_cert_reg_t *tls_cert_reg_make(apr_pool_t *p);

/**
 * Return the number of certified keys in the registry.
 */
apr_size_t tls_cert_reg_count(tls_cert_reg_t *reg);

/**
 * Get a the `rustls_certified_key` identified by `spec` from the registry.
 * This will load the key the first time it is requested.
 * The returned `rustls_certified_key` is owned by the registry.
 * @param reg the certified key registry
 * @param s the server_rec this is loaded into, useful for error logging
 * @param spec the specification of the certified key
 * @param pckey the certified key instance on return
 */
apr_status_t tls_cert_reg_get_certified_key(
    tls_cert_reg_t *reg, server_rec *s, const tls_cert_spec_t *spec, const rustls_certified_key **pckey);

/**
 * Visit all certified keys in the registry.
 * The callback may return 0 to abort the iteration.
 * @param userdata supplied by the visit invocation
 * @param s the server_rec the certified was load into first
 * @param id internal identifier of the certified key
 * @param cert_pem the PEM data of the certificate and its chain
 * @param certified_key the key instance itself
 */
typedef int tls_cert_reg_visitor(
    void *userdata, server_rec *s,
    const char *id, const char *cert_pem, const rustls_certified_key *certified_key);

/**
 * Visit all certified_key entries in the registry.
 * @param visitor callback invoked on each entry until it returns 0.
 * @param userdata passed to callback
 * @param reg the registry to iterate over
 */
void tls_cert_reg_do(
    tls_cert_reg_visitor *visitor, void *userdata, tls_cert_reg_t *reg);

/**
 * Get the identified assigned to a loaded, certified key. Returns NULL, if the
 * key is not part of the registry. The returned bytes are owned by the registry
 * entry.
 * @param reg the registry to look in.
 * @param certified_key the key to get the identifier for
 */
const char *tls_cert_reg_get_id(tls_cert_reg_t *reg, const rustls_certified_key *certified_key);

/**
 * Specification of a TLS cipher by name, possible alias and its 16 bit value
 * as assigned by IANA.
 */
typedef struct {
    apr_uint16_t id;      /* IANA 16-bit assigned value as used on the wire */
    const char *name;     /* IANA given name of hte cipher */
    const char *alias;    /* Optional, commonly known alternate name */
} tls_cipher_t;

/**
 * TLS protocol related definitions constructed
 * by querying crustls lib.
 */
typedef struct tls_proto_conf_t tls_proto_conf_t;
struct tls_proto_conf_t {
    apr_array_header_t *supported_versions; /* supported protocol versions (apr_uint16_t) */
    apr_hash_t *known_ciphers_by_name; /* hash by name of known tls_cipher_t* */
    apr_hash_t *known_ciphers_by_id; /* hash by id of known tls_cipher_t* */
    apr_hash_t *rustls_ciphers_by_id; /* hash by id of rustls rustls_supported_ciphersuite* */
    apr_array_header_t *supported_cipher_ids; /* cipher ids (apr_uint16_t) supported by rustls */
};

/**
 * Create and populate the protocol configuration.
 */
tls_proto_conf_t *tls_proto_init(apr_pool_t *p, server_rec *s);

/**
 * Called during post-config phase to conclude the intialization
 * of the tls protocol configuration.
 */
apr_status_t tls_proto_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s);

/**
 * Get the TLS protocol identifer (as used on the wire) for the TLS
 * protocol of the given name. Returns 0 if protocol is unknown.
 */
apr_uint16_t tls_proto_get_version_by_name(tls_proto_conf_t *conf, const char *name);

/**
 * Get the name of the protocol version identified by its identifier. This
 * will return the name from the protocol configuration or, if unknown, create
 * the string `TLSv0x%04x` from the 16bit identifier.
 */
const char *tls_proto_get_version_name(
    tls_proto_conf_t *conf, apr_uint16_t id, apr_pool_t *pool);

/**
 * Create an array of the given TLS protocol version identifier `min_version`
 * and all supported new ones. The array carries apr_uint16_t values.
 */
apr_array_header_t *tls_proto_create_versions_plus(
    tls_proto_conf_t *conf, apr_uint16_t min_version, apr_pool_t *pool);

/**
 * Get a TLS cipher spec by name/alias.
 */
apr_status_t tls_proto_get_cipher_by_name(
    tls_proto_conf_t *conf, const char *name, apr_uint16_t *pcipher);

/**
 * Return != 0 iff the cipher is supported by the rustls library.
 */
int tls_proto_is_cipher_supported(tls_proto_conf_t *conf, apr_uint16_t cipher);

/**
 * Get the name of a TLS cipher for the IANA assigned 16bit value. This will
 * return the name in the protocol configuation, if the cipher is known, and
 * create the string `TLS_CIPHER_0x%04x` for the 16bit cipher value.
 */
const char *tls_proto_get_cipher_name(
    tls_proto_conf_t *conf, apr_uint16_t cipher, apr_pool_t *pool);

/**
 * Get the concatenated names with ':' as separator of all TLS cipher identifiers
 * as given in `ciphers`.
 * @param conf the TLS protocol configuration
 * @param ciphers the 16bit values of the TLS ciphers
 * @param pool to use for allocation the string.
 */
const char *tls_proto_get_cipher_names(
    tls_proto_conf_t *conf, const apr_array_header_t *ciphers, apr_pool_t *pool);

/**
 * Convert an array of TLS cipher 16bit identifiers into the `rustls_supported_ciphersuite`
 * instances that can be passed to crustls in session configurations.
 * Any cipher identifier not supported by rustls we be silently omitted.
 */
apr_array_header_t *tls_proto_get_rustls_suites(
    tls_proto_conf_t *conf, const apr_array_header_t *ids, apr_pool_t *pool);

#endif /* tls_proto_h */