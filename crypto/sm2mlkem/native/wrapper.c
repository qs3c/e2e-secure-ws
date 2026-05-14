#define SM2MLKEM_WRAPPER_BUILD

#include "../wrapper.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define SM2_GROUP_NAME "SM2"
#define MLKEM768_ALG_NAME "ML-KEM-768"

#define SM2_PUBLIC_KEY_LEN 65
#define SM2_PRIVATE_KEY_LEN 32
#define MLKEM768_PUBLIC_KEY_LEN 1184
#define MLKEM768_PRIVATE_KEY_LEN 2400
#define MLKEM768_CIPHERTEXT_LEN 1088
#define COMPONENT_SHARED_SECRET_LEN 32

struct SM2MLKEM_KEY {
    unsigned char public_key[SM2MLKEM_PUBLIC_KEY_LEN];
    unsigned char private_key[SM2MLKEM_PRIVATE_KEY_LEN];
    int has_public;
    int has_private;
};

static char last_error[512];
static OSSL_PROVIDER *default_provider;

static void set_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(last_error, sizeof(last_error), fmt, ap);
    va_end(ap);
}

static void set_openssl_error(const char *prefix)
{
    unsigned long err = ERR_get_error();
    const char *reason = NULL;

    if (err != 0)
        reason = ERR_reason_error_string(err);
    if (reason == NULL)
        reason = "unknown OpenSSL error";
    set_error("%s: %s", prefix, reason);
}

const char *sm2mlkem_last_error(void)
{
    return last_error[0] == '\0' ? "no error" : last_error;
}

static int check_output_buffer(size_t need, unsigned char *out, size_t *out_len)
{
    if (out_len == NULL) {
        set_error("missing output length pointer");
        return 0;
    }
    if (out == NULL) {
        *out_len = need;
        return 1;
    }
    if (*out_len < need) {
        *out_len = need;
        set_error("output buffer too small");
        return 0;
    }
    return 1;
}

static SM2MLKEM_KEY *alloc_key(void)
{
    SM2MLKEM_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        set_openssl_error("OPENSSL_zalloc failed");
    return key;
}

static EVP_PKEY *new_key_from_params(const char *alg, int selection,
                                     OSSL_PARAM params[])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
        set_openssl_error("EVP_PKEY_fromdata failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *import_ec_public_key(const unsigned char *in)
{
    char group_name[] = SM2_GROUP_NAME;
    OSSL_PARAM params[3];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)in,
                                                  SM2_PUBLIC_KEY_LEN);
    params[2] = OSSL_PARAM_construct_end();
    return new_key_from_params("EC",
                               OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                               | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                               params);
}

static EVP_PKEY *import_ec_private_key(const unsigned char *in)
{
    char group_name[] = SM2_GROUP_NAME;
    BIGNUM *priv = NULL;
    unsigned char native_priv[SM2_PRIVATE_KEY_LEN];
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;

    priv = BN_bin2bn(in, SM2_PRIVATE_KEY_LEN, NULL);
    if (priv == NULL) {
        set_openssl_error("BN_bin2bn failed");
        return NULL;
    }
    if (BN_bn2nativepad(priv, native_priv, sizeof(native_priv))
        != SM2_PRIVATE_KEY_LEN) {
        set_error("unexpected EC private key length");
        goto end;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name, 0);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                        native_priv,
                                        SM2_PRIVATE_KEY_LEN);
    params[2] = OSSL_PARAM_construct_end();
    pkey = new_key_from_params("EC",
                               OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                               | OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                               params);

end:
    OPENSSL_cleanse(native_priv, sizeof(native_priv));
    BN_clear_free(priv);
    return pkey;
}

static EVP_PKEY *import_mlkem_public_key(const unsigned char *in)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  (void *)in,
                                                  MLKEM768_PUBLIC_KEY_LEN);
    params[1] = OSSL_PARAM_construct_end();
    return new_key_from_params(MLKEM768_ALG_NAME,
                               OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params);
}

static EVP_PKEY *import_mlkem_private_key(const unsigned char *in)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  (void *)in,
                                                  MLKEM768_PRIVATE_KEY_LEN);
    params[1] = OSSL_PARAM_construct_end();
    return new_key_from_params(MLKEM768_ALG_NAME,
                               OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params);
}

static int export_ec_private_key(EVP_PKEY *pkey, unsigned char *out)
{
    BIGNUM *priv = NULL;
    int ret = 0;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) {
        set_openssl_error("EC private key export failed");
        return 0;
    }
    if (BN_bn2binpad(priv, out, SM2_PRIVATE_KEY_LEN) != SM2_PRIVATE_KEY_LEN) {
        set_error("unexpected EC private key length");
        goto end;
    }
    ret = 1;

end:
    BN_clear_free(priv);
    return ret;
}

static int export_octet_param(EVP_PKEY *pkey, const char *param_name,
                              unsigned char *out, size_t want)
{
    size_t actual = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, param_name, out, want,
                                        &actual) != 1) {
        set_openssl_error("octet key export failed");
        return 0;
    }
    if (actual != want) {
        set_error("unexpected octet key length");
        return 0;
    }
    return 1;
}

int sm2mlkem_init(const char *provider_path)
{
    EVP_PKEY_CTX *ec_probe = NULL;
    EVP_PKEY_CTX *mlkem_probe = NULL;
    int ret = 0;

    last_error[0] = '\0';

    if (provider_path != NULL && provider_path[0] != '\0') {
        if (OSSL_PROVIDER_set_default_search_path(NULL, provider_path) != 1) {
            set_openssl_error("OSSL_PROVIDER_set_default_search_path failed");
            return 0;
        }
    }

    if (default_provider == NULL) {
        default_provider = OSSL_PROVIDER_load(NULL, "default");
        if (default_provider == NULL) {
            set_openssl_error("OSSL_PROVIDER_load(default) failed");
            return 0;
        }
    }

    ec_probe = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    mlkem_probe = EVP_PKEY_CTX_new_from_name(NULL, MLKEM768_ALG_NAME, NULL);
    if (ec_probe == NULL || mlkem_probe == NULL) {
        set_openssl_error("SM2 or ML-KEM-768 is unavailable");
        goto end;
    }
    ret = 1;

end:
    EVP_PKEY_CTX_free(ec_probe);
    EVP_PKEY_CTX_free(mlkem_probe);
    return ret;
}

SM2MLKEM_KEY *sm2mlkem_generate_key(void)
{
    EVP_PKEY *ec_key = NULL;
    EVP_PKEY *mlkem_key = NULL;
    SM2MLKEM_KEY *key = NULL;

    last_error[0] = '\0';

    key = alloc_key();
    if (key == NULL)
        return NULL;

    ec_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", SM2_GROUP_NAME);
    mlkem_key = EVP_PKEY_Q_keygen(NULL, NULL, MLKEM768_ALG_NAME);
    if (ec_key == NULL || mlkem_key == NULL) {
        set_openssl_error("component key generation failed");
        goto err;
    }

    if (!export_octet_param(ec_key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                            key->public_key, SM2_PUBLIC_KEY_LEN)
        || !export_ec_private_key(ec_key, key->private_key)
        || !export_octet_param(mlkem_key, OSSL_PKEY_PARAM_PUB_KEY,
                               key->public_key + SM2_PUBLIC_KEY_LEN,
                               MLKEM768_PUBLIC_KEY_LEN)
        || !export_octet_param(mlkem_key, OSSL_PKEY_PARAM_PRIV_KEY,
                               key->private_key + SM2_PRIVATE_KEY_LEN,
                               MLKEM768_PRIVATE_KEY_LEN)) {
        goto err;
    }

    key->has_public = 1;
    key->has_private = 1;
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(mlkem_key);
    return key;

err:
    EVP_PKEY_free(ec_key);
    EVP_PKEY_free(mlkem_key);
    OPENSSL_clear_free(key, sizeof(*key));
    return NULL;
}

SM2MLKEM_KEY *sm2mlkem_import_public_key(const unsigned char *in, size_t in_len)
{
    SM2MLKEM_KEY *key = NULL;

    last_error[0] = '\0';
    if (in == NULL || in_len != SM2MLKEM_PUBLIC_KEY_LEN) {
        set_error("invalid public key length");
        return NULL;
    }
    key = alloc_key();
    if (key == NULL)
        return NULL;
    memcpy(key->public_key, in, SM2MLKEM_PUBLIC_KEY_LEN);
    key->has_public = 1;
    return key;
}

SM2MLKEM_KEY *sm2mlkem_import_private_key(const unsigned char *in, size_t in_len)
{
    SM2MLKEM_KEY *key = NULL;

    last_error[0] = '\0';
    if (in == NULL || in_len != SM2MLKEM_PRIVATE_KEY_LEN) {
        set_error("invalid private key length");
        return NULL;
    }
    key = alloc_key();
    if (key == NULL)
        return NULL;
    memcpy(key->private_key, in, SM2MLKEM_PRIVATE_KEY_LEN);
    key->has_private = 1;
    return key;
}

void sm2mlkem_free_key(SM2MLKEM_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_clear_free(key, sizeof(*key));
}

int sm2mlkem_export_public_key(SM2MLKEM_KEY *key, unsigned char *out, size_t *out_len)
{
    last_error[0] = '\0';
    if (key == NULL || !key->has_public) {
        set_error("missing public key");
        return 0;
    }
    if (!check_output_buffer(SM2MLKEM_PUBLIC_KEY_LEN, out, out_len))
        return out == NULL;
    if (out == NULL)
        return 1;
    memcpy(out, key->public_key, SM2MLKEM_PUBLIC_KEY_LEN);
    *out_len = SM2MLKEM_PUBLIC_KEY_LEN;
    return 1;
}

int sm2mlkem_export_private_key(SM2MLKEM_KEY *key, unsigned char *out, size_t *out_len)
{
    last_error[0] = '\0';
    if (key == NULL || !key->has_private) {
        set_error("missing private key");
        return 0;
    }
    if (!check_output_buffer(SM2MLKEM_PRIVATE_KEY_LEN, out, out_len))
        return out == NULL;
    if (out == NULL)
        return 1;
    memcpy(out, key->private_key, SM2MLKEM_PRIVATE_KEY_LEN);
    *out_len = SM2MLKEM_PRIVATE_KEY_LEN;
    return 1;
}

int sm2mlkem_encapsulate(SM2MLKEM_KEY *peer_public_key,
                         unsigned char *ciphertext, size_t *ciphertext_len,
                         unsigned char *shared_secret, size_t *shared_secret_len)
{
    EVP_PKEY *peer_ec = NULL;
    EVP_PKEY *peer_mlkem = NULL;
    EVP_PKEY *ephemeral_ec = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t actual = 0;
    int ret = 0;

    last_error[0] = '\0';
    if (peer_public_key == NULL || !peer_public_key->has_public) {
        set_error("missing peer public key");
        return 0;
    }
    if (!check_output_buffer(SM2MLKEM_CIPHERTEXT_LEN, ciphertext, ciphertext_len)
        || !check_output_buffer(SM2MLKEM_SHARED_SECRET_LEN, shared_secret,
                                shared_secret_len))
        return 0;

    peer_ec = import_ec_public_key(peer_public_key->public_key);
    peer_mlkem = import_mlkem_public_key(peer_public_key->public_key
                                         + SM2_PUBLIC_KEY_LEN);
    ephemeral_ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", SM2_GROUP_NAME);
    if (peer_ec == NULL || peer_mlkem == NULL || ephemeral_ec == NULL) {
        if (last_error[0] == '\0')
            set_openssl_error("encapsulation key setup failed");
        goto end;
    }

    actual = SM2_PUBLIC_KEY_LEN;
    if (EVP_PKEY_get_octet_string_param(ephemeral_ec,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, ciphertext, actual,
            &actual) != 1 || actual != SM2_PUBLIC_KEY_LEN) {
        set_openssl_error("ephemeral SM2 public key export failed");
        goto end;
    }

    actual = MLKEM768_CIPHERTEXT_LEN;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer_mlkem, NULL);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, ciphertext + SM2_PUBLIC_KEY_LEN, &actual,
                                shared_secret + COMPONENT_SHARED_SECRET_LEN,
                                shared_secret_len) <= 0
        || actual != MLKEM768_CIPHERTEXT_LEN
        || *shared_secret_len != COMPONENT_SHARED_SECRET_LEN) {
        set_openssl_error("ML-KEM encapsulation failed");
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    actual = COMPONENT_SHARED_SECRET_LEN;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ephemeral_ec, NULL);
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, peer_ec) <= 0
        || EVP_PKEY_derive(ctx, shared_secret, &actual) <= 0
        || actual != COMPONENT_SHARED_SECRET_LEN) {
        set_openssl_error("SM2 ECDH derivation failed");
        goto end;
    }

    *ciphertext_len = SM2MLKEM_CIPHERTEXT_LEN;
    *shared_secret_len = SM2MLKEM_SHARED_SECRET_LEN;
    ret = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_ec);
    EVP_PKEY_free(peer_mlkem);
    EVP_PKEY_free(ephemeral_ec);
    return ret;
}

int sm2mlkem_decapsulate(SM2MLKEM_KEY *local_private_key,
                         const unsigned char *ciphertext, size_t ciphertext_len,
                         unsigned char *shared_secret, size_t *shared_secret_len)
{
    EVP_PKEY *local_ec = NULL;
    EVP_PKEY *local_mlkem = NULL;
    EVP_PKEY *peer_ephemeral_ec = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t actual = 0;
    int ret = 0;

    last_error[0] = '\0';
    if (local_private_key == NULL || !local_private_key->has_private) {
        set_error("missing local private key");
        return 0;
    }
    if (ciphertext == NULL || ciphertext_len != SM2MLKEM_CIPHERTEXT_LEN) {
        set_error("invalid ciphertext length");
        return 0;
    }
    if (!check_output_buffer(SM2MLKEM_SHARED_SECRET_LEN, shared_secret,
                             shared_secret_len))
        return 0;

    local_ec = import_ec_private_key(local_private_key->private_key);
    local_mlkem = import_mlkem_private_key(local_private_key->private_key
                                           + SM2_PRIVATE_KEY_LEN);
    peer_ephemeral_ec = import_ec_public_key(ciphertext);
    if (local_ec == NULL || local_mlkem == NULL || peer_ephemeral_ec == NULL) {
        if (last_error[0] == '\0')
            set_openssl_error("decapsulation key setup failed");
        goto end;
    }

    actual = COMPONENT_SHARED_SECRET_LEN;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local_mlkem, NULL);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, shared_secret + COMPONENT_SHARED_SECRET_LEN,
                                &actual, ciphertext + SM2_PUBLIC_KEY_LEN,
                                MLKEM768_CIPHERTEXT_LEN) <= 0
        || actual != COMPONENT_SHARED_SECRET_LEN) {
        set_openssl_error("ML-KEM decapsulation failed");
        goto end;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    actual = COMPONENT_SHARED_SECRET_LEN;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local_ec, NULL);
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, peer_ephemeral_ec) <= 0
        || EVP_PKEY_derive(ctx, shared_secret, &actual) <= 0
        || actual != COMPONENT_SHARED_SECRET_LEN) {
        set_openssl_error("SM2 ECDH derivation failed");
        goto end;
    }

    *shared_secret_len = SM2MLKEM_SHARED_SECRET_LEN;
    ret = 1;

end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local_ec);
    EVP_PKEY_free(local_mlkem);
    EVP_PKEY_free(peer_ephemeral_ec);
    return ret;
}
