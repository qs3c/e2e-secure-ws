#ifndef QS3C_SM2MLKEM_WRAPPER_H
#define QS3C_SM2MLKEM_WRAPPER_H

#include <stddef.h>

#ifdef _WIN32
# ifdef SM2MLKEM_WRAPPER_BUILD
#  define SM2MLKEM_API __declspec(dllexport)
# else
#  define SM2MLKEM_API __declspec(dllimport)
# endif
#else
# define SM2MLKEM_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SM2MLKEM_GROUP_ID 0x11EE
#define SM2MLKEM_PUBLIC_KEY_LEN 1249
#define SM2MLKEM_PRIVATE_KEY_LEN 2432
#define SM2MLKEM_CIPHERTEXT_LEN 1153
#define SM2MLKEM_SHARED_SECRET_LEN 64

typedef struct SM2MLKEM_KEY SM2MLKEM_KEY;

SM2MLKEM_API int sm2mlkem_init(const char *provider_path);
SM2MLKEM_API const char *sm2mlkem_last_error(void);

SM2MLKEM_API SM2MLKEM_KEY *sm2mlkem_generate_key(void);
SM2MLKEM_API SM2MLKEM_KEY *sm2mlkem_import_public_key(const unsigned char *in, size_t in_len);
SM2MLKEM_API SM2MLKEM_KEY *sm2mlkem_import_private_key(const unsigned char *in, size_t in_len);
SM2MLKEM_API void sm2mlkem_free_key(SM2MLKEM_KEY *key);

SM2MLKEM_API int sm2mlkem_export_public_key(SM2MLKEM_KEY *key, unsigned char *out, size_t *out_len);
SM2MLKEM_API int sm2mlkem_export_private_key(SM2MLKEM_KEY *key, unsigned char *out, size_t *out_len);

SM2MLKEM_API int sm2mlkem_encapsulate(SM2MLKEM_KEY *peer_public_key,
                                      unsigned char *ciphertext, size_t *ciphertext_len,
                                      unsigned char *shared_secret, size_t *shared_secret_len);
SM2MLKEM_API int sm2mlkem_decapsulate(SM2MLKEM_KEY *local_private_key,
                                      const unsigned char *ciphertext, size_t ciphertext_len,
                                      unsigned char *shared_secret, size_t *shared_secret_len);

#ifdef __cplusplus
}
#endif

#endif
