#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RustLong {
  uintptr_t val;
  int32_t status;
  int32_t sub;
  const char *msg;
} RustLong;

typedef struct RustBool {
  uintptr_t val;
  int32_t status;
  int32_t sub;
  const char *msg;
} RustBool;

typedef struct RustUnit {
  int32_t status;
  int32_t sub;
  const char *msg;
} RustUnit;

//typedef struct RustStr {
//  const char *val;
//  const char *err;
//} RustStr;

void multee_free_rust_str(const char *r_str);

void multee_destroy(uintptr_t enc_sess);

RustLong multee_load_keys(const char *uri,
                          const char *const *key_names,
                          uintptr_t num_keys,
                          const char *creds_path);

RustLong multee_key_length(uintptr_t enc_sess,
                               uintptr_t key_index);

RustLong multee_crypt_cbc(uintptr_t enc_sess,
                              uintptr_t key_index,
                              uintptr_t encrypt,
                              uintptr_t explicit_iv,
                              uint8_t  *iv,
                              uint8_t  *crypto_buf,
                              uintptr_t input_len);

RustUnit multee_crypt_gcm(uintptr_t enc_sess,
                              uintptr_t key_index,
                              uintptr_t encrypt,
                              uint8_t *aad,
                              uintptr_t aad_len,
                              uint8_t * crypto_buf,
                              uintptr_t input_len,
                              uint8_t *iv,
                              uint8_t *tag);

RustUnit multee_hmac_sha256(uintptr_t enc_sess,
                                uintptr_t key_index,
                                const uint8_t *input,
                                uintptr_t input_len,
                                uint8_t *output);

RustUnit multee_sign(uintptr_t enc_sess,
                         uintptr_t key_index,
                         const uint8_t *input,
                         uintptr_t input_len,
                         uint8_t *output,
                         uintptr_t *output_len);

RustBool multee_verify(uintptr_t enc_sess,
                           uintptr_t key_index,
                           const uint8_t *message,
                           uintptr_t message_len,
                           const uint8_t *signature,
                           uintptr_t signature_len);

#ifdef __cplusplus
}
#endif

