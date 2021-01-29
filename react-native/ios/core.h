#pragma once

#include <stdint.h>

// rust ffi

struct ExternError {
  int32_t code;
  char *message; // note: nullable
};

void signer_destroy_string(const char *cstring);

void process_events(struct ExternError *, const char *kel_str, const char *db_path);

const char *resolve_id(struct ExternError *, const char *id, const char *db_path);

const char *get_kerl(struct ExternError *, const char *id, const char *db_path);

// returns a new encrypted walet
const char *new_wallet(struct ExternError *, const char *id, const char *pass);

const char *keri_incept_wallet(struct ExternError *, const char *ew,
                               const char *id, const char *pass);

const char *keri_incept_wallet_from_keys(struct ExternError *, const char *live_keys,
                               const char *pre_rotated_keys, const char *pass);

const char *change_pass(struct ExternError *, const char *ew, const char *id,
                        const char *old_pass, const char *new_pass);

const char *change_id(struct ExternError *, const char *ew, const char *id,
                      const char *new_id, const char *pass);

const char *new_key(struct ExternError *, const char *ew, const char *id,
                    const char *pass, const char *type, const char *controller);

const char *add_content(struct ExternError *, const char *ew, const char *id,
                        const char *pass, const char *content);

const char *set_key_controller(struct ExternError *, const char *ew,
                               const char *id, const char *pass,
                               const char *key_ref, const char *controller);

const char *get_key(struct ExternError *, const char *ew, const char *id,
                    const char *pass, const char *key_ref);

const char *get_key_by_controller(struct ExternError *, const char *ew,
                                  const char *id, const char *pass,
                                  const char *controller);

const char *get_keys(struct ExternError *, const char *ew, const char *id,
                     const char *pass);

const char *sign_by_controller(struct ExternError *, const char *ew, const char *id,
                 const char *pass, const char *controller, const char *data);

const bool jc_verify(struct ExternError *, const char *key, const char *type,
                   const char *data, const char *signature);

const char *jc_encrypt(struct ExternError *, const char *key, const char *type,
                    const char *data, const char *aad);

const char *jc_decrypt(struct ExternError *, const char *ew, const char *id,
                    const char *pass, const char *key_ref, const char *data,
                    const char *aad);

const char *get_random(struct ExternError *, const unsigned len);

const void jolo_destroy_string(const char *);
