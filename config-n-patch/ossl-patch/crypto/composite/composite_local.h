/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include <crypto/x509.h>
#include <crypto/evp/evp_local.h>
#include <openssl/asn1t.h>

#ifndef OPENSSL_COMPOSITE_LOCAL_H
#define OPENSSL_COMPOSITE_LOCAL_H

#ifdef  __cplusplus
extern "C" {
#endif

// ==============================
// Declarations & Data Structures
// ==============================

DEFINE_STACK_OF(EVP_PKEY);

typedef struct {

  EVP_MD_CTX * md_ctx;
    // EVP_MD for digital signatures

  EVP_PKEY_CTX * pkey_ctx;
    // Component's CTX (if any)

  EVP_PKEY * pkey;
    // EVP_PKEY for this item

} COMPOSITE_KEY_ITEM;

// Declare a stack of these items
DEFINE_STACK_OF(COMPOSITE_KEY_ITEM);


// Structure for a Composite Key
typedef struct {

  // Single Items composing the key
  STACK_OF(COMPOSITE_KEY_ITEM) *items;

} COMPOSITE_KEY;

typedef struct {

    // Security Bits for the Composite are reported
    // to be the strongest among all the keys (combined)

    // When the (OR) logic is used (compositeOr), the
    // combined Security Bits are the lowest of all items

    // Stack of Keys
    COMPOSITE_KEY * key;

} COMPOSITE_PKEY_CTX;


DEFINE_STACK_OF(EVP_PKEY_CTX)

// Used to Concatenate the encodings of the different
// components when encoding via the ASN1 meth (priv_encode)

DEFINE_STACK_OF(ASN1_OCTET_STRING)

// ====================
// Functions Prototypes
// ====================

COMPOSITE_KEY * COMPOSITE_KEY_new_null();
void COMPOSITE_KEY_free(COMPOSITE_KEY * key);

// Returns an allocated Stack that MUST be Freed by the caller
STACK_OF(EVP_PKEY) * COMPOSITE_KEY_sk_get1(COMPOSITE_KEY * key);

// Does NOT transfer ownership
EVP_PKEY * COMPOSITE_KEY_get0(COMPOSITE_KEY * key, int num);
COMPOSITE_KEY_ITEM * COMPOSITE_KEY_ITEM_get0(COMPOSITE_KEY * key, int num);

// Transfers ownership
EVP_PKEY * COMPOSITE_KEY_pop(COMPOSITE_KEY * key);

int COMPOSITE_KEY_add(COMPOSITE_KEY * key, EVP_PKEY * pkey, int num);
int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num);
int COMPOSITE_KEY_push(COMPOSITE_KEY * key, EVP_PKEY * pkey);
int COMPOSITE_KEY_clear(COMPOSITE_KEY * key);

int COMPOSITE_KEY_num(COMPOSITE_KEY * key);
int COMPOSITE_KEY_size(COMPOSITE_KEY * key);
int COMPOSITE_KEY_bits(COMPOSITE_KEY * bits);
int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * sec_bits);


#ifdef  __cplusplus
}
#endif
#endif

/* END: composite_local.h */
