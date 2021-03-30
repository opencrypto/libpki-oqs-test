/* BEGIN: composite_pmenth.c */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#include "composite_pmeth.h"

// ===============
// Data Structures
// ===============

#include "composite_local.h"

// ======================
// MACRO & Other Oddities
// ======================

#define DEBUG(args...) \
  { fprintf(stderr, "[%s:%d] %s() - ", __FILE__, __LINE__, __func__); \
  fprintf(stderr, ## args) ; fprintf(stderr,"\n"); fflush(stderr) ; }

// ==================
// Internal Functions
// ==================

static COMPOSITE_KEY_ITEM * COMPOSITE_KEY_ITEM_new_null() {

  COMPOSITE_KEY_ITEM * ret = NULL;
    // Return Data Structure


  // Allocates Memory
  ret = OPENSSL_zalloc(sizeof(*ret));

  if (!ret) return NULL;

  ret->pkey_ctx = NULL;
  ret->md_ctx   = NULL;
  ret->pkey     = NULL;

  // All Done
  return ret;
}

static void COMPOSITE_KEY_ITEM_free(COMPOSITE_KEY_ITEM *x) {

  if (!x) return;

  if (x->md_ctx) EVP_MD_CTX_free(x->md_ctx); // EVP_MD_meth_free()
  x->md_ctx = NULL;

  if (x->pkey_ctx) EVP_PKEY_CTX_free(x->pkey_ctx);
  x->pkey_ctx = NULL;

  if (x->pkey) EVP_PKEY_free(x->pkey);
  x->pkey = NULL;

  OPENSSL_free(x);

  return;
}

static COMPOSITE_KEY_ITEM * COMPOSITE_KEY_ITEM_new_id (int alg_nid) {

  COMPOSITE_KEY_ITEM * ret = NULL;
    // Return item

  // Input Validation
  if (alg_nid <= NID_undef) return NULL;

  // Allocate the return object
  if ((ret = COMPOSITE_KEY_ITEM_new_null()) == NULL)
    return NULL;

  // Get the CTX from the NID
  if ((ret->pkey_ctx = EVP_PKEY_CTX_new_id(alg_nid, NULL)) == NULL) {
    DEBUG("Cannot Get a new Item's CTX");
    goto err;
  }

  DEBUG("ITEM (%d) created successfully", alg_nid);

  return ret;

err:

  if (ret) COMPOSITE_KEY_ITEM_free(ret);

  return NULL;
}

COMPOSITE_KEY * COMPOSITE_KEY_new_null() {

  COMPOSITE_KEY * ret = NULL;
    // Composite Key Container

  STACK_OF(COMPOSITE_KEY_ITEM) * items = NULL;
    // Empty Stack for Key Sequences

  // Generates the Stack First
  if ((items = sk_COMPOSITE_KEY_ITEM_new_null()) == NULL)
    return NULL;

  // Allocates the return memoty
  if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
    sk_COMPOSITE_KEY_ITEM_free(items);
    return NULL;
  }

  // Transfers Ownership
  ret->items = items;

  // All Done
  return ret;
}

void COMPOSITE_KEY_free(COMPOSITE_KEY * key) {

  COMPOSITE_KEY_ITEM * it = NULL;
    // Temp pointer for freeing resources

  // Input check
  if (!key) return;

  // Free the components first
  while ((key->items != NULL) && 
         (it = sk_COMPOSITE_KEY_ITEM_pop(key->items)) != NULL) {

    // Deallocate the memory for the object
    COMPOSITE_KEY_ITEM_free(it);
  }

  // Deallocate memory for the main strcuture
  OPENSSL_free(key);

  // All Done
  return;

}

static COMPOSITE_PKEY_CTX * COMPOSITE_PKEY_CTX_new_null() {

  COMPOSITE_PKEY_CTX * ctx = NULL;

  // Allocates the CTX
  if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
    return NULL;
  }

  // Allocates an empty Key
  if (((ctx->key = COMPOSITE_KEY_new_null())) == NULL) {
    OPENSSL_free(ctx);
    return NULL;
  }

  // All Done
  return ctx;
}

static void COMPOSITE_PKEY_CTX_free(COMPOSITE_PKEY_CTX * ctx) {

  if (!ctx) return;

  // Free the key (if present)
  if (ctx->key != NULL) COMPOSITE_KEY_free(ctx->key);

  // Free the main structure
  OPENSSL_free(ctx);

  // Safety
  ctx = NULL;

  // All Done
  return;
}

EVP_PKEY * COMPOSITE_KEY_get0(COMPOSITE_KEY * key, int num) {

  COMPOSITE_KEY_ITEM * it = NULL;
    // Pointer for the Data Structure

  if ((it = COMPOSITE_KEY_ITEM_get0(key, num)) == NULL)
    return NULL;

  // All done
  return it->pkey;
}

COMPOSITE_KEY_ITEM * COMPOSITE_KEY_ITEM_get0(COMPOSITE_KEY * key, int num) {

  COMPOSITE_KEY_ITEM * it = NULL;
    // Pointer for the Data Structure

  // Input checks
  if (!key || !key->items)
    return NULL;

  // Checks the range for num
  if (num >= sk_COMPOSITE_KEY_ITEM_num(key->items))
    return NULL;

  // Gets the item
  if ((it = sk_COMPOSITE_KEY_ITEM_value(key->items, num)) == NULL)
    return NULL;

  // All done
  return it;
}

int COMPOSITE_KEY_add(COMPOSITE_KEY * key, EVP_PKEY * pkey, int num) {

  COMPOSITE_KEY_ITEM * aItem = NULL;

  // Input check
  if (!key || !key->items || !pkey) return 0;

  // Checks the range for num
  if (num < 0 || num >= sk_COMPOSITE_KEY_ITEM_num(key->items))
    return 0;

  // Generate a new item
  if ((aItem = COMPOSITE_KEY_ITEM_new_null()) == NULL)
    return 0;

  // Let's add the new Item to the Stack first (check error)
  // and then assign the pkey to the item
  if (!sk_COMPOSITE_KEY_ITEM_insert(key->items, aItem, num)) {
    // Free Memory
    COMPOSITE_KEY_ITEM_free(aItem);
    return 0;
  }

  // Let's assign the pkey to the added item
  aItem->pkey = pkey;

  // All Done
  return 1;
}

int COMPOSITE_KEY_del(COMPOSITE_KEY * key, int num) {

  // COMPOSITE_KEY_ITEM * aItem = NULL;

  if (!key || !key->items) return 0;

  DEBUG("MISSING CODE: Del Key from MultiKey");

  return 0;

}

int COMPOSITE_KEY_push(COMPOSITE_KEY * key, EVP_PKEY * pkey) {

  COMPOSITE_KEY_ITEM * aItem = NULL;

  if (!key || !key->items) return 0;

  // Generate a new item
  if ((aItem = COMPOSITE_KEY_ITEM_new_null()) == NULL)
    return 0;

  // Let's add the new Item to the Stack first (check error)
  // and then assign the pkey to the item
  if (!sk_COMPOSITE_KEY_ITEM_push(key->items, aItem)) {
    // Free Memory
    COMPOSITE_KEY_ITEM_free(aItem);
    return 0;
  }

  // Let's assign the pkey to the added item
  aItem->pkey = pkey;

  // All Done
  return 1;
}

EVP_PKEY * COMPOSITE_KEY_pop(COMPOSITE_KEY * key) {

  EVP_PKEY * aKey = NULL;

  COMPOSITE_KEY_ITEM * aItem = NULL;

  if (!key || !key->items) return NULL;

  if ((aItem = sk_COMPOSITE_KEY_ITEM_pop(key->items)) == NULL)
    return NULL;

  // Transfer Ownership
  aKey = aItem->pkey;
  aItem->pkey = NULL;

  // Free the memory
  COMPOSITE_KEY_ITEM_free(aItem);

  // Returns the PKEY
  return aKey;
}

int COMPOSITE_KEY_clear(COMPOSITE_KEY * key) {

  EVP_PKEY * aKey = NULL;

  // Input Checks
  if (!key || !key->items) return 0;

  while ((aKey = COMPOSITE_KEY_pop(key)) != NULL) {
    // Free the Key Data Structure
    EVP_PKEY_free(aKey);
  }

  // All Done.
  return 1;
}

int COMPOSITE_KEY_num(COMPOSITE_KEY * key) {
  
  if (!key || !key->items) return -1;

  return sk_COMPOSITE_KEY_ITEM_num(key->items);
}

int COMPOSITE_KEY_size(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_size = 0;

  if (!key || !key->items) return -1;

  if ((key_num = COMPOSITE_KEY_num(key)) <= 0)
    return 0;

  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    total_size += EVP_PKEY_size(single_key);

    DEBUG("DEBUG: [%d] Current Total Size is [%d] (already total size!)",
      i, total_size);
  }

  DEBUG("Final Total Size: %d", total_size);

  return total_size;
}

int COMPOSITE_KEY_bits(COMPOSITE_KEY * key) {

  int i = 0;
  int key_num = 0;  
  int total_bits = 0;

  if (!key || !key->items) return -1;

  if ((key_num = COMPOSITE_KEY_num(key)) <= 0)
    return 0;

  for (i = 0; i < key_num; i++) {

    const EVP_PKEY * single_key;

    if ((single_key = COMPOSITE_KEY_get0(key, i)) == NULL) {
      DEBUG("ERROR: Cannot get key %d", i);
      return 0;
    }

    total_bits += EVP_PKEY_size(single_key);

    DEBUG("DEBUG: [%d] Current Total BITS is [%d]",
     i, total_bits);
  }

  DEBUG("Returning Total Size: %d", total_bits);

  return total_bits;
}

int COMPOSITE_KEY_security_bits(COMPOSITE_KEY * sec_bits) {
  DEBUG("Not Implemented, yet.");
  return 0;
}

// =========================
// EVP_PKEY_METHOD Functions
// =========================

// Implemented
static int init(EVP_PKEY_CTX *ctx) {
  
  COMPOSITE_PKEY_CTX *comp_ctx = NULL;

  // Allocate Memory
  if ((comp_ctx = COMPOSITE_PKEY_CTX_new_null()) == NULL)
    return 0;

  // Assigns the algorithm-specific data
  // to the data field
  ctx->data = comp_ctx;

  // These are used during Key Gen to display
  // '.', '+', '*', '\n' during key gen
  ctx->keygen_info = NULL;
  ctx->keygen_info_count = 0;

  DEBUG("Init completed successfully.");

  // All Done
  return 1;
}

// Not Implemented
static int copy(EVP_PKEY_CTX * dst,
                EVP_PKEY_CTX * src) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static void cleanup(EVP_PKEY_CTX * ctx) {

  COMPOSITE_PKEY_CTX * comp_ctx = NULL;
    // Composite Context

  // Input Check
  if (!ctx) return;

  // Retrieves the internal context
  if ((comp_ctx = ctx->data) != NULL)
    COMPOSITE_PKEY_CTX_free(comp_ctx);

  DEBUG("cleanup completed successfully.");

  return;
}

// Not Implemented
static int paramgen_init(EVP_PKEY_CTX * ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int paramgen(EVP_PKEY_CTX * ctx,
                    EVP_PKEY     * pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Nothing to do here
static int keygen_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 1;
}

// Not Implemented
static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {

  int alg_nid = 0;
    // NID for the algorithm

  COMPOSITE_PKEY_CTX * comp_ctx = NULL;

  // Input Validation
  if (!ctx || !ctx->data || !pkey) return 0;

  // Some extra checking for correctness
  if ((alg_nid = ctx->pmeth->pkey_id) != NID_composite) {
    DEBUG("ERROR: NID is not NID_composite (%d vs. %d)",
      alg_nid, NID_composite);
    return 0;
  }

  // Checks we have the right data and items
  if (!(comp_ctx = ctx->data) || !(comp_ctx->key) || 
        sk_COMPOSITE_KEY_ITEM_num(comp_ctx->key->items) <= 0) {

    // No components present in the key
    DEBUG("ERROR: No Keys Are Present in the SEQUENCE!");
    return 0;
  }
  // NOTE: To Get the Structure, use EVP_PKEY_get0(EVP_PKEY *k)
  // NOTE: To Add the Key Structure, use EVP_PKEY_assign()
  EVP_PKEY_assign_COMPOSITE(pkey, comp_ctx->key);
  // EVP_PKEY_assign(pkey, -1, comp_ctx->key);

  DEBUG("KeyGen Completed Successfully.");

  return 1;
}

// Implemented
static int sign_init(EVP_PKEY_CTX *ctx) {

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to inner structure

  if (!ctx || !ctx->pkey ||
     ((comp_key = EVP_PKEY_get0(ctx->pkey)) == NULL)) {
    return 0;
  }

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    COMPOSITE_KEY_ITEM * it = NULL;
      // Pointer to Internal Structure that
      // contains also the EVP_PKEY_CTX for
      // the component of the key

    if ((it = COMPOSITE_KEY_ITEM_get0(comp_key, i)) == NULL)
      return 0;

    if (!it->pkey_ctx) {
      // Copies some details from the main EVP_PKEY_CTX
      // int the newly generated one associated to the
      // single component
      it->pkey_ctx = EVP_PKEY_CTX_new_id(
                          it->pkey->type,
                          ctx->engine);

      // Copies the basic data
      it->pkey_ctx->operation = ctx->operation;
      it->pkey_ctx->app_data  = ctx->app_data;
    }

    // Attaches the EVP_PKEY if not there
    if (NULL == it->pkey_ctx->pkey) {
      it->pkey_ctx->pkey = it->pkey;
      EVP_PKEY_up_ref(it->pkey);
    }

    // Initialize the Signature for the component
    if (1 != EVP_PKEY_sign_init(it->pkey_ctx)) {
      DEBUG("ERROR: Cannot initialize signature for Key Component #%d", i);
      return 0;
    }
  }

  // All Components have been initialized
  return 1;
}

// Implemented
static int sign(EVP_PKEY_CTX        * ctx, 
                unsigned char       * sig,
                size_t              * siglen,
                const unsigned char * tbs,
                size_t                tbslen) {

  COMPOSITE_KEY * comp_key = EVP_PKEY_get0(ctx && ctx->pkey ? ctx->pkey : NULL);
    // Pointer to inner key structure

  STACK_OF(ASN1_TYPE) *sk = NULL;
    // Stack of ASN1_OCTET_STRINGs

  ASN1_OCTET_STRING * oct_string = NULL;
    // Output Signature to be added
    // to the stack of signatures

  ASN1_TYPE * aType = NULL;
    // ASN1 generic wrapper

  int comp_key_num = 0;
    // Number of components

  const int signature_size = EVP_PKEY_size(ctx->pkey);
    // The total signature size

  unsigned char * buff = NULL;
  unsigned char * pnt  = NULL;
  int buff_len =  0;
    // Temp Pointers

  int total_size = 0;
    // Total Signature Size

  if ((comp_key == NULL) || 
      ((comp_key_num = COMPOSITE_KEY_num(comp_key)) <= 0)) {
    DEBUG("ERROR: Cannot get the Composite key inner structure");
    return 0;
  }

  if (sig == NULL) {
    *siglen = (size_t)signature_size;
    return 1;
  }

  if ((size_t)signature_size > (*siglen)) {
    DEBUG("ERROR: Buffer is too small");
    return 0;
  }

  if ((sk = sk_ASN1_TYPE_new_null()) == NULL) {
    DEBUG("ERROR: Memory Allocation");
    return 0;
  }

  for (int i = 0; i < comp_key_num; i++) {

    COMPOSITE_KEY_ITEM * it = COMPOSITE_KEY_ITEM_get0(comp_key, i);
      // Pointer to the single ITEM in the Composite Key

    EVP_PKEY_CTX * tmp_pkey_ctx = NULL;
      // Pointer to the EVP_PKEY from the CTX

    // Gets the EVP_PKEY from the sequence
    if ((tmp_pkey_ctx = it->pkey_ctx) == NULL) {
      DEBUG("ERROR: Cannot retrieve the PKEY CTX of the %d-th component of the key", i);
      goto err;
    }

    DEBUG("Determining Signature Size for Component #%d", i);

    // Let's get the size of the single signature
    if (EVP_PKEY_sign(tmp_pkey_ctx, NULL, (size_t *)&buff_len, tbs, tbslen) != 1) {
      DEBUG("ERROR: Null Size reported from Key Component #%d", i);
      goto err;
    }

    // Allocate the buffer for the single signature
    if ((pnt = buff = OPENSSL_malloc(buff_len)) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    DEBUG("PNT = %p, BUFF = %p", pnt, buff);

    // Generates the single signature
    if (EVP_PKEY_sign(tmp_pkey_ctx, pnt, (size_t *)&buff_len, tbs, tbslen) != 1) {
      DEBUG("ERROR: Component #%d cannot generate signatures", i);
      goto err;
    }

    DEBUG("PNT = %p, BUFF = %p", pnt, buff);

    // Updates the overall real size
    total_size += buff_len;

    DEBUG("Generated Signature for Component #%d Successfully (size: %d)", i, buff_len);
    DEBUG("Signature Total Size [So Far] ... %d", total_size);

    if ((oct_string = ASN1_OCTET_STRING_new()) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    // This sets the internal pointers
    ASN1_STRING_set0(oct_string, buff, buff_len);

    // Resets the pointer and length after ownership transfer
    buff = NULL; buff_len = 0;

    // Let's now generate the ASN1_TYPE and add it to the stack
    if ((aType = ASN1_TYPE_new()) == NULL) {
      DEBUG("ERROR: Memory Allocation");
      goto err;
    }

    // Transfer Ownership to the aType structure
    ASN1_TYPE_set(aType, V_ASN1_OCTET_STRING, oct_string);
    oct_string = NULL;

    // Adds the component to the stack
    if (!sk_ASN1_TYPE_push(sk, aType)) {
      DEBUG("ERROR: Cannot push the new Type");
      goto err;
    }

    // Transfers ownership
    aType = NULL;
  }

  if ((buff_len = i2d_ASN1_SEQUENCE_ANY(sk, &buff)) <= 0) {
    DEBUG("ERROR: Cannot ASN1 encode the Overall Composite Key");
    goto err;
  }

  // Reporting the total size
  DEBUG("Total Signature Size: %d (reported: %d)", total_size, EVP_PKEY_size(ctx->pkey))

  // Free the stack's memory
  while ((aType = sk_ASN1_TYPE_pop(sk)) == NULL) {
    ASN1_TYPE_free(aType);
  }
  sk_ASN1_TYPE_free(sk);
  sk = NULL;

  // Sets the output buffer
  sig = buff;
  *siglen = buff_len;

  // All Done
  return 1;

err:

  DEBUG("ERROR: Signing failed");

  // Here we need to cleanup the memory

  return 0;
}

// Implemented
static int verify_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int verify(EVP_PKEY_CTX        * ctx,
                                 const unsigned char * sig,
                                 size_t                siglen,
                                 const unsigned char * tbs,
                                 size_t                tbslen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int verify_recover(EVP_PKEY_CTX        * ctx,
                          unsigned char       * rout,
                          size_t              * routlen,
                          const unsigned char * sig,
                          size_t                siglen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

  COMPOSITE_KEY * comp_key = NULL;
    // Pointer to inner structure

  if (!ctx || !ctx->pkey ||
     ((comp_key = EVP_PKEY_get0(ctx->pkey)) == NULL)) {
    return 0;
  }

  if (!EVP_PKEY_sign_init(ctx)) {
    DEBUG("ERROR: Cannot initialize the Multi-Key PKEY CTX");
    return 0;
  }

  for (int i = 0; i < COMPOSITE_KEY_num(comp_key); i++) {

    COMPOSITE_KEY_ITEM * it = NULL;
      // Pointer to Internal Structure that
      // contains also the EVP_PKEY_CTX for
      // the component of the key

    if ((it = COMPOSITE_KEY_ITEM_get0(comp_key, i)) == NULL)
      return 0;

    if (!it->pkey_ctx) {
      // Copies some details from the main EVP_PKEY_CTX
      // int the newly generated one associated to the
      // single component

      it->pkey_ctx = EVP_PKEY_CTX_new_id(
                          it->pkey->type,
                          ctx->engine);

      // Copies the basic data
      it->pkey_ctx->operation = ctx->operation;
      it->pkey_ctx->app_data  = ctx->app_data;
    }

    if (mctx) {
      
      if (!it->md_ctx && 
          ((it->md_ctx = EVP_MD_CTX_new()) == NULL)) {
        DEBUG("ERROR: Cannot Allocate the MD CTX for Component #%d", i);
      }

      // Initializes the EVP_MD (alias to EVP_MD_reset)
      EVP_MD_CTX_init(it->md_ctx);

      // Copy the MD to the specific component
      if ((mctx->digest != NULL) && 
          (EVP_MD_CTX_copy(it->md_ctx, mctx) <= 0)) {
        // This is ok, it fails when the mctx->digest is NULL
        DEBUG("ERROR: Cannot copy the MD CTX for Component #%d", i);
        EVP_MD_CTX_free(it->md_ctx);
        it->md_ctx = NULL;
        return 0;
      }
    }

    // Use the Component's signctx_init specific callback
    if (it->pkey_ctx->pmeth->signctx_init != NULL &&
        (it->pkey_ctx->pmeth->signctx_init(it->pkey_ctx, 
                                           it->md_ctx) != 1)) {
      DEBUG("ERROR: Cannot Initialize Signature for Component #%d", i);
      return 0;
    }
  }

  // All Components have been initialized
  return 1;
}

// Implemented
static int signctx (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) {

  DEBUG("Not implemented, yet.");
  return 0;
}


// Implemented
static int verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int verifyctx (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int encrypt_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int decrypt_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int derive_init(EVP_PKEY_CTX *ctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int ctrl(EVP_PKEY_CTX *ctx, int type, int key_id, void *value) {

  COMPOSITE_PKEY_CTX *comp_ctx = ctx->data;
    // Pointer to the Composite CTX

  EVP_PKEY * pkey = NULL;
    // Pointer to the PKEY to add/del

  // Input checks
  if (!comp_ctx || !comp_ctx->key)
    return 0;

  switch (type) {

    // ===================
    // OpenSSL CTRL Values
    // ===================

    case EVP_PKEY_CTRL_MD: {

      const EVP_PKEY * aKey = NULL;
        // Pointer for signle component keys

      if (key_id < 0) return 0;

      if (value == NULL) {
        DEBUG("Setting NULL digest, returning OK.");
        return 1;
      }

      if ((aKey = COMPOSITE_KEY_get0(comp_ctx->key, key_id)) == NULL) {
        DEBUG("ERROR: Cannot Get Key %d from the stack (%p)", key_id, comp_ctx->key);
        return 0;
      }

      DEBUG("MISSING CODE: Setting the MD for the selected key!");

    } break;


    case EVP_PKEY_OP_TYPE_SIG: {
      DEBUG("Got EVP sign operation");
    } break;

    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_CMS_ENCRYPT:
    case EVP_PKEY_CTRL_CMS_DECRYPT:
    case EVP_PKEY_CTRL_CMS_SIGN:
    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
    case EVP_PKEY_CTRL_SET_MAC_KEY:
    case EVP_PKEY_CTRL_SET_IV:
    case EVP_PKEY_CTRL_CIPHER: {
      
      DEBUG("Unsupported CTRL: type = %d, param_1 = %d, param_2 = %p",
        type, key_id, value);
      return 0;

    } break;

    // =====================
    // COMPOSITE CTRL Values
    // =====================

    case EVP_PKEY_CTRL_COMPOSITE_ADD: {

      DEBUG("ADD a Key: %d -> %p", key_id, value);
      
      if ((pkey = (EVP_PKEY *)value) == NULL) {
        DEBUG("ERROR: Missing PKEY");
        return 0;
      }

      if (!COMPOSITE_KEY_add(comp_ctx->key, pkey, key_id)) {
        DEBUG("ERROR: Cannot ADD the new key");
        return 0;
      }

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_PUSH: {

      DEBUG("PUSH a Key: %p", value);

      if ((pkey = (EVP_PKEY *)value) == NULL) {
        DEBUG("ERROR: Missing PKEY");
        return 0;
      }

      if (!COMPOSITE_KEY_push(comp_ctx->key, pkey)) {
        DEBUG("ERROR: Cannot PUSH the new key");
        return 0;
      }

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_DEL: {

      DEBUG("DEL a Key: %d", key_id);

      // Delete the specific item from the stack
      if (!COMPOSITE_KEY_del(comp_ctx->key, key_id)) {
        DEBUG("ERROR: Cannot delete key %d", key_id);
        return 0;
      }

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_POP: {

      DEBUG("POP a Key");
      
      // POP the specific item and get the EVP_PKEY
      if ((pkey = COMPOSITE_KEY_pop(comp_ctx->key)) == NULL) {
        DEBUG("ERROR: Cannot POP a key from the composite");
        return 0;
      }

      // Free the EVP_PKEY memory
      EVP_PKEY_free(pkey);

    } break;

    case EVP_PKEY_CTRL_COMPOSITE_CLEAR: {
      DEBUG("Clearing ALL Keys: %d -> %p", key_id, value);

      // Clears all components from the key
      if (!COMPOSITE_KEY_clear(comp_ctx->key)) {
        DEBUG("ERROR: Cannot delete key %d", key_id);
        return 0;
      }

    } break;


    default: {
      DEBUG("Unrecognized CTRL (type = %d)", type);
      return 0;
    }

  }

  // Returns OK
  return 1;
}

// Not Implemented
static int ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// ===================
// OpenSSL 1.1.x+ Only
// ===================

// Implemented
static int digestsign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int digestverify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int public_check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Not Implemented
static int param_check(EVP_PKEY *pkey) {
  DEBUG("Not implemented, yet.");
  return 0;
}

// Implemented
static int digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  DEBUG("Not implemented, yet.");
  return 0;
}

/* END: composite_pmenth.c */