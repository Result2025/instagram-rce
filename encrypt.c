/*
 * ATOM 4: SRTP Encryption & Authentication
 * AES-CM counter mode + HMAC-SHA1 authentication
 */

#include "instagram_rce.h"

/* Initialize SRTP IV for AES-CM */
static void init_srtp_iv(const srtp_context_t *ctx, uint8_t *iv) {

    printf("\n[*] ATOM 4-1: SRTP Context Initialization\n");

    /* IV = (index || timestamp || ssrc) XOR salt */
    /* index = (ROC << 16 | seq_num) */

    uint8_t index_bytes[8];
    *(uint32_t *)(index_bytes + 0) = htonl((ctx->roc << 16) | ctx->seq_num);
    *(uint32_t *)(index_bytes + 4) = htonl(ctx->timestamp);

    /* XOR with salt (padded to 16 bytes) */
    uint8_t salt_padded[16];
    memcpy(salt_padded, ctx->salt, SRTP_SALT_SIZE);
    memset(salt_padded + SRTP_SALT_SIZE, 0, 16 - SRTP_SALT_SIZE);

    for (int i = 0; i < 8; i++) {
        iv[i] = index_bytes[i] ^ salt_padded[i];
    }

    /* Add SSRC to IV */
    uint8_t ssrc_bytes[4];
    *(uint32_t *)ssrc_bytes = htonl(ctx->ssrc);

    for (int i = 0; i < 4; i++) {
        iv[8 + i] = ssrc_bytes[i] ^ salt_padded[8 + i];
    }

    printf("[+] IV initialized (16 bytes)\n");
    print_hex(iv, 16, "IV");
}

/* AES-CM (Counter Mode) encryption */
static int aes_cm_encrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t *ciphertext) {

    printf("\n[*] ATOM 4-2: AES-CM Encryption\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ciphertext_len = 0;

    /* Initialize cipher (AES-128-CTR) */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Encrypt */
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    /* Finalize */
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    printf("[+] AES-CM encryption complete\n");
    printf("    Plaintext:  %zu bytes\n", plaintext_len);
    printf("    Ciphertext: %d bytes\n", ciphertext_len);

    return ciphertext_len;
}

/* HMAC-SHA1 authentication tag */
static int hmac_sha1_auth_tag(const uint8_t *auth_key,
                             const uint8_t *authenticated_data,
                             size_t auth_data_len,
                             uint8_t *tag) {

    printf("\n[*] ATOM 4-3: HMAC-SHA1 Authentication Tag\n");

    HMAC_CTX *hmac = HMAC_CTX_new();
    if (!hmac) return -1;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (!HMAC_Init_ex(hmac, auth_key, SRTP_AUTH_KEY_SIZE, EVP_sha1(), NULL)) {
        HMAC_CTX_free(hmac);
        return -1;
    }

    if (!HMAC_Update(hmac, authenticated_data, auth_data_len)) {
        HMAC_CTX_free(hmac);
        return -1;
    }

    if (!HMAC_Final(hmac, hash, &hash_len)) {
        HMAC_CTX_free(hmac);
        return -1;
    }

    HMAC_CTX_free(hmac);

    /* Truncate to 80 bits (10 bytes) */
    memcpy(tag, hash, SRTP_AUTH_TAG_SIZE);

    printf("[+] HMAC-SHA1 tag generated\n");
    printf("    Full hash: %u bytes\n", hash_len);
    printf("    Truncated: %d bytes (80-bit)\n", SRTP_AUTH_TAG_SIZE);
    print_hex(tag, SRTP_AUTH_TAG_SIZE, "Auth Tag");

    return SRTP_AUTH_TAG_SIZE;
}

int srtp_encrypt_packet(const rtp_packet_t *rtp, const srtp_context_t *ctx,
                        uint8_t *output, size_t *output_size) {

    printf("\n[*] ATOM 4-4: SRTP Packet Assembly\n");

    /* RTP Header (plaintext) */
    uint8_t rtp_header[RTP_HEADER_SIZE];
    memcpy(rtp_header, rtp->payload, RTP_HEADER_SIZE);

    /* RTP Payload (to be encrypted) */
    const uint8_t *rtp_payload = rtp->payload + RTP_HEADER_SIZE;
    size_t rtp_payload_len = rtp->payload_size - RTP_HEADER_SIZE;

    /* Initialize IV */
    uint8_t iv[16];
    init_srtp_iv(ctx, iv);

    /* Encrypt payload */
    uint8_t encrypted_payload[512];
    int encrypted_len = aes_cm_encrypt(ctx->key, iv, rtp_payload,
                                       rtp_payload_len, encrypted_payload);
    if (encrypted_len < 0) {
        return -1;
    }

    /* Prepare data for authentication (header + encrypted payload) */
    uint8_t auth_data[1024];
    memcpy(auth_data, rtp_header, RTP_HEADER_SIZE);
    memcpy(auth_data + RTP_HEADER_SIZE, encrypted_payload, encrypted_len);

    /* Generate authentication tag */
    uint8_t auth_tag[SRTP_AUTH_TAG_SIZE];
    if (hmac_sha1_auth_tag(ctx->auth_key, auth_data,
                          RTP_HEADER_SIZE + encrypted_len,
                          auth_tag) < 0) {
        return -1;
    }

    /* Assemble final SRTP packet */
    /* SRTP = RTP Header + Encrypted Payload + Auth Tag */
    size_t srtp_size = RTP_HEADER_SIZE + encrypted_len + SRTP_AUTH_TAG_SIZE;

    memcpy(output, rtp_header, RTP_HEADER_SIZE);
    memcpy(output + RTP_HEADER_SIZE, encrypted_payload, encrypted_len);
    memcpy(output + RTP_HEADER_SIZE + encrypted_len, auth_tag, SRTP_AUTH_TAG_SIZE);

    printf("[+] SRTP Packet assembled:\n");
    printf("    RTP Header:        %d bytes (plaintext)\n", RTP_HEADER_SIZE);
    printf("    Encrypted Payload: %d bytes\n", encrypted_len);
    printf("    Auth Tag:          %d bytes (80-bit HMAC-SHA1)\n", SRTP_AUTH_TAG_SIZE);
    printf("    Total SRTP Packet: %zu bytes\n", srtp_size);

    *output_size = srtp_size;

    return 0;
}
