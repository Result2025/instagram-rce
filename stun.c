/*
 * ATOM 1-1: STUN Client
 * Discovers public IP and port through STUN server
 */

#include "instagram_rce.h"

/* STUN Protocol Constants */
#define STUN_MESSAGE_TYPE_REQUEST 0x0001
#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_ATTRIBUTE_MAPPED_ADDRESS 0x0001
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS 0x0020

/* STUN Binding Request */
static void create_stun_binding_request(uint8_t *buffer, size_t *size) {
    uint32_t magic_cookie = htonl(STUN_MAGIC_COOKIE);
    uint16_t msg_type = htons(STUN_MESSAGE_TYPE_REQUEST);
    uint16_t msg_len = htons(0);
    uint8_t transaction_id[12];

    /* Random transaction ID */
    for (int i = 0; i < 12; i++) {
        transaction_id[i] = rand() & 0xFF;
    }

    /* Build STUN header */
    int offset = 0;

    /* Message Type */
    memcpy(buffer + offset, &msg_type, 2);
    offset += 2;

    /* Message Length */
    memcpy(buffer + offset, &msg_len, 2);
    offset += 2;

    /* Magic Cookie */
    memcpy(buffer + offset, &magic_cookie, 4);
    offset += 4;

    /* Transaction ID */
    memcpy(buffer + offset, transaction_id, 12);
    offset += 12;

    *size = offset;
}

/* Parse STUN response */
static int parse_stun_response(const uint8_t *buffer, size_t size,
                              char *public_ip, uint16_t *public_port) {
    if (size < 20) {
        return -1;
    }

    /* Skip header, go to attributes (offset 20) */
    size_t offset = 20;

    while (offset + 4 <= size) {
        uint16_t attr_type = ntohs(*(uint16_t *)(buffer + offset));
        uint16_t attr_len = ntohs(*(uint16_t *)(buffer + offset + 2));

        if (attr_type == STUN_ATTRIBUTE_MAPPED_ADDRESS && attr_len >= 8) {
            /* Parse MAPPED-ADDRESS */
            uint16_t port = ntohs(*(uint16_t *)(buffer + offset + 6));
            uint32_t ip = ntohl(*(uint32_t *)(buffer + offset + 8));

            sprintf(public_ip, "%u.%u.%u.%u",
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                   (ip >> 8) & 0xFF, ip & 0xFF);
            *public_port = port;
            return 0;

        } else if (attr_type == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS && attr_len >= 8) {
            /* Parse XOR-MAPPED-ADDRESS */
            uint16_t xor_port = ntohs(*(uint16_t *)(buffer + offset + 6));
            uint32_t xor_ip = ntohl(*(uint32_t *)(buffer + offset + 8));

            /* XOR with magic cookie */
            uint16_t port = xor_port ^ (STUN_MAGIC_COOKIE >> 16);
            uint32_t ip = xor_ip ^ STUN_MAGIC_COOKIE;

            sprintf(public_ip, "%u.%u.%u.%u",
                   (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                   (ip >> 8) & 0xFF, ip & 0xFF);
            *public_port = port;
            return 0;
        }

        /* Next attribute (4-byte aligned) */
        size_t padded_len = ((attr_len + 3) / 4) * 4;
        offset += 4 + padded_len;
    }

    return -1;
}

int stun_discover(stun_result_t *result) {
    printf("\n[*] ATOM 1-1: STUN Client - NAT Traversal\n");
    printf("    Connecting to: %s:%d\n", STUN_SERVER, STUN_PORT);

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("[-] socket creation failed");
        return -1;
    }

    /* Resolve STUN server */
    struct hostent *he = gethostbyname(STUN_SERVER);
    if (!he) {
        perror("[-] gethostbyname failed");
        close(sock);
        return -1;
    }

    struct sockaddr_in stun_addr;
    memset(&stun_addr, 0, sizeof(stun_addr));
    stun_addr.sin_family = AF_INET;
    stun_addr.sin_port = htons(STUN_PORT);
    memcpy(&stun_addr.sin_addr, he->h_addr, he->h_length);

    /* Create STUN request */
    uint8_t stun_request[20];
    size_t request_size;
    create_stun_binding_request(stun_request, &request_size);

    /* Send request */
    if (sendto(sock, stun_request, request_size, 0,
              (struct sockaddr *)&stun_addr, sizeof(stun_addr)) < 0) {
        perror("[-] sendto failed");
        close(sock);
        return -1;
    }

    printf("[+] STUN request sent (%zu bytes)\n", request_size);

    /* Receive response (3 second timeout) */
    uint8_t response[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("[-] setsockopt failed");
        close(sock);
        return -1;
    }

    ssize_t recv_size = recvfrom(sock, response, sizeof(response), 0,
                                 (struct sockaddr *)&from_addr, &from_len);

    if (recv_size < 0) {
        printf("[-] STUN server did not respond (timeout)\n");
        close(sock);
        return -1;
    }

    printf("[+] STUN response received (%zd bytes)\n", recv_size);

    /* Parse response */
    char ip[16];
    uint16_t port;

    if (parse_stun_response(response, recv_size, ip, &port) == 0) {
        strcpy(result->public_ip, ip);
        result->public_port = port;
        printf("[✓] Public address discovered: %s:%u\n", ip, port);
        close(sock);
        return 0;
    } else {
        printf("[-] Failed to parse STUN response\n");
        close(sock);
        return -1;
    }
}
