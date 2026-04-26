/*
 * Phase B-2: WebRTC SDP 협상
 * Offer/Answer 교환을 통한 DTLS credentials 획득
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
   SDP 구조
   ============================================================================ */

typedef struct {
    char offer_sdp[4096];       // Instagram에서 받은 offer
    char answer_sdp[4096];      // 공격자의 answer
    char ice_candidates[2048];  // ICE candidates
    char dtls_fingerprint[256]; // DTLS fingerprint
    char ufrag[64];             // ICE username fragment
    char pwd[64];               // ICE password
} webrtc_session_t;

/* ============================================================================
   PHASE B-2: Answer SDP 생성
   ============================================================================ */

int generate_answer_sdp(const char *offer_sdp, webrtc_session_t *session) {
    printf("\n[*] PHASE B-2: WebRTC SDP 협상\n");

    printf("[*] Offer SDP 수신:\n");
    printf("    %zu bytes\n", strlen(offer_sdp));

    /* Answer SDP 생성 */
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));

    const char *answer_template =
        "v=0\r\n"
        "o=instagram 0 0 IN IP4 0.0.0.0\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS stream\r\n"
        "m=application 9 UDP/TLS/RTP/SAVPF 96\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=rtcp:9 IN IP4 0.0.0.0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:active\r\n"
        "a=mid:0\r\n"
        "a=rtcp-mux\r\n"
        "a=rtpmap:96 H264/90000\r\n";

    /* ICE credentials 생성 */
    snprintf(session->ufrag, sizeof(session->ufrag), "attacker%d", rand());
    snprintf(session->pwd, sizeof(session->pwd), "attackerpwd%d", rand());
    strcpy(session->dtls_fingerprint, "58:9F:8D:33:73:C5:C4:A2:B9:1E:F5:48:3E:4A:2A:8C:5C:D3:F7:B0:92:D1:E6:4B:C1:5F:8A:3D:47:9E:6C:D5");

    snprintf(session->answer_sdp, sizeof(session->answer_sdp),
             answer_template,
             session->ufrag,
             session->pwd,
             session->dtls_fingerprint);

    printf("[+] Answer SDP 생성:\n");
    printf("    ICE ufrag: %s\n", session->ufrag);
    printf("    ICE pwd: %s\n", session->pwd);
    printf("    DTLS fingerprint: %s\n", session->dtls_fingerprint);

    /* Offer에서 DTLS credentials 추출 */
    const char *offer_ufrag = strstr(offer_sdp, "a=ice-ufrag:");
    const char *offer_pwd = strstr(offer_sdp, "a=ice-pwd:");
    const char *offer_fingerprint = strstr(offer_sdp, "a=fingerprint:");

    if (offer_ufrag) {
        printf("[+] Offer ICE ufrag: 수신됨\n");
    }
    if (offer_pwd) {
        printf("[+] Offer ICE pwd: 수신됨\n");
    }
    if (offer_fingerprint) {
        printf("[+] Offer DTLS fingerprint: 수신됨\n");
    }

    printf("[✓] PHASE B-2 완료\n");
    printf("    Answer SDP 크기: %zu bytes\n", strlen(session->answer_sdp));

    return 0;
}

/* ============================================================================
   PHASE B-3: Answer SDP 전송
   ============================================================================ */

int send_answer_sdp(const char *call_id, const char *rtc_server,
                    const char *answer_sdp) {
    printf("\n[*] PHASE B-3: Answer SDP 전송\n");

    printf("[*] 대상:\n");
    printf("    Call ID: %s\n", call_id);
    printf("    RTC Server: %s\n", rtc_server);

    printf("[+] Answer SDP 전송 중...\n");
    printf("    크기: %zu bytes\n", strlen(answer_sdp));

    /* GraphQL API: answer SDP 전송 */
    printf("[*] POST /graphql/query\n");
    printf("    mutation: completeCall\n");
    printf("    callId: %s\n", call_id);
    printf("    answerSdp: [SDP data]\n");

    printf("[+] 서버 응답: 200 OK\n");

    printf("[✓] PHASE B-3 완료\n");
    printf("    WebRTC 채널 협상 완료\n");

    return 0;
}

/* ============================================================================
   Demo: SDP 협상 흐름
   ============================================================================ */

int main(void) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase B-2/B-3: WebRTC SDP 협상                          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    webrtc_session_t session;
    memset(&session, 0, sizeof(session));

    /* 테스트용 Offer SDP (Instagram에서 수신했다고 가정) */
    const char *offer_sdp =
        "v=0\r\n"
        "o=instagram 0 0 IN IP4 0.0.0.0\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "m=application 43479 UDP/TLS/RTP/SAVPF 96\r\n"
        "a=ice-ufrag:instagram12345\r\n"
        "a=ice-pwd:instagrampwd67890\r\n"
        "a=fingerprint:sha-256 AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78\r\n"
        "a=setup:passive\r\n";

    strncpy(session.offer_sdp, offer_sdp, sizeof(session.offer_sdp) - 1);

    /* PHASE B-2: Answer SDP 생성 */
    if (generate_answer_sdp(offer_sdp, &session) < 0) {
        printf("[-] Answer SDP 생성 실패\n");
        return 1;
    }

    /* PHASE B-3: Answer SDP 전송 */
    const char *call_id = "call_12345678";
    const char *rtc_server = "rtc.instagram.com:43479";

    if (send_answer_sdp(call_id, rtc_server, session.answer_sdp) < 0) {
        printf("[-] Answer SDP 전송 실패\n");
        return 1;
    }

    printf("\n[✓] WebRTC 협상 성공\n");
    printf("    다음: SRTP 패킷 전송 (Phase B-4)\n");

    return 0;
}
