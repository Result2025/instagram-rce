/*
 * ATOM 1-3: SDP Generation
 * Creates Session Description Protocol for WebRTC negotiation
 */

#include "instagram_rce.h"

char* sdp_generate(const char *username, const char *public_ip, uint16_t port) {

    printf("\n[*] ATOM 1-3: SDP Generation\n");
    printf("    Username: %s\n", username);
    printf("    Public IP: %s:%u\n", public_ip, port);

    char *sdp = malloc(2048);
    if (!sdp) return NULL;

    int offset = 0;

    /* Session Description */
    offset += snprintf(sdp + offset, 2048 - offset,
        "v=0\r\n"
        "o=instagram 0 0 IN IP4 %s\r\n"
        "s=Instagram Video Call\r\n"
        "t=0 0\r\n"
        "m=application %u UDP/TLS/RTP/SAVPF 96\r\n"
        "c=IN IP4 %s\r\n"
        "a=rtcp:%u IN IP4 %s\r\n"
        "a=ice-ufrag:instagram%04x\r\n"
        "a=ice-pwd:instagrampwd%016lx\r\n"
        "a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n"
        "a=setup:actpass\r\n"
        "a=rtcp-mux\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 profile-level-id=42e01e packetization-mode=1\r\n",
        public_ip, port, public_ip, port, public_ip,
        (unsigned int)(rand() & 0xFFFF),
        (unsigned long)(rand() & 0xFFFFFFFFUL));

    printf("[+] SDP generated (%d bytes)\n", offset);
    printf("    Media: H.264 RTP over UDP/TLS\n");
    printf("    DTLS-SRTP enabled\n");

    return sdp;
}
