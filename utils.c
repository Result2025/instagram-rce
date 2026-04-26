/*
 * Utility Functions
 */

#include "instagram_rce.h"

void print_hex(const uint8_t *data, size_t len, const char *label) {
    if (label) {
        printf("    %s: ", label);
    }

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_banner(void) {
    printf("\n");
    printf("==============================================================================\n");
    printf("  Instagram SRTP 0-Day RCE - Method B: ADB + Real Negotiation\n");
    printf("  Vulnerability: width × height 32-bit integer overflow\n");
    printf("  Port: %u (Instagram RTC)\n", TARGET_RTC_PORT);
    printf("==============================================================================\n");
}

void print_phase_header(int phase, const char *title) {
    printf("\n");
    printf("################################################################################\n");
    printf("# PHASE %d: %s\n", phase, title);
    printf("################################################################################\n");
}
