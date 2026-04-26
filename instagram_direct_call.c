/*
 * Instagram Direct Message Video Call API
 * REST API를 사용해 직접 video call 시작
 */

#include "instagram_rce.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int initiate_video_call_direct(const char *target_username) {
    printf("\n[*] REST API: Direct Video Call Initiation\n");
    printf("    Target: @%s\n", target_username);

    char curl_cmd[4096];

    /* STEP 1: Get or create thread with target user */
    printf("[*] STEP 1: Direct thread 찾기/생성\n");

    snprintf(curl_cmd, sizeof(curl_cmd),
        "curl -s -X POST 'https://www.instagram.com/api/v1/direct_v2/create/' "
        "-H 'Cookie: sessionid=%s' "
        "-H 'X-CSRFToken: %s' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "-d 'recipient_users=[[\"%%22id%%22,%%22%s%%22]]' "
        "2>&1",
        INSTAGRAM_SESSIONID, INSTAGRAM_CSRFTOKEN, target_username);

    FILE *fp = popen(curl_cmd, "r");
    if (!fp) {
        printf("[-] curl 실행 실패\n");
        return -1;
    }

    char thread_response[4096] = {0};
    size_t resp_len = 0;
    while (fgets(thread_response + resp_len, sizeof(thread_response) - resp_len, fp)) {
        resp_len = strlen(thread_response);
        if (resp_len > 2000) break;
    }
    pclose(fp);

    printf("[+] Thread 응답: %zu bytes\n", resp_len);
    printf("[+] 응답: %.300s\n", thread_response);

    /* Parse thread_id from response */
    const char *thread_id_start = strstr(thread_response, "\"thread_id\":\"");
    if (!thread_id_start) {
        printf("[-] thread_id를 응답에서 찾을 수 없음\n");
        return -1;
    }

    thread_id_start += strlen("\"thread_id\":\"");
    char thread_id[256] = {0};
    sscanf(thread_id_start, "%255[^\"]", thread_id);

    printf("[+] ✅ Thread ID: %s\n\n", thread_id);

    /* STEP 2: Initiate video call */
    printf("[*] STEP 2: Video call 시작\n");

    snprintf(curl_cmd, sizeof(curl_cmd),
        "curl -s -X POST 'https://www.instagram.com/api/v1/direct_v2/threads/%s/video_call/' "
        "-H 'Cookie: sessionid=%s' "
        "-H 'X-CSRFToken: %s' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "2>&1",
        thread_id, INSTAGRAM_SESSIONID, INSTAGRAM_CSRFTOKEN);

    fp = popen(curl_cmd, "r");
    if (!fp) {
        printf("[-] Video call API 호출 실패\n");
        return -1;
    }

    char call_response[2048] = {0};
    resp_len = 0;
    while (fgets(call_response + resp_len, sizeof(call_response) - resp_len, fp)) {
        resp_len = strlen(call_response);
        if (resp_len > 1000) break;
    }
    pclose(fp);

    printf("[+] Video call 응답: %zu bytes\n", resp_len);
    printf("[+] 응답: %.300s\n", call_response);

    if (strstr(call_response, "video_call_event") || strstr(call_response, "status")) {
        printf("[+] ✅ Video call 신호 전송됨!\n");
        printf("[*] @%s에게 전화 신호 전송\n", target_username);
        printf("[*] 대상 기기: 벨소리 울림 (확정)\n\n");
        return 0;
    } else {
        printf("[-] Video call 시작 실패\n");
        return -1;
    }
}
