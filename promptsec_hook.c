#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <stdarg.h>

#define MAX_PATTERNS 200
#define MAX_PATTERN_LEN 512
#define MAX_NAME_LEN 128
#define EXPORT __declspec(dllexport)

typedef struct {
    wchar_t name[MAX_NAME_LEN];
    wchar_t pattern[MAX_PATTERN_LEN];
    int enabled;
} Pattern;

static Pattern g_patterns[MAX_PATTERNS];
static int g_patternCount = 0;
static HWND g_callbackWindow = NULL;
static UINT g_msgThreatDetected = 0;
static volatile BOOL g_active = FALSE;
static volatile BOOL g_running = FALSE;
static BOOL g_initialized = FALSE;
static CRITICAL_SECTION g_cs;
static HANDLE g_monitorThread = NULL;
static wchar_t g_lastClipboard[2048] = L"";
static FILE* g_logFile = NULL;

void DebugLog(const char* format, ...) {
    if (!g_logFile) {
        g_logFile = fopen("promptsec_debug.log", "a");
    }
    if (g_logFile) {
        time_t now = time(NULL);
        struct tm* t = localtime(&now);
        fprintf(g_logFile, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        va_list args;
        va_start(args, format);
        vfprintf(g_logFile, format, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
}

wchar_t ToLowerW(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return c + 32;
    return c;
}

const wchar_t* FindSubstringW(const wchar_t* text, const wchar_t* pattern) {
    if (!text || !pattern || *pattern == L'\0') return NULL;

    size_t textLen = wcslen(text);
    size_t patLen = wcslen(pattern);

    if (patLen == 0 || patLen > textLen) return NULL;

    for (size_t i = 0; i <= textLen - patLen; i++) {
        BOOL match = TRUE;
        for (size_t j = 0; j < patLen; j++) {
            if (ToLowerW(text[i + j]) != ToLowerW(pattern[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) return text + i;
    }
    return NULL;
}

wchar_t* GetClipboardTextSafe(void) {
    wchar_t* result = NULL;

    for (int retry = 0; retry < 10; retry++) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t* pData = (wchar_t*)GlobalLock(hData);
                if (pData) {
                    size_t len = wcslen(pData);
                    if (len > 0 && len < 1000000) {
                        result = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
                        if (result) {
                            wcscpy(result, pData);
                        }
                    }
                    GlobalUnlock(hData);
                }
            }
            CloseClipboard();
            break;
        }
        Sleep(20);
    }

    return result;
}

BOOL SetClipboardTextSafe(const wchar_t* text) {
    if (!text) return FALSE;

    size_t len = wcslen(text);
    if (len == 0 || len > 1000000) return FALSE;

    for (int retry = 0; retry < 10; retry++) {
        if (OpenClipboard(NULL)) {
            EmptyClipboard();

            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
            if (hMem) {
                wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
                if (pMem) {
                    wcscpy(pMem, text);
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_UNICODETEXT, hMem);
                    CloseClipboard();
                    return TRUE;
                }
                GlobalFree(hMem);
            }
            CloseClipboard();
            break;
        }
        Sleep(20);
    }
    return FALSE;
}

BOOL ProcessClipboard(wchar_t* outThreats, int outSize) {
    if (!g_active || g_patternCount == 0) return FALSE;

    wchar_t* clipText = GetClipboardTextSafe();
    if (!clipText) return FALSE;

    size_t clipLen = wcslen(clipText);
    if (clipLen == 0) {
        free(clipText);
        return FALSE;
    }

    BOOL foundThreat = FALSE;
    wchar_t threatNames[1024] = L"";

    size_t bufSize = clipLen * 4 + 4096;
    wchar_t* modifiedText = (wchar_t*)malloc(bufSize * sizeof(wchar_t));
    if (!modifiedText) {
        free(clipText);
        return FALSE;
    }
    wcscpy(modifiedText, clipText);

    EnterCriticalSection(&g_cs);

    for (int i = 0; i < g_patternCount; i++) {
        if (!g_patterns[i].enabled) continue;
        if (wcslen(g_patterns[i].pattern) == 0) continue;

        wchar_t* pos;
        while ((pos = (wchar_t*)FindSubstringW(modifiedText, g_patterns[i].pattern)) != NULL) {

            if (!foundThreat) {
                foundThreat = TRUE;
            }

            if (wcsstr(threatNames, g_patterns[i].name) == NULL) {
                if (wcslen(threatNames) > 0) wcscat(threatNames, L", ");
                if (wcslen(threatNames) + wcslen(g_patterns[i].name) < 1000) {
                    wcscat(threatNames, g_patterns[i].name);
                }
            }

            wchar_t tag[256];
            swprintf(tag, 256, L"[BLOCKED:%ls]", g_patterns[i].name);

            size_t patLen = wcslen(g_patterns[i].pattern);
            size_t matchLen = patLen;

            wchar_t* scanPos = pos + patLen;
            while (*scanPos) {
                wchar_t c = *scanPos;
                if ((c >= L'a' && c <= L'z') ||
                    (c >= L'A' && c <= L'Z') ||
                    (c >= L'0' && c <= L'9') ||
                    c == L'_' || c == L'-' || c == L'+' || c == L'/' || c == L'=') {
                    matchLen++;
                    scanPos++;
                } else {
                    break;
                }
            }

            size_t tagLen = wcslen(tag);
            size_t tailLen = wcslen(pos + matchLen);

            memmove(pos + tagLen, pos + matchLen, (tailLen + 1) * sizeof(wchar_t));
            memcpy(pos, tag, tagLen * sizeof(wchar_t));
        }
    }

    LeaveCriticalSection(&g_cs);

    if (foundThreat) {
        DebugLog("Threat found, redacting clipboard");

        if (SetClipboardTextSafe(modifiedText)) {
            DebugLog("Clipboard redacted OK");

            wcsncpy(g_lastClipboard, modifiedText, 2000);
            g_lastClipboard[2000] = L'\0';
        } else {
            DebugLog("Failed to set clipboard");
        }

        if (outThreats && outSize > 0) {
            wcsncpy(outThreats, threatNames, outSize - 1);
            outThreats[outSize - 1] = L'\0';
        }
    }

    free(modifiedText);
    free(clipText);

    return foundThreat;
}

DWORD WINAPI MonitorThread(LPVOID param) {
    DebugLog("Monitor thread started");

    while (g_running) {
        if (g_active) {
            wchar_t* clipText = GetClipboardTextSafe();

            if (clipText) {
                size_t len = wcslen(clipText);

                if (len > 0) {
                    wchar_t sample[2001];
                    wcsncpy(sample, clipText, 2000);
                    sample[2000] = L'\0';

                    if (wcscmp(sample, g_lastClipboard) != 0) {
                        DebugLog("Clipboard changed, len=%d", (int)len);

                        wcsncpy(g_lastClipboard, sample, 2000);
                        g_lastClipboard[2000] = L'\0';

                        free(clipText);
                        clipText = NULL;

                        wchar_t threats[512] = L"";
                        if (ProcessClipboard(threats, 512)) {
                            DebugLog("Threat detected: %ls", threats);

                            if (g_callbackWindow && g_msgThreatDetected) {
                                wchar_t* msgCopy = _wcsdup(threats);
                                if (msgCopy) {
                                    PostMessage(g_callbackWindow, g_msgThreatDetected, (WPARAM)msgCopy, 0);
                                }
                            }
                        }
                    }
                }

                if (clipText) free(clipText);
            }
        }

        Sleep(50);
    }

    DebugLog("Monitor thread exiting");
    return 0;
}

EXPORT BOOL __stdcall InitHook(HWND callbackWindow, UINT msgThreatDetected) {
    DebugLog("InitHook called");

    if (g_initialized) {
        DebugLog("Already initialized");
        return TRUE;
    }

    InitializeCriticalSection(&g_cs);

    g_callbackWindow = callbackWindow;
    g_msgThreatDetected = msgThreatDetected;
    g_running = TRUE;
    g_active = FALSE;
    g_patternCount = 0;
    g_lastClipboard[0] = L'\0';
    g_initialized = TRUE;

    g_monitorThread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);

    DebugLog("InitHook complete");
    return g_monitorThread != NULL;
}

EXPORT void __stdcall CleanupHook(void) {
    DebugLog("CleanupHook called");

    g_active = FALSE;
    g_running = FALSE;

    if (g_monitorThread) {
        WaitForSingleObject(g_monitorThread, 3000);
        CloseHandle(g_monitorThread);
        g_monitorThread = NULL;
    }

    if (g_initialized) {
        DeleteCriticalSection(&g_cs);
        g_initialized = FALSE;
    }

    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }
}

EXPORT void __stdcall SetActive(BOOL active) {
    DebugLog("SetActive: %d", active);
    g_active = active;

    if (active) {
        g_lastClipboard[0] = L'\0';
    }
}

EXPORT BOOL __stdcall IsActive(void) {
    return g_active;
}

EXPORT BOOL __stdcall AddPattern(const wchar_t* name, const wchar_t* pattern, BOOL enabled) {
    if (!g_initialized) return FALSE;
    if (!name || !pattern) return FALSE;
    if (g_patternCount >= MAX_PATTERNS) return FALSE;

    EnterCriticalSection(&g_cs);

    wcsncpy(g_patterns[g_patternCount].name, name, MAX_NAME_LEN - 1);
    g_patterns[g_patternCount].name[MAX_NAME_LEN - 1] = L'\0';

    wcsncpy(g_patterns[g_patternCount].pattern, pattern, MAX_PATTERN_LEN - 1);
    g_patterns[g_patternCount].pattern[MAX_PATTERN_LEN - 1] = L'\0';

    g_patterns[g_patternCount].enabled = enabled ? 1 : 0;

    DebugLog("AddPattern[%d]: %ls", g_patternCount, g_patterns[g_patternCount].name);

    g_patternCount++;

    LeaveCriticalSection(&g_cs);
    return TRUE;
}

EXPORT void __stdcall ClearPatterns(void) {
    if (!g_initialized) return;

    EnterCriticalSection(&g_cs);
    g_patternCount = 0;
    LeaveCriticalSection(&g_cs);

    DebugLog("ClearPatterns called");
}

EXPORT int __stdcall GetPatternCount(void) {
    return g_patternCount;
}

EXPORT BOOL __stdcall TestPattern(const wchar_t* text, const wchar_t* pattern) {
    return FindSubstringW(text, pattern) != NULL;
}

EXPORT BOOL __stdcall ForceCheck(void) {
    DebugLog("ForceCheck called");
    g_lastClipboard[0] = L'\0';

    wchar_t threats[512] = L"";
    return ProcessClipboard(threats, 512);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
