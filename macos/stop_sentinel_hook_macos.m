// stop_sentinel_hook_macos.m
// Compile: gcc -shared -fPIC -o stop_sentinel_hook.dylib stop_sentinel_hook_macos.m -framework Cocoa -lpthread -O2

#import <Cocoa/Cocoa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>

#define MAX_PATTERNS 200
#define MAX_PATTERN_LEN 512
#define MAX_NAME_LEN 128

typedef void (*ThreatCallback)(const char* threats);

typedef struct {
    char name[MAX_NAME_LEN];
    char pattern[MAX_PATTERN_LEN];
    int enabled;
} Pattern;

static Pattern g_patterns[MAX_PATTERNS];
static int g_patternCount = 0;
static volatile int g_active = 0;
static volatile int g_running = 0;
static int g_initialized = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_monitorThread;
static char g_lastClipboard[2048] = "";
static NSInteger g_lastChangeCount = 0;
static FILE* g_logFile = NULL;
static ThreatCallback g_callback = NULL;

void DebugLog(const char* format, ...) {
    if (!g_logFile) {
        g_logFile = fopen("stop_sentinel_debug.log", "a");
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

char ToLowerC(char c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

const char* FindSubstring(const char* text, const char* pattern) {
    if (!text || !pattern || *pattern == '\0') return NULL;
    
    size_t textLen = strlen(text);
    size_t patLen = strlen(pattern);
    
    if (patLen == 0 || patLen > textLen) return NULL;
    
    for (size_t i = 0; i <= textLen - patLen; i++) {
        int match = 1;
        for (size_t j = 0; j < patLen; j++) {
            if (ToLowerC(text[i + j]) != ToLowerC(pattern[j])) {
                match = 0;
                break;
            }
        }
        if (match) return text + i;
    }
    return NULL;
}

char* GetClipboardText(void) {
    @autoreleasepool {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        NSString* text = [pb stringForType:NSPasteboardTypeString];
        
        if (text) {
            return strdup([text UTF8String]);
        }
    }
    return NULL;
}

int SetClipboardText(const char* text) {
    if (!text) return 0;
    
    @autoreleasepool {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        [pb clearContents];
        
        NSString* nsText = [NSString stringWithUTF8String:text];
        if (nsText) {
            [pb setString:nsText forType:NSPasteboardTypeString];
            return 1;
        }
    }
    return 0;
}

int ProcessClipboard(char* outThreats, int outSize) {
    if (!g_active || g_patternCount == 0) return 0;
    
    char* clipText = GetClipboardText();
    if (!clipText || strlen(clipText) == 0) {
        if (clipText) free(clipText);
        return 0;
    }
    
    DebugLog("ProcessClipboard: len=%d", (int)strlen(clipText));
    
    int foundThreat = 0;
    char threatNames[1024] = "";
    
    size_t clipLen = strlen(clipText);
    size_t bufSize = clipLen * 4 + 4096;
    char* modifiedText = (char*)malloc(bufSize);
    if (!modifiedText) {
        free(clipText);
        return 0;
    }
    strcpy(modifiedText, clipText);
    
    pthread_mutex_lock(&g_mutex);
    
    for (int i = 0; i < g_patternCount; i++) {
        if (!g_patterns[i].enabled) continue;
        if (strlen(g_patterns[i].pattern) == 0) continue;
        
        char* pos;
        while ((pos = (char*)FindSubstring(modifiedText, g_patterns[i].pattern)) != NULL) {
            if (!foundThreat) foundThreat = 1;
            
            if (strstr(threatNames, g_patterns[i].name) == NULL) {
                if (strlen(threatNames) > 0) strcat(threatNames, ", ");
                if (strlen(threatNames) + strlen(g_patterns[i].name) < 1000) {
                    strcat(threatNames, g_patterns[i].name);
                }
            }
            
            char tag[256];
            snprintf(tag, 256, "[BLOCKED:%s]", g_patterns[i].name);
            
            size_t patLen = strlen(g_patterns[i].pattern);
            size_t matchLen = patLen;
            
            char* scanPos = pos + patLen;
            while (*scanPos) {
                char c = *scanPos;
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '_' || c == '-' || c == '+' || c == '/' || c == '=') {
                    matchLen++;
                    scanPos++;
                } else {
                    break;
                }
            }
            
            size_t tagLen = strlen(tag);
            size_t tailLen = strlen(pos + matchLen);
            
            memmove(pos + tagLen, pos + matchLen, tailLen + 1);
            memcpy(pos, tag, tagLen);
        }
    }
    
    pthread_mutex_unlock(&g_mutex);
    
    if (foundThreat) {
        DebugLog("Threat found, redacting");
        
        if (SetClipboardText(modifiedText)) {
            DebugLog("Clipboard redacted OK");
            strncpy(g_lastClipboard, modifiedText, 2000);
            g_lastClipboard[2000] = '\0';
        }
        
        if (outThreats && outSize > 0) {
            strncpy(outThreats, threatNames, outSize - 1);
            outThreats[outSize - 1] = '\0';
        }
    }
    
    free(modifiedText);
    free(clipText);
    return foundThreat;
}

void* MonitorThread(void* param) {
    DebugLog("Monitor thread started");
    
    while (g_running) {
        if (g_active) {
            @autoreleasepool {
                NSPasteboard* pb = [NSPasteboard generalPasteboard];
                NSInteger changeCount = [pb changeCount];
                
                if (changeCount != g_lastChangeCount) {
                    g_lastChangeCount = changeCount;
                    DebugLog("Clipboard changed (changeCount=%ld)", (long)changeCount);
                    
                    char threats[512] = "";
                    if (ProcessClipboard(threats, 512)) {
                        DebugLog("Threat detected: %s", threats);
                        
                        // Update change count after our modification
                        g_lastChangeCount = [pb changeCount];
                        
                        if (g_callback) {
                            g_callback(threats);
                        }
                    }
                }
            }
        }
        
        usleep(50000); // 50ms
    }
    
    DebugLog("Monitor thread exiting");
    return NULL;
}

int InitHook(ThreatCallback callback) {
    DebugLog("InitHook called");
    
    if (g_initialized) return 1;
    
    g_callback = callback;
    g_running = 1;
    g_active = 0;
    g_patternCount = 0;
    g_lastClipboard[0] = '\0';
    g_lastChangeCount = 0;
    g_initialized = 1;
    
    if (pthread_create(&g_monitorThread, NULL, MonitorThread, NULL) != 0) {
        DebugLog("Failed to create monitor thread");
        return 0;
    }
    
    DebugLog("InitHook complete");
    return 1;
}

void CleanupHook(void) {
    DebugLog("CleanupHook called");
    g_active = 0;
    g_running = 0;
    pthread_join(g_monitorThread, NULL);
    g_initialized = 0;
    if (g_logFile) { fclose(g_logFile); g_logFile = NULL; }
}

void SetActive(int active) {
    DebugLog("SetActive: %d", active);
    g_active = active;
    if (active) {
        g_lastClipboard[0] = '\0';
        @autoreleasepool {
            g_lastChangeCount = [[NSPasteboard generalPasteboard] changeCount];
        }
    }
}

int IsActive(void) { return g_active; }

int AddPattern(const char* name, const char* pattern, int enabled) {
    if (!g_initialized || !name || !pattern) return 0;
    if (g_patternCount >= MAX_PATTERNS) return 0;
    
    pthread_mutex_lock(&g_mutex);
    strncpy(g_patterns[g_patternCount].name, name, MAX_NAME_LEN - 1);
    g_patterns[g_patternCount].name[MAX_NAME_LEN - 1] = '\0';
    strncpy(g_patterns[g_patternCount].pattern, pattern, MAX_PATTERN_LEN - 1);
    g_patterns[g_patternCount].pattern[MAX_PATTERN_LEN - 1] = '\0';
    g_patterns[g_patternCount].enabled = enabled ? 1 : 0;
    DebugLog("AddPattern[%d]: %s", g_patternCount, g_patterns[g_patternCount].name);
    g_patternCount++;
    pthread_mutex_unlock(&g_mutex);
    return 1;
}

void ClearPatterns(void) {
    if (!g_initialized) return;
    pthread_mutex_lock(&g_mutex);
    g_patternCount = 0;
    pthread_mutex_unlock(&g_mutex);
}

int GetPatternCount(void) { return g_patternCount; }

int ForceCheck(void) {
    DebugLog("ForceCheck called");
    g_lastClipboard[0] = '\0';
    g_lastChangeCount = 0;
    char threats[512] = "";
    return ProcessClipboard(threats, 512);
}
