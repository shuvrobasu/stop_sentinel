// stop_sentinel_hook_linux.c
// Compile: gcc -shared -fPIC -o stop_sentinel_hook.so stop_sentinel_hook_linux.c -lX11 -lpthread -O2
#include <sys/time.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>

#define MAX_PATTERNS 200
#define MAX_PATTERN_LEN 512
#define MAX_NAME_LEN 128
#define MAX_CLIP_LEN 1000000

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
static FILE* g_logFile = NULL;
static ThreatCallback g_callback = NULL;
static Display* g_display = NULL;

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
    Display* display = XOpenDisplay(NULL);
    if (!display) return NULL;
    
    Window root = DefaultRootWindow(display);
    Atom clipboard = XInternAtom(display, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(display, "UTF8_STRING", False);
    Atom target = XInternAtom(display, "STOP_SENTINEL_SEL", False);
    
    // Create temporary window for selection
    Window win = XCreateSimpleWindow(display, root, 0, 0, 1, 1, 0, 0, 0);
    
    // Request clipboard content
    XConvertSelection(display, clipboard, utf8, target, win, CurrentTime);
    XFlush(display);
    
    // Wait for SelectionNotify event
    XEvent event;
    char* result = NULL;
    
    // Timeout after 200ms
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        if (XPending(display)) {
            XNextEvent(display, &event);
            
            if (event.type == SelectionNotify) {
                if (event.xselection.property != None) {
                    Atom type;
                    int format;
                    unsigned long items, bytes;
                    unsigned char* data = NULL;
                    
                    XGetWindowProperty(display, win, target, 0, MAX_CLIP_LEN, False,
                                       AnyPropertyType, &type, &format, &items, &bytes, &data);
                    
                    if (data && items > 0) {
                        result = strdup((char*)data);
                    }
                    
                    if (data) XFree(data);
                }
                break;
            }
        }
        
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        if (elapsed > 200) break;
        
        usleep(1000);
    }
    
    XDestroyWindow(display, win);
    XCloseDisplay(display);
    
    return result;
}

int SetClipboardText(const char* text) {
    if (!text) return 0;
    
    // Use xclip for reliable clipboard setting
    FILE* pipe = popen("xclip -selection clipboard", "w");
    if (!pipe) {
        // Fallback to xsel
        pipe = popen("xsel --clipboard --input", "w");
        if (!pipe) return 0;
    }
    
    fputs(text, pipe);
    int result = pclose(pipe);
    
    return result == 0;
}

int ProcessClipboard(char* outThreats, int outSize) {
    if (!g_active || g_patternCount == 0) return 0;
    
    char* clipText = GetClipboardText();
    if (!clipText) return 0;
    
    size_t clipLen = strlen(clipText);
    if (clipLen == 0) {
        free(clipText);
        return 0;
    }
    
    DebugLog("ProcessClipboard: len=%d", (int)clipLen);
    
    int foundThreat = 0;
    char threatNames[1024] = "";
    
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
                if ((c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
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
            char* clipText = GetClipboardText();
            
            if (clipText && strlen(clipText) > 0) {
                char sample[2001];
                strncpy(sample, clipText, 2000);
                sample[2000] = '\0';
                
                if (strcmp(sample, g_lastClipboard) != 0) {
                    DebugLog("Clipboard changed, len=%d", (int)strlen(clipText));
                    strncpy(g_lastClipboard, sample, 2000);
                    g_lastClipboard[2000] = '\0';
                    
                    free(clipText);
                    clipText = NULL;
                    
                    char threats[512] = "";
                    if (ProcessClipboard(threats, 512)) {
                        DebugLog("Threat detected: %s", threats);
                        
                        if (g_callback) {
                            g_callback(threats);
                        }
                    }
                }
            }
            
            if (clipText) free(clipText);
        }
        
        usleep(50000); // 50ms
    }
    
    DebugLog("Monitor thread exiting");
    return NULL;
}

// Exported functions
int InitHook(ThreatCallback callback) {
    DebugLog("InitHook called");
    
    if (g_initialized) return 1;
    
    g_callback = callback;
    g_running = 1;
    g_active = 0;
    g_patternCount = 0;
    g_lastClipboard[0] = '\0';
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
    
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }
}

void SetActive(int active) {
    DebugLog("SetActive: %d", active);
    g_active = active;
    if (active) g_lastClipboard[0] = '\0';
}

int IsActive(void) {
    return g_active;
}

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
    DebugLog("ClearPatterns called");
}

int GetPatternCount(void) {
    return g_patternCount;
}

int ForceCheck(void) {
    DebugLog("ForceCheck called");
    g_lastClipboard[0] = '\0';
    char threats[512] = "";
    return ProcessClipboard(threats, 512);
}
