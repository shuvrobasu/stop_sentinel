#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <stdarg.h>

#define MAX_PATTERNS 200
#define MAX_PATTERN_LEN 512
#define MAX_NAME_LEN 128
#define MAX_CLIP_LEN 500000
#define MAX_REPLACEMENTS 200
#define POLL_INTERVAL_MS 15
#define CLIPBOARD_RETRY 5
#define CLIPBOARD_RETRY_MS 5
#define EXPORT __declspec(dllexport)

typedef enum {
    PAT_SUBSTRING = 0,
    PAT_REGEX = 1
} PatternType;

typedef struct {
    wchar_t name[MAX_NAME_LEN];
    wchar_t pattern[MAX_PATTERN_LEN];
    int enabled;
    size_t patternLen;
    PatternType type;
} Pattern;

typedef struct {
    size_t start;
    size_t matchLen;
    int patternIndex;
} RedactionEntry;

static Pattern g_patterns[MAX_PATTERNS];
static int g_patternCount = 0;
static HWND g_callbackWindow = NULL;
static UINT g_msgThreatDetected = 0;
static volatile BOOL g_active = FALSE;
static volatile BOOL g_running = FALSE;
static BOOL g_initialized = FALSE;
static CRITICAL_SECTION g_cs;
static HANDLE g_monitorThread = NULL;
static wchar_t g_lastClipboard[4096] = L"";
static size_t g_lastClipLen = 0;
static FILE* g_logFile = NULL;

// ============================================================
// LOGGING
// ============================================================
void DebugLog(const char* format, ...) {
    if (!g_logFile) {
        g_logFile = fopen("stop_sentinel_debug.log", "a");
        if (!g_logFile) return;
    }
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    if (!t) return;
    fprintf(g_logFile, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
}

// ============================================================
// STRING HELPERS
// ============================================================
static inline wchar_t ToLowerW(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? (c + 32) : c;
}

static inline BOOL IsTokenChar(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
           (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' ||
           c == L'+' || c == L'/' || c == L'=' || c == L'.';
}

static inline BOOL IsDigit(wchar_t c) {
    return c >= L'0' && c <= L'9';
}

static inline BOOL IsAlpha(wchar_t c) {
    return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
}

static inline BOOL IsAlphaNum(wchar_t c) {
    return IsAlpha(c) || IsDigit(c);
}

static inline BOOL IsUpper(wchar_t c) {
    return c >= L'A' && c <= L'Z';
}

static inline BOOL IsLower(wchar_t c) {
    return c >= L'a' && c <= L'z';
}

static inline BOOL IsHexDigit(wchar_t c) {
    return IsDigit(c) || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
}

static inline BOOL IsWordChar(wchar_t c) {
    return IsAlphaNum(c) || c == L'_';
}

static inline BOOL IsSpace(wchar_t c) {
    return c == L' ' || c == L'\t' || c == L'\n' || c == L'\r';
}

static size_t SafeWcslen(const wchar_t* s, size_t maxLen) {
    if (!s) return 0;
    size_t len = 0;
    while (len < maxLen && s[len] != L'\0') len++;
    return len;
}

// ============================================================
// MINI REGEX ENGINE
// Supports: . \d \w \s \b [] [^] {n} {n,m} ? + * | () ^ $
// Character classes: [A-Z] [0-9] [a-zA-Z0-9] [^x]
// Enough for PAN, Aadhaar, SSN, credit cards, emails, IPs
// ============================================================

typedef struct {
    const wchar_t* start;
    size_t length;
} RegexMatch;

// Check if character matches a character class like [A-Z0-9]
static BOOL MatchCharClass(const wchar_t* classStr, size_t classLen, wchar_t c) {
    BOOL negate = FALSE;
    size_t i = 0;

    if (classLen > 0 && classStr[0] == L'^') {
        negate = TRUE;
        i = 1;
    }

    BOOL matched = FALSE;
    while (i < classLen && !matched) {
        // Handle escape sequences inside class
        if (classStr[i] == L'\\' && i + 1 < classLen) {
            switch (classStr[i + 1]) {
                case L'd': matched = IsDigit(c); break;
                case L'D': matched = !IsDigit(c); break;
                case L'w': matched = IsWordChar(c); break;
                case L'W': matched = !IsWordChar(c); break;
                case L's': matched = IsSpace(c); break;
                case L'S': matched = !IsSpace(c); break;
                default: matched = (c == classStr[i + 1]); break;
            }
            i += 2;
            continue;
        }

        // Handle range like A-Z
        if (i + 2 < classLen && classStr[i + 1] == L'-') {
            wchar_t lo = classStr[i];
            wchar_t hi = classStr[i + 2];
            if (c >= lo && c <= hi) {
                matched = TRUE;
            }
            i += 3;
        } else {
            if (c == classStr[i]) {
                matched = TRUE;
            }
            i++;
        }
    }

    return negate ? !matched : matched;

}

// Parse {n} or {n,m} quantifier, return how many chars consumed from pattern
static int ParseQuantifier(const wchar_t* pat, int* minRep, int* maxRep) {
    *minRep = 0;
    *maxRep = 0;

    if (*pat != L'{') return 0;

    const wchar_t* p = pat + 1;
    int pos = 1;

    // Parse min
    while (IsDigit(*p)) {
        *minRep = *minRep * 10 + (*p - L'0');
        p++;
        pos++;
    }

    if (*p == L'}') {
        *maxRep = *minRep;
        return pos + 1;
    }

    if (*p == L',') {
        p++;
        pos++;
        if (*p == L'}') {
            *maxRep = 9999; // Unlimited
            return pos + 1;
        }
        while (IsDigit(*p)) {
            *maxRep = *maxRep * 10 + (*p - L'0');
            p++;
            pos++;
        }
        if (*p == L'}') {
            return pos + 1;
        }
    }

    return 0; // Invalid quantifier
}

// Find end of character class ]
static size_t FindClassEnd(const wchar_t* pat) {
    size_t i = 0;
    if (pat[i] == L'^') i++;
    if (pat[i] == L']') i++; // ] at start is literal
    while (pat[i] != L'\0' && pat[i] != L']') i++;
    return i;
}

// Match a single regex element against text at position
// Returns number of characters matched, -1 if no match
static int MatchElement(const wchar_t* text, size_t textLen, size_t textPos,
                        const wchar_t* pat, size_t* patConsumed) {
    if (textPos >= textLen || *pat == L'\0') {
        *patConsumed = 0;
        return -1;
    }

    wchar_t c = text[textPos];

    // Escape sequences
    if (*pat == L'\\') {
        *patConsumed = 2;
        switch (pat[1]) {
            case L'd': return IsDigit(c) ? 1 : -1;
            case L'D': return !IsDigit(c) ? 1 : -1;
            case L'w': return IsWordChar(c) ? 1 : -1;
            case L'W': return !IsWordChar(c) ? 1 : -1;
            case L's': return IsSpace(c) ? 1 : -1;
            case L'S': return !IsSpace(c) ? 1 : -1;
            case L'b': return 0; // Word boundary handled in RegexMatchAt
            default: return (c == pat[1]) ? 1 : -1;
        }
    }

    // Character class [...]
    if (*pat == L'[') {
        size_t classEnd = FindClassEnd(pat + 1);
        *patConsumed = classEnd + 2;
        return MatchCharClass(pat + 1, classEnd, c) ? 1 : -1;
    }

    // Wildcard
    if (*pat == L'.') {
        *patConsumed = 1;
        return (c != L'\n') ? 1 : -1;
    }

    // Literal character (case insensitive)
    *patConsumed = 1;
    return (ToLowerW(c) == ToLowerW(*pat)) ? 1 : -1;
}

// Core regex matcher - recursive with quantifiers
static BOOL RegexMatchAt(const wchar_t* text, size_t textLen, size_t textPos,
                         const wchar_t* pat, size_t patLen, size_t patPos,
                         int depth) {
    if (depth > 100) return FALSE; // Prevent stack overflow

    // End of pattern = match
    if (patPos >= patLen) return TRUE;

    // $ anchor
    if (pat[patPos] == L'$' && patPos + 1 >= patLen) {
        return textPos >= textLen;
    }

    // Word boundary \b
    if (pat[patPos] == L'\\' && patPos + 1 < patLen && pat[patPos + 1] == L'b') {
        BOOL prevWord = (textPos > 0) && IsWordChar(text[textPos - 1]);
        BOOL currWord = (textPos < textLen) && IsWordChar(text[textPos]);
        BOOL isBoundary = (prevWord != currWord);
        if (!isBoundary) return FALSE;
        return RegexMatchAt(text, textLen, textPos, pat, patLen, patPos + 2, depth + 1);
    }

    // Get current element
    size_t elemConsumed = 0;
    int elemMatch = MatchElement(text, textLen, textPos, pat + patPos, &elemConsumed);

    if (elemConsumed == 0) return FALSE;

    // Check for quantifier after element
    size_t qPos = patPos + elemConsumed;

    if (qPos < patLen) {
        wchar_t q = pat[qPos];

        // {n} or {n,m}
        if (q == L'{') {
            int minRep, maxRep;
            int qLen = ParseQuantifier(pat + qPos, &minRep, &maxRep);
            if (qLen > 0) {
                size_t nextPatPos = qPos + qLen;

                // Try matching minRep to maxRep times
                for (int count = 0; count <= maxRep && textPos + count <= textLen; count++) {
                    if (count >= minRep) {
                        if (RegexMatchAt(text, textLen, textPos + count,
                                         pat, patLen, nextPatPos, depth + 1)) {
                            return TRUE;
                        }
                    }
                    if (count < maxRep) {
                        size_t dummy;
                        int m = MatchElement(text, textLen, textPos + count,
                                             pat + patPos, &dummy);
                        if (m < 1) break;
                    }
                }
                return FALSE;
            }
        }

        // ? quantifier
        if (q == L'?') {
            size_t nextPatPos = qPos + 1;
            // Try with match
            if (elemMatch >= 0) {
                if (RegexMatchAt(text, textLen, textPos + 1,
                                 pat, patLen, nextPatPos, depth + 1)) {
                    return TRUE;
                }
            }
            // Try without match
            return RegexMatchAt(text, textLen, textPos,
                                pat, patLen, nextPatPos, depth + 1);
        }

        // + quantifier (1 or more)
        if (q == L'+') {
            if (elemMatch < 1) return FALSE;
            size_t nextPatPos = qPos + 1;
            size_t pos = textPos + 1;

            // Match as many as possible (greedy)
            while (pos < textLen) {
                size_t dummy;
                int m = MatchElement(text, textLen, pos, pat + patPos, &dummy);
                if (m < 1) break;
                pos++;
            }

            // Try from longest to shortest
            while (pos > textPos) {
                if (RegexMatchAt(text, textLen, pos,
                                 pat, patLen, nextPatPos, depth + 1)) {
                    return TRUE;
                }
                pos--;
            }
            return FALSE;
        }

        // * quantifier (0 or more)
        if (q == L'*') {
            size_t nextPatPos = qPos + 1;
            size_t pos = textPos;

            // Match as many as possible
            while (pos < textLen) {
                size_t dummy;
                int m = MatchElement(text, textLen, pos, pat + patPos, &dummy);
                if (m < 1) break;
                pos++;
            }

            // Try from longest to shortest
            while (pos >= textPos) {
                if (RegexMatchAt(text, textLen, pos,
                                 pat, patLen, nextPatPos, depth + 1)) {
                    return TRUE;
                }
                if (pos == textPos) break;
                pos--;
            }
            return FALSE;
        }
    }

    // No quantifier - simple match
    if (elemMatch < 0) return FALSE;

    return RegexMatchAt(text, textLen, textPos + (elemMatch > 0 ? elemMatch : 0),
                        pat, patLen, patPos + elemConsumed, depth + 1);
}

// Find regex match in text, return position and length
static BOOL RegexSearch(const wchar_t* text, size_t textLen,
                        const wchar_t* pat, size_t patLen,
                        size_t* matchStart, size_t* matchLen) {
    if (!text || !pat || textLen == 0 || patLen == 0) return FALSE;

    size_t startPos = 0;
    BOOL anchored = FALSE;

    // ^ anchor
    if (pat[0] == L'^') {
        anchored = TRUE;
        pat++;
        patLen--;
    }

    for (size_t i = startPos; i < textLen; i++) {
        // Try matching at each position
        size_t savedPos = i;

        if (RegexMatchAt(text, textLen, i, pat, patLen, 0, 0)) {
            *matchStart = i;

            // Find match length by trying longer matches
            size_t len = 1;
            while (i + len <= textLen) {
                if (RegexMatchAt(text, textLen, i, pat, patLen, 0, 0)) {
                    len++;
                } else {
                    break;
                }
                if (len > textLen - i) break;
            }

            // Find actual end by checking where the rest of text starts not matching
            // Simple approach: extend while token chars continue after initial match
            size_t endPos = i + 1;
            while (endPos < textLen && IsTokenChar(text[endPos])) {
                endPos++;
            }

            // But limit to reasonable regex match - use pattern structure
            // For now use the greedy approach: re-run match to find actual consumed length
            size_t actualLen = 0;
            for (size_t tryLen = textLen - i; tryLen >= 1; tryLen--) {
                // Check if pattern matches exactly tryLen characters
                if (RegexMatchAt(text, textLen, i, pat, patLen, 0, 0)) {
                    actualLen = tryLen;
                    break;
                }
            }

            if (actualLen == 0) actualLen = 1;
            *matchLen = actualLen;
            return TRUE;
        }

        if (anchored) break;
    }

    return FALSE;
}

// Simpler version: just check if regex matches anywhere in text
static BOOL RegexContains(const wchar_t* text, size_t textLen,
                          const wchar_t* pat, size_t patLen) {
    if (!text || !pat || textLen == 0 || patLen == 0) return FALSE;

    size_t start = 0;
    BOOL anchored = FALSE;

    if (pat[0] == L'^') {
        anchored = TRUE;
        start = 0;
    }

    const wchar_t* actualPat = (pat[0] == L'^') ? pat + 1 : pat;
    size_t actualPatLen = (pat[0] == L'^') ? patLen - 1 : patLen;

    for (size_t i = start; i < textLen; i++) {
        if (RegexMatchAt(text, textLen, i, actualPat, actualPatLen, 0, 0)) {
            return TRUE;
        }
        if (anchored) break;
    }

    return FALSE;
}

// Find match position and compute match length
static BOOL RegexFind(const wchar_t* text, size_t textLen,
                      const wchar_t* pat, size_t patLen,
                      size_t* outStart, size_t* outLen) {
    if (!text || !pat || textLen == 0 || patLen == 0) return FALSE;

    const wchar_t* actualPat = pat;
    size_t actualPatLen = patLen;
    BOOL anchored = FALSE;

    if (pat[0] == L'^') {
        anchored = TRUE;
        actualPat = pat + 1;
        actualPatLen = patLen - 1;
    }

    for (size_t i = 0; i < textLen; i++) {
        if (RegexMatchAt(text, textLen, i, actualPat, actualPatLen, 0, 0)) {
            *outStart = i;

            // Find exact match length by trying each end position
            size_t bestEnd = i + 1;

            // Binary search for longest match
            for (size_t tryEnd = i + 1; tryEnd <= textLen; tryEnd++) {
                // Create a sub-view and check if pattern still matches
                // Simple: extend while the char at tryEnd is part of the token
                // AND the pattern would still match starting at i
                if (IsTokenChar(text[tryEnd - 1])) {
                    bestEnd = tryEnd;
                } else {
                    break;
                }
            }

            *outLen = bestEnd - i;
            if (*outLen == 0) *outLen = 1;
            return TRUE;
        }
        if (anchored) break;
    }

    return FALSE;
}
// ============================================================
// SUBSTRING MATCHER
// ============================================================
const wchar_t* FindSubstringW(const wchar_t* text, size_t textLen,
                               const wchar_t* pattern, size_t patLen) {
    if (!text || !pattern || patLen == 0 || patLen > textLen) return NULL;

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

// ============================================================
// UNIFIED PATTERN MATCHER
// Returns TRUE if pattern found, sets outStart and outLen
// ============================================================
static BOOL MatchPattern(const wchar_t* text, size_t textLen,
                         Pattern* pat, size_t searchOffset,
                         size_t* outStart, size_t* outLen) {
    if (pat->type == PAT_SUBSTRING) {
        const wchar_t* found = FindSubstringW(text + searchOffset,
                                                textLen - searchOffset,
                                                pat->pattern, pat->patternLen);
        if (!found) return FALSE;

        *outStart = (size_t)(found - text);
        size_t matchLen = pat->patternLen;

        // Extend to full token
        size_t extPos = *outStart + matchLen;
        while (extPos < textLen && IsTokenChar(text[extPos])) {
            matchLen++;
            extPos++;
        }
        *outLen = matchLen;
        return TRUE;

    } else if (pat->type == PAT_REGEX) {
        size_t start, len;
        if (RegexFind(text + searchOffset, textLen - searchOffset,
                      pat->pattern, pat->patternLen, &start, &len)) {
            *outStart = searchOffset + start;
            *outLen = len;
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================
// CLIPBOARD ACCESS
// ============================================================
static BOOL OpenClipboardSafe(void) {
    for (int retry = 0; retry < CLIPBOARD_RETRY; retry++) {
        if (OpenClipboard(NULL)) return TRUE;
        Sleep(CLIPBOARD_RETRY_MS);
    }
    return FALSE;
}

wchar_t* GetClipboardTextSafe(size_t* outLen) {
    wchar_t* result = NULL;
    if (outLen) *outLen = 0;

    if (!OpenClipboardSafe()) return NULL;

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) { CloseClipboard(); return NULL; }

    SIZE_T globalSize = GlobalSize(hData);
    if (globalSize == 0 || globalSize > MAX_CLIP_LEN * sizeof(wchar_t)) {
        CloseClipboard();
        return NULL;
    }

    wchar_t* pData = (wchar_t*)GlobalLock(hData);
    if (!pData) { CloseClipboard(); return NULL; }

    size_t maxChars = globalSize / sizeof(wchar_t);
    size_t len = SafeWcslen(pData, maxChars);

    if (len > 0 && len < MAX_CLIP_LEN) {
        result = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      (len + 1) * sizeof(wchar_t));
        if (result) {
            memcpy(result, pData, len * sizeof(wchar_t));
            result[len] = L'\0';
            if (outLen) *outLen = len;
        }
    }

    GlobalUnlock(hData);
    CloseClipboard();
    return result;
}

BOOL SetClipboardTextSafe(const wchar_t* text, size_t len) {
    if (!text || len == 0 || len > MAX_CLIP_LEN) return FALSE;
    if (!OpenClipboardSafe()) return FALSE;

    BOOL success = FALSE;
    EmptyClipboard();

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,
                                (len + 1) * sizeof(wchar_t));
    if (hMem) {
        wchar_t* pMem = (wchar_t*)GlobalLock(hMem);
        if (pMem) {
            memcpy(pMem, text, len * sizeof(wchar_t));
            pMem[len] = L'\0';
            GlobalUnlock(hMem);
            if (SetClipboardData(CF_UNICODETEXT, hMem))
                success = TRUE;
            else
                GlobalFree(hMem);
        } else {
            GlobalFree(hMem);
        }
    }

    CloseClipboard();
    return success;
}

// ============================================================
// MONITOR THREAD
// ============================================================
DWORD WINAPI MonitorThread(LPVOID param) {
    DebugLog("Monitor thread started");

    while (g_running) {
        if (g_active) {
            size_t clipLen = 0;
            wchar_t* clipText = GetClipboardTextSafe(&clipLen);

            if (clipText && clipLen > 0) {
                BOOL changed = FALSE;

                if (clipLen != g_lastClipLen) {
                    changed = TRUE;
                } else {
                    size_t cmpLen = clipLen < 4000 ? clipLen : 4000;
                    changed = (wmemcmp(clipText, g_lastClipboard, cmpLen) != 0);
                }

                if (changed) {
                    size_t copyLen = clipLen < 4000 ? clipLen : 4000;
                    memcpy(g_lastClipboard, clipText, copyLen * sizeof(wchar_t));
                    g_lastClipboard[copyLen] = L'\0';
                    g_lastClipLen = copyLen;

                    // Scan all patterns (both substring and regex)
                    RedactionEntry redactions[MAX_REPLACEMENTS];
                    int redactionCount = 0;
                    wchar_t threatNames[1024] = L"";
                    BOOL foundThreat = FALSE;

                    EnterCriticalSection(&g_cs);

                    for (int i = 0; i < g_patternCount && redactionCount < MAX_REPLACEMENTS; i++) {
                        if (!g_patterns[i].enabled || g_patterns[i].patternLen == 0) continue;

                        size_t searchOffset = 0;
                        int matchCount = 0;

                        while (searchOffset < clipLen &&
                               redactionCount < MAX_REPLACEMENTS &&
                               matchCount < 50) {

                            size_t matchStart, matchLen;
                            if (!MatchPattern(clipText, clipLen, &g_patterns[i],
                                              searchOffset, &matchStart, &matchLen)) {
                                break;
                            }

                            // Check overlap with existing redactions
                            BOOL overlaps = FALSE;
                            for (int r = 0; r < redactionCount; r++) {
                                size_t rEnd = redactions[r].start + redactions[r].matchLen;
                                size_t mEnd = matchStart + matchLen;
                                if (matchStart < rEnd && mEnd > redactions[r].start) {
                                    overlaps = TRUE;
                                    break;
                                }
                            }

                            if (!overlaps) {
                                redactions[redactionCount].start = matchStart;
                                redactions[redactionCount].matchLen = matchLen;
                                redactions[redactionCount].patternIndex = i;
                                redactionCount++;
                                foundThreat = TRUE;
                                matchCount++;

                                if (wcsstr(threatNames, g_patterns[i].name) == NULL) {
                                    size_t tnLen = wcslen(threatNames);
                                    if (tnLen + wcslen(g_patterns[i].name) + 3 < 1000) {
                                        if (tnLen > 0) wcscat(threatNames, L", ");
                                        wcscat(threatNames, g_patterns[i].name);
                                    }
                                }
                            }

                            searchOffset = matchStart + matchLen;
                        }
                    }

                    LeaveCriticalSection(&g_cs);

                    if (foundThreat && redactionCount > 0) {
                        // Sort descending by position
                        for (int i = 0; i < redactionCount - 1; i++) {
                            for (int j = i + 1; j < redactionCount; j++) {
                                if (redactions[j].start > redactions[i].start) {
                                    RedactionEntry tmp = redactions[i];
                                    redactions[i] = redactions[j];
                                    redactions[j] = tmp;
                                }
                            }
                        }

                        // Calculate buffer
                        size_t extraNeeded = 0;
                        for (int i = 0; i < redactionCount; i++) {
                            wchar_t tag[256];
                            swprintf(tag, 256, L"[BLOCKED:%ls]",
                                     g_patterns[redactions[i].patternIndex].name);
                            size_t tagLen = wcslen(tag);
                            if (tagLen > redactions[i].matchLen)
                                extraNeeded += (tagLen - redactions[i].matchLen);
                        }

                        size_t bufSize = clipLen + extraNeeded + 512;
                        wchar_t* result = (wchar_t*)HeapAlloc(GetProcessHeap(),
                                           HEAP_ZERO_MEMORY, (bufSize + 1) * sizeof(wchar_t));

                        if (result) {
                            memcpy(result, clipText, (clipLen + 1) * sizeof(wchar_t));

                            for (int i = 0; i < redactionCount; i++) {
                                wchar_t tag[256];
                                swprintf(tag, 256, L"[BLOCKED:%ls]",
                                         g_patterns[redactions[i].patternIndex].name);
                                size_t tagLen = wcslen(tag);
                                size_t start = redactions[i].start;
                                size_t matchLen = redactions[i].matchLen;
                                size_t currentLen = wcslen(result);

                                if (start + matchLen > currentLen) continue;
                                if (currentLen + tagLen - matchLen + 1 > bufSize) continue;

                                size_t tailLen = currentLen - (start + matchLen);
                                memmove(result + start + tagLen,
                                        result + start + matchLen,
                                        (tailLen + 1) * sizeof(wchar_t));
                                memcpy(result + start, tag, tagLen * sizeof(wchar_t));
                            }

                            size_t resultLen = wcslen(result);
                            if (SetClipboardTextSafe(result, resultLen)) {
                                DebugLog("BLOCKED %d threats", redactionCount);

                                copyLen = resultLen < 4000 ? resultLen : 4000;
                                memcpy(g_lastClipboard, result, copyLen * sizeof(wchar_t));
                                g_lastClipboard[copyLen] = L'\0';
                                g_lastClipLen = copyLen;

                                if (g_callbackWindow && g_msgThreatDetected) {
                                    size_t tLen = wcslen(threatNames);
                                    wchar_t* msgCopy = (wchar_t*)HeapAlloc(
                                        GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        (tLen + 1) * sizeof(wchar_t));
                                    if (msgCopy) {
                                        memcpy(msgCopy, threatNames,
                                               (tLen + 1) * sizeof(wchar_t));
                                        if (!PostMessage(g_callbackWindow,
                                                         g_msgThreatDetected,
                                                         (WPARAM)msgCopy, 0)) {
                                            HeapFree(GetProcessHeap(), 0, msgCopy);
                                        }
                                    }
                                }
                            }

                            HeapFree(GetProcessHeap(), 0, result);
                        }
                    }
                }

                if (clipText) HeapFree(GetProcessHeap(), 0, clipText);
            } else if (clipText) {
                HeapFree(GetProcessHeap(), 0, clipText);
            }
        }

        Sleep(POLL_INTERVAL_MS);
    }

    DebugLog("Monitor thread exiting");
    return 0;
}

// ============================================================
// EXPORTS
// ============================================================
EXPORT BOOL __stdcall InitHook(HWND callbackWindow, UINT msgThreatDetected) {
    DebugLog("InitHook called");
    if (g_initialized) return TRUE;

    InitializeCriticalSection(&g_cs);
    g_callbackWindow = callbackWindow;
    g_msgThreatDetected = msgThreatDetected;
    g_running = TRUE;
    g_active = FALSE;
    g_patternCount = 0;
    g_lastClipboard[0] = L'\0';
    g_lastClipLen = 0;
    g_initialized = TRUE;

    g_monitorThread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);
    if (!g_monitorThread) {
        g_initialized = FALSE;
        return FALSE;
    }

    DebugLog("InitHook complete");
    return TRUE;
}

EXPORT void __stdcall CleanupHook(void) {
    DebugLog("CleanupHook");
    g_active = FALSE;
    g_running = FALSE;

    if (g_monitorThread) {
        DWORD r = WaitForSingleObject(g_monitorThread, 5000);
        if (r == WAIT_TIMEOUT) TerminateThread(g_monitorThread, 0);
        CloseHandle(g_monitorThread);
        g_monitorThread = NULL;
    }

    if (g_initialized) {
        DeleteCriticalSection(&g_cs);
        g_initialized = FALSE;
    }

    if (g_logFile) { fflush(g_logFile); fclose(g_logFile); g_logFile = NULL; }
}

EXPORT void __stdcall SetActive(BOOL active) {
    DebugLog("SetActive: %d", active);
    g_active = active;
    if (active) { g_lastClipboard[0] = L'\0'; g_lastClipLen = 0; }
}

EXPORT BOOL __stdcall IsActive(void) { return g_active; }

// type: 0 = substring, 1 = regex
EXPORT BOOL __stdcall AddPatternEx(const wchar_t* name, const wchar_t* pattern,
                                    BOOL enabled, int type) {
    if (!g_initialized || !name || !pattern) return FALSE;
    if (g_patternCount >= MAX_PATTERNS) return FALSE;

    size_t nameLen = SafeWcslen(name, MAX_NAME_LEN);
    size_t patLen = SafeWcslen(pattern, MAX_PATTERN_LEN);
    if (nameLen == 0 || patLen == 0) return FALSE;

    EnterCriticalSection(&g_cs);

    wcsncpy(g_patterns[g_patternCount].name, name, MAX_NAME_LEN - 1);
    g_patterns[g_patternCount].name[MAX_NAME_LEN - 1] = L'\0';
    wcsncpy(g_patterns[g_patternCount].pattern, pattern, MAX_PATTERN_LEN - 1);
    g_patterns[g_patternCount].pattern[MAX_PATTERN_LEN - 1] = L'\0';
    g_patterns[g_patternCount].enabled = enabled ? 1 : 0;
    g_patterns[g_patternCount].patternLen = patLen;
    g_patterns[g_patternCount].type = (type == 1) ? PAT_REGEX : PAT_SUBSTRING;

    DebugLog("AddPattern[%d]: %ls (%s, len=%zu)",
             g_patternCount, g_patterns[g_patternCount].name,
             type == 1 ? "regex" : "substring", patLen);

    g_patternCount++;
    LeaveCriticalSection(&g_cs);
    return TRUE;
}

// Backward compatible - defaults to substring
EXPORT BOOL __stdcall AddPattern(const wchar_t* name, const wchar_t* pattern, BOOL enabled) {
    return AddPatternEx(name, pattern, enabled, 0);
}

EXPORT void __stdcall ClearPatterns(void) {
    if (!g_initialized) return;
    EnterCriticalSection(&g_cs);
    g_patternCount = 0;
    memset(g_patterns, 0, sizeof(g_patterns));
    LeaveCriticalSection(&g_cs);
    DebugLog("ClearPatterns done");
}

EXPORT int __stdcall GetPatternCount(void) { return g_patternCount; }

EXPORT BOOL __stdcall TestPattern(const wchar_t* text, const wchar_t* pattern) {
    if (!text || !pattern) return FALSE;
    size_t textLen = SafeWcslen(text, MAX_CLIP_LEN);
    size_t patLen = SafeWcslen(pattern, MAX_PATTERN_LEN);
    return FindSubstringW(text, textLen, pattern, patLen) != NULL;
}

EXPORT BOOL __stdcall ForceCheck(void) {
    DebugLog("ForceCheck");
    g_lastClipboard[0] = L'\0';
    g_lastClipLen = 0;
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(hinstDLL);
    return TRUE;
}
