#ifndef RAW_H
#define RAW_H
#include <mupdf/fitz.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <direct.h>
#include <process.h>
#include <sys/timeb.h>
#include <time.h>
#include <windows.h>

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

static inline int raw_clock_gettime(int clock_id, struct timespec* ts)
{
    (void)clock_id;
    static LARGE_INTEGER frequency;
    static int initialized = 0;
    LARGE_INTEGER counter;

    if (!initialized) {
        QueryPerformanceFrequency(&frequency);
        initialized = 1;
    }

    QueryPerformanceCounter(&counter);
    ts->tv_sec = (time_t)(counter.QuadPart / frequency.QuadPart);
    ts->tv_nsec = (long)(((counter.QuadPart % frequency.QuadPart) * 1000000000LL) / frequency.QuadPart);
    return 0;
}

static inline char* raw_mkdtemp(char* templ)
{
    size_t len = strlen(templ);
    if (len < 6)
        return NULL;

    char* suffix = templ + len - 6;
    for (int attempt = 0; attempt < 100; attempt++) {
        unsigned value = (unsigned)GetCurrentProcessId() ^ (unsigned)time(NULL) ^ (unsigned)attempt;
        static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (int i = 0; i < 6; i++) {
            suffix[i] = alphabet[value % (sizeof(alphabet) - 1)];
            value = value * 1103515245u + 12345u;
        }
        if (_mkdir(templ) == 0)
            return templ;
        if (errno != EEXIST)
            return NULL;
    }
    return NULL;
}

static inline long raw_processor_count(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors > 0 ? (long)info.dwNumberOfProcessors : 1;
}

#define clock_gettime raw_clock_gettime
#define mkdtemp raw_mkdtemp
#define getpid _getpid
#endif

#define OK 0
#define ERR_GENERIC -5
// opaque handles for go
typedef struct context context;
typedef struct page page;
// device operations for table edge capture
typedef struct edge
{
    double x0, y0, x1, y1;
    char orientation; // 'h' or 'v'
} edge;
char* extract_all_pages(const char* pdf_path);
typedef struct fchar
{
    int codepoint;
    float size;
    float bbox_x0, bbox_y0, bbox_x1, bbox_y1;
    uint8_t is_bold;
    uint8_t is_italic;
    uint8_t is_monospaced;
} fchar;
typedef struct fline
{
    float bbox_x0, bbox_y0, bbox_x1, bbox_y1;
    int char_start;
    int char_count;
} fline;
typedef struct fblock
{
    uint8_t type; // 0=text, 1=image
    float bbox_x0, bbox_y0, bbox_x1, bbox_y1;
    int line_start;
    int line_count;
} fblock;
typedef struct flink
{
    float rect_x0, rect_y0, rect_x1, rect_y1;
    char* uri;
} flink;
typedef struct page_data
{
    int page_number;
    float page_x0, page_y0, page_x1, page_y1;
    fblock* blocks;
    int block_count;
    fline* lines;
    int line_count;
    fchar* chars;
    int char_count;
    edge* edges;
    int edge_count;
    flink* links;
    int link_count;
} page_data;
int read_page(const char* filepath, page_data* out);
void free_page(page_data* data);
#endif // RAW_H
