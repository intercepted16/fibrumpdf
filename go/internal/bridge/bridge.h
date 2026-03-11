#ifndef BRIDGE_H
#define BRIDGE_H
#include <mupdf/fitz.h>
#include <stdint.h>
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
typedef struct edge_array
{
    edge* items;
    int count;
    int capacity;
} edge_array;
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
#endif // BRIDGE_H
