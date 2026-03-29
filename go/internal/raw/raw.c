// why do logic in here > just wrapping fz functions via cgo?
// performance. the thousands of `cgo` calls added up
// (approx. 3x slower overall)
// so, use one function that writes to disk instead, much less overhead.
// this is mostly pre existing logic just written to be used via Go.
// additionally, the raw 'binary' format is used for performance and less disk usage. json gets very taxing on thousands of chars.
//
#include "raw.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#include <math.h>

#define EDGE_MIN_LENGTH 3.0
#define EDGE_MAX_WIDTH 3.0
#define FZ_STORE_SIZE 32 * 1024 * 1024 // 32MB
#define MIN_EDGE_LENGTH 6.0
#define EDGE_DUP_TOL 0.35
#define MAX_DUP_CHECK 48

typedef struct
{
    fz_device super;
    fz_device* stext_dev;  
    fz_buffer* edges_buf;
} combined_device;

typedef struct {
    fz_font* font;
    unsigned char flags;
} font_cache_entry;


#define FONT_CACHE_SIZE 256
typedef struct {
    pthread_mutex_t lock;
    font_cache_entry entries[FONT_CACHE_SIZE];
    int len;
} shared_font_cache;

static shared_font_cache* global_font_cache = NULL;

static int contains_token_ci(const char* haystack, const char* needle) {
    if (!haystack || !needle || !needle[0])
        return 0;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen)
        return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j = 0;
        while (j < nlen) {
            unsigned char hc = (unsigned char)haystack[i + j];
            unsigned char nc = (unsigned char)needle[j];
            if (tolower(hc) != tolower(nc))
                break;
            j++;
        }
        if (j == nlen)
            return 1;
    }
    return 0;
}

static unsigned char infer_style_from_font_name(const char* name) {
    if (!name || !name[0])
        return 0;

    unsigned char flags = 0;
    if (contains_token_ci(name, "bold") || contains_token_ci(name, "black") ||
        contains_token_ci(name, "heavy") || contains_token_ci(name, "semibold") ||
        contains_token_ci(name, "demi")) {
        flags |= 1;
    }
    if (contains_token_ci(name, "italic") || contains_token_ci(name, "oblique") ||
        contains_token_ci(name, "kursiv") || contains_token_ci(name, "slanted")) {
        flags |= 2;
    }
    return flags;
}

/* Initialize shared font cache (call in parent before fork) */
static int init_shared_font_cache(void) {
    global_font_cache = mmap(NULL, sizeof(shared_font_cache), 
                             PROT_READ | PROT_WRITE, 
                             MAP_SHARED | MAP_ANONYMOUS, 
                             -1, 0);
    if (global_font_cache == MAP_FAILED)
        return -1;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    int ret = pthread_mutex_init(&global_font_cache->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    
    if (ret != 0) {
        munmap(global_font_cache, sizeof(shared_font_cache));
        global_font_cache = NULL;
        return -1;
    }

    global_font_cache->len = 0;
    return 0;
}

/* Cleanup shared font cache (call after all workers finish) */
static void cleanup_shared_font_cache(void) {
    if (!global_font_cache)
        return;
    pthread_mutex_destroy(&global_font_cache->lock);
    munmap(global_font_cache, sizeof(shared_font_cache));
    global_font_cache = NULL;
}

/* Lookup or add font to shared cache. Returns flags for the font. */
static unsigned char get_font_flags(fz_context* ctx, fz_font* f) {
    if (!f)
        return 0;

    if (global_font_cache) {
        pthread_mutex_lock(&global_font_cache->lock);

        for (int i = 0; i < global_font_cache->len; i++) {
            if (global_font_cache->entries[i].font == f) {
                unsigned char flags = global_font_cache->entries[i].flags;
                pthread_mutex_unlock(&global_font_cache->lock);
                return flags;
            }
        }

        unsigned char flags = 0;
        fz_font_flags_t* ff = fz_font_flags(f);
        if (fz_font_is_bold(ctx, f)) flags |= 1;
        if (fz_font_is_italic(ctx, f)) flags |= 2;
        if (fz_font_is_monospaced(ctx, f)) flags |= 4;
        if (ff && ff->fake_bold) flags |= 1;
        if (ff && ff->fake_italic) flags |= 2;
        flags |= infer_style_from_font_name(fz_font_name(ctx, f));

        if (global_font_cache->len < FONT_CACHE_SIZE) {
            global_font_cache->entries[global_font_cache->len].font = f;
            global_font_cache->entries[global_font_cache->len].flags = flags;
            global_font_cache->len++;
        }

        pthread_mutex_unlock(&global_font_cache->lock);
        return flags;
    }

    /* Fallback: no cache, compute directly */
    unsigned char flags = 0;
    fz_font_flags_t* ff = fz_font_flags(f);
    if (fz_font_is_bold(ctx, f)) flags |= 1;
    if (fz_font_is_italic(ctx, f)) flags |= 2;
    if (fz_font_is_monospaced(ctx, f)) flags |= 4;
    if (ff && ff->fake_bold) flags |= 1;
    if (ff && ff->fake_italic) flags |= 2;
    flags |= infer_style_from_font_name(fz_font_name(ctx, f));
    return flags;
}

static void mupdf_warning_callback(void* user, const char* message) {
    (void)user;
    (void)message;
}

static void mupdf_error_callback(void* user, const char* message) {
    (void)user;
    (void)message;
}

static void add_edge(fz_context* ctx, fz_buffer* buf, double x0, double y0, double x1, double y1, char orientation)
{
    edge e = {x0, y0, x1, y1, orientation};
    fz_append_data(ctx, buf, &e, sizeof(edge));
}

static void combined_fill_path(fz_context* ctx, fz_device* dev, const fz_path* path, int even_odd, fz_matrix ctm,
                               fz_colorspace* cs, const float* color, float alpha, fz_color_params cp)
{
    combined_device* cdev = (combined_device*)dev;

    fz_rect bbox = fz_bound_path(ctx, path, NULL, ctm);
    double width = bbox.x1 - bbox.x0;
    double height = bbox.y1 - bbox.y0;

    if (width > 0 && height > 0)
    {
        add_edge(ctx, cdev->edges_buf, bbox.x0, bbox.y0, bbox.x1, bbox.y0, 'h');
        add_edge(ctx, cdev->edges_buf, bbox.x0, bbox.y1, bbox.x1, bbox.y1, 'h');
        add_edge(ctx, cdev->edges_buf, bbox.x0, bbox.y0, bbox.x0, bbox.y1, 'v');
        add_edge(ctx, cdev->edges_buf, bbox.x1, bbox.y0, bbox.x1, bbox.y1, 'v');
    }

    if (cdev->stext_dev && cdev->stext_dev->fill_path)
        cdev->stext_dev->fill_path(ctx, cdev->stext_dev, path, even_odd, ctm, cs, color, alpha, cp);
}

static void combined_stroke_path(fz_context* ctx, fz_device* dev, const fz_path* path, const fz_stroke_state* stroke,
                                 fz_matrix ctm, fz_colorspace* cs, const float* color, float alpha, fz_color_params cp)
{
    combined_device* cdev = (combined_device*)dev;

    if (!stroke || stroke->linewidth <= EDGE_MAX_WIDTH)
    {
        fz_rect bbox = fz_bound_path(ctx, path, stroke, ctm);
        double width = bbox.x1 - bbox.x0;
        double height = bbox.y1 - bbox.y0;

        if (height <= EDGE_MAX_WIDTH && width >= EDGE_MIN_LENGTH)
            add_edge(ctx, cdev->edges_buf, bbox.x0, bbox.y0, bbox.x1, bbox.y0, 'h');
        else if (width <= EDGE_MAX_WIDTH && height >= EDGE_MIN_LENGTH)
            add_edge(ctx, cdev->edges_buf, bbox.x0, bbox.y0, bbox.x0, bbox.y1, 'v');
    }

    if (cdev->stext_dev && cdev->stext_dev->stroke_path)
        cdev->stext_dev->stroke_path(ctx, cdev->stext_dev, path, stroke, ctm, cs, color, alpha, cp);
}

static void combined_fill_text(fz_context* ctx, fz_device* dev, const fz_text* text, fz_matrix ctm,
                               fz_colorspace* cs, const float* color, float alpha, fz_color_params cp)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev && cdev->stext_dev->fill_text)
        cdev->stext_dev->fill_text(ctx, cdev->stext_dev, text, ctm, cs, color, alpha, cp);
}

static void combined_stroke_text(fz_context* ctx, fz_device* dev, const fz_text* text, const fz_stroke_state* stroke,
                                 fz_matrix ctm, fz_colorspace* cs, const float* color, float alpha, fz_color_params cp)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev && cdev->stext_dev->stroke_text)
        cdev->stext_dev->stroke_text(ctx, cdev->stext_dev, text, stroke, ctm, cs, color, alpha, cp);
}

static void combined_clip_text(fz_context* ctx, fz_device* dev, const fz_text* text, fz_matrix ctm, fz_rect scissor)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev && cdev->stext_dev->clip_text)
        cdev->stext_dev->clip_text(ctx, cdev->stext_dev, text, ctm, scissor);
}

static void combined_clip_stroke_text(fz_context* ctx, fz_device* dev, const fz_text* text, const fz_stroke_state* stroke,
                                      fz_matrix ctm, fz_rect scissor)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev && cdev->stext_dev->clip_stroke_text)
        cdev->stext_dev->clip_stroke_text(ctx, cdev->stext_dev, text, stroke, ctm, scissor);
}


static void combined_close_device(fz_context* ctx, fz_device* dev)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev)
        fz_close_device(ctx, cdev->stext_dev);
}

static void combined_drop_device(fz_context* ctx, fz_device* dev)
{
    combined_device* cdev = (combined_device*)dev;
    if (cdev->stext_dev)
        fz_drop_device(ctx, cdev->stext_dev);
}

static double edge_length(const edge* e)
{
    if (!e)
        return 0.0;
    if (e->orientation == 'h')
        return fabs(e->x1 - e->x0);
    return fabs(e->y1 - e->y0);
}

static int edges_similar(const edge* a, const edge* b)
{
    if (!a || !b)
        return 0;
    if (a->orientation != b->orientation)
        return 0;
    double tol = EDGE_DUP_TOL;
    if (fabs(a->x0 - b->x0) > tol || fabs(a->y0 - b->y0) > tol)
        return 0;
    if (fabs(a->x1 - b->x1) > tol || fabs(a->y1 - b->y1) > tol)
        return 0;
    return 1;
}

static void filter_edges(fz_context* ctx, fz_buffer* buf)
{
    if (!buf)
        return;
    
    size_t data_len = 0;
    unsigned char* data = NULL;
    data_len = fz_buffer_storage(ctx, buf, &data);
    int old_count = (int)(data_len / sizeof(edge));
    
    if (old_count <= 0)
        return;
    
    edge* old = (edge*)data;
    edge* filtered = malloc(old_count * sizeof(edge));
    if (!filtered)
        return;
    
    int keep = 0;
    for (int i = 0; i < old_count; i++) {
        edge* current = &old[i];
        if (edge_length(current) < MIN_EDGE_LENGTH)
            continue;
        int dup = 0;
        int limit = MAX_DUP_CHECK;
        for (int j = keep - 1; j >= 0 && limit > 0; j--, limit--) {
            if (edges_similar(&filtered[j], current)) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        filtered[keep++] = *current;
    }
    
    fz_clear_buffer(ctx, buf);
    fz_append_data(ctx, buf, filtered, keep * sizeof(edge));
    free(filtered);
}

static int is_ascii_letter(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int is_italic_shear_candidate(const fz_stext_char* ch)
{
    if (!ch)
        return 0;

    float left_h = ch->quad.ul.y - ch->quad.ll.y;
    float right_h = ch->quad.ur.y - ch->quad.lr.y;
    if (left_h < 0) left_h = -left_h;
    if (right_h < 0) right_h = -right_h;
    float h = (left_h + right_h) * 0.5f;
    if (h < 1e-3f)
        return 0;

    float left_dx = (ch->quad.ul.x - ch->quad.ll.x) / h;
    float right_dx = (ch->quad.ur.x - ch->quad.lr.x) / h;

    if ((left_dx > 0 && right_dx < 0) || (left_dx < 0 && right_dx > 0))
        return 0;

    float shear = (left_dx + right_dx) * 0.5f;
    if (shear < 0) shear = -shear;

    return shear >= 0.24f && shear <= 0.55f;
}

static void write_chars_from_block_list(fz_buffer* buf, fz_context* ctx, fz_stext_block* block, int* written,
    fchar** line_buffer_ptr, size_t* line_buffer_capacity_ptr, uint8_t** italic_candidate_ptr, size_t* italic_capacity_ptr)
{
    fchar* line_buffer = *line_buffer_ptr;
    size_t line_buffer_capacity = *line_buffer_capacity_ptr;
    uint8_t* italic_candidate = *italic_candidate_ptr;
    size_t italic_capacity = *italic_capacity_ptr;

    for (; block; block = block->next)
    {
        if (block->type == FZ_STEXT_BLOCK_STRUCT && block->u.s.down)
        {
            write_chars_from_block_list(buf, ctx, block->u.s.down->first_block, written,
                &line_buffer, &line_buffer_capacity, &italic_candidate, &italic_capacity);
            continue;
        }
        if (block->type != FZ_STEXT_BLOCK_TEXT)
            continue;
        for (fz_stext_line* line = block->u.t.first_line; line; line = line->next)
        {
            int line_chars = 0;
            for (fz_stext_char* ch = line->first_char; ch; ch = ch->next)
            {
                size_t required = (size_t)line_chars + 1;
                if (required > line_buffer_capacity)
                {
                    size_t new_capacity = line_buffer_capacity ? line_buffer_capacity * 2 : 256;
                    while (new_capacity < required)
                        new_capacity *= 2;
                    fchar* resized = realloc(line_buffer, new_capacity * sizeof(fchar));
                    if (!resized)
                        break;
                    line_buffer = resized;
                    line_buffer_capacity = new_capacity;
                }
                if (required > italic_capacity)
                {
                    size_t new_capacity = italic_capacity ? italic_capacity * 2 : 256;
                    while (new_capacity < required)
                        new_capacity *= 2;
                    uint8_t* resized = realloc(italic_candidate, new_capacity * sizeof(uint8_t));
                    if (!resized)
                        break;
                    italic_candidate = resized;
                    italic_capacity = new_capacity;
                }

                fchar rc = {0};
                rc.codepoint = ch->c;
                rc.size = ch->size;

                float x0 = ch->quad.ll.x;
                float y0 = ch->quad.ll.y;
                float x1 = ch->quad.ur.x;
                float y1 = ch->quad.ur.y;
                rc.bbox_x0 = x0 < x1 ? x0 : x1;
                rc.bbox_y0 = y0 < y1 ? y0 : y1;
                rc.bbox_x1 = x0 > x1 ? x0 : x1;
                rc.bbox_y1 = y0 > y1 ? y0 : y1;

                unsigned char flags = get_font_flags(ctx, ch->font);
                rc.is_bold = (flags & 1) || (ch->flags & FZ_STEXT_BOLD) ? 1 : 0;
                rc.is_italic = (flags & 2) ? 1 : 0;
                rc.is_monospaced = (flags & 4) ? 1 : 0;

                line_buffer[line_chars] = rc;
                italic_candidate[line_chars] = (rc.is_italic == 0 && is_italic_shear_candidate(ch)) ? 1 : 0;
                line_chars++;
            }
            if (line_chars == 0)
                continue;

            for (int i = 0; i < line_chars; )
            {
                if (!italic_candidate[i])
                {
                    i++;
                    continue;
                }
                int start = i;
                int run_len = 0;
                int letter_count = 0;
                while (i < line_chars && italic_candidate[i])
                {
                    if (is_ascii_letter(line_buffer[i].codepoint))
                        letter_count++;
                    run_len++;
                    i++;
                }
                if (run_len >= 8 && letter_count >= 7)
                {
                    for (int j = start; j < i; j++)
                        line_buffer[j].is_italic = 1;
                }
            }

            fz_append_data(ctx, buf, line_buffer, (size_t)line_chars * sizeof(fchar));
            *written += line_chars;
        }
    }

    *line_buffer_ptr = line_buffer;
    *line_buffer_capacity_ptr = line_buffer_capacity;
    *italic_candidate_ptr = italic_candidate;
    *italic_capacity_ptr = italic_capacity;
}

static void write_all_char_data(fz_buffer* buf, fz_context* ctx, fz_stext_page* stext, int expected_total)
{
    int written = 0;
    fchar* line_buffer = NULL;
    size_t line_buffer_capacity = 0;
    uint8_t* italic_candidate = NULL;
    size_t italic_capacity = 0;

    write_chars_from_block_list(buf, ctx, stext->first_block, &written,
        &line_buffer, &line_buffer_capacity, &italic_candidate, &italic_capacity);

    free(line_buffer);
    free(italic_candidate);
    (void)expected_total;
}

static void append_text_blocks_and_lines(fz_context* ctx, fz_stext_block* block, fz_buffer* blocks_buf, fz_buffer* lines_buf,
    int* total_blocks, int* total_lines, int* total_chars, int* line_idx, int* char_idx)
{
    for (; block; block = block->next)
    {
        if (block->type == FZ_STEXT_BLOCK_STRUCT && block->u.s.down)
        {
            append_text_blocks_and_lines(ctx, block->u.s.down->first_block, blocks_buf, lines_buf,
                total_blocks, total_lines, total_chars, line_idx, char_idx);
            continue;
        }
        fblock rb = {0};
        rb.type = block->type;
        rb.bbox_x0 = block->bbox.x0;
        rb.bbox_y0 = block->bbox.y0;
        rb.bbox_x1 = block->bbox.x1;
        rb.bbox_y1 = block->bbox.y1;
        rb.line_start = *line_idx;
        rb.line_count = 0;

        if (block->type == FZ_STEXT_BLOCK_TEXT)
        {
            for (fz_stext_line* line = block->u.t.first_line; line; line = line->next)
            {
                rb.line_count++;
                fline rl = {0};
                rl.bbox_x0 = line->bbox.x0;
                rl.bbox_y0 = line->bbox.y0;
                rl.bbox_x1 = line->bbox.x1;
                rl.bbox_y1 = line->bbox.y1;
                rl.char_start = *char_idx;
                rl.char_count = 0;

                for (fz_stext_char* ch = line->first_char; ch; ch = ch->next)
                {
                    rl.char_count++;
                    (*total_chars)++;
                }
                *char_idx += rl.char_count;

                fz_append_data(ctx, lines_buf, &rl, sizeof(fline));
                (*total_lines)++;
            }
            *line_idx += rb.line_count;
        }
        else
        {
            continue;
        }

        fz_append_data(ctx, blocks_buf, &rb, sizeof(fblock));
        (*total_blocks)++;
    }
}

static int count_links(fz_link* links) {
    int count = 0;
    for (fz_link* l = links; l; l = l->next)
        count++;
    return count;
}

static int extract_page_to_file(fz_context* ctx, fz_document* doc, int page_num, const char* output_path)
{
    fz_page* page = NULL;
    fz_stext_page* stext = NULL;
    fz_link* page_links = NULL;
    FILE* out = NULL;
    int status = 0;
    fz_buffer* edges_buf = NULL;
    fz_buffer* output_buf = NULL;
    fz_device* combined_dev = NULL;
    fz_device* stext_dev = NULL;

    fz_try(ctx)
    {
        page = fz_load_page(ctx, doc, page_num);
        fz_rect bounds = fz_bound_page(ctx, page);

        page_links = fz_load_links(ctx, page);
        int link_count = count_links(page_links);

        fz_stext_options opts = (fz_stext_options){0};
        opts.flags = FZ_STEXT_PRESERVE_WHITESPACE | FZ_STEXT_ACCURATE_BBOXES | FZ_STEXT_COLLECT_STYLES;
        stext = fz_new_stext_page(ctx, bounds);

        stext_dev = fz_new_stext_device(ctx, stext, &opts);

        fz_run_page(ctx, page, stext_dev, fz_identity, NULL);
        fz_close_device(ctx, stext_dev);

        edges_buf = fz_new_buffer(ctx, 256 * 1024);

        combined_device* cdev = fz_new_derived_device(ctx, combined_device);
        combined_dev = &cdev->super;
        cdev->stext_dev = NULL;
        cdev->edges_buf = edges_buf;

        combined_dev->close_device = combined_close_device;
        combined_dev->drop_device = combined_drop_device;
        combined_dev->fill_path = combined_fill_path;
        combined_dev->stroke_path = combined_stroke_path;
        combined_dev->fill_text = combined_fill_text;
        combined_dev->stroke_text = combined_stroke_text;
        combined_dev->clip_text = combined_clip_text;
        combined_dev->clip_stroke_text = combined_clip_stroke_text;

        fz_run_page_contents(ctx, page, combined_dev, fz_identity, NULL);
        fz_close_device(ctx, combined_dev);

        out = fopen(output_path, "wb");
        if (!out)
            fz_throw(ctx, FZ_ERROR_GENERIC, "cannot open output file");
        setvbuf(out, NULL, _IOFBF, 256 * 1024);

        output_buf = fz_new_buffer(ctx, 512 * 1024);

        int total_blocks = 0, total_lines = 0, total_chars = 0;
        fblock* blocks_buffer = NULL;
        fline* lines_buffer = NULL;
        fz_buffer* blocks_buf = fz_new_buffer(ctx, 256 * 1024);
        fz_buffer* lines_buf = fz_new_buffer(ctx, 256 * 1024);

        int line_idx = 0;
        int char_idx = 0;

        append_text_blocks_and_lines(ctx, stext->first_block, blocks_buf, lines_buf,
            &total_blocks, &total_lines, &total_chars, &line_idx, &char_idx);

        int page_number = page_num + 1;
        filter_edges(ctx, edges_buf);
        
        fz_append_data(ctx, output_buf, &page_number, sizeof(int));
        fz_append_data(ctx, output_buf, &bounds, sizeof(fz_rect));
        fz_append_data(ctx, output_buf, &total_blocks, sizeof(int));
        fz_append_data(ctx, output_buf, &total_lines, sizeof(int));
        fz_append_data(ctx, output_buf, &total_chars, sizeof(int));
        
        unsigned char* edges_data = NULL;
        size_t edges_len = fz_buffer_storage(ctx, edges_buf, &edges_data);
        int edges_count = (int)(edges_len / sizeof(edge));
        fz_append_data(ctx, output_buf, &edges_count, sizeof(int));
        fz_append_data(ctx, output_buf, &link_count, sizeof(int));

        unsigned char* blocks_data = NULL;
        size_t blocks_len = fz_buffer_storage(ctx, blocks_buf, &blocks_data);
        fz_append_data(ctx, output_buf, blocks_data, blocks_len);
        
        unsigned char* lines_data = NULL;
        size_t lines_len = fz_buffer_storage(ctx, lines_buf, &lines_data);
        fz_append_data(ctx, output_buf, lines_data, lines_len);

        write_all_char_data(output_buf, ctx, stext, total_chars);

        fz_append_data(ctx, output_buf, edges_data, edges_len);

        for (fz_link* l = page_links; l; l = l->next) {
            fz_append_data(ctx, output_buf, &l->rect, sizeof(fz_rect));
            const char* uri = l->uri ? l->uri : "";
            int uri_len = strlen(uri);
            fz_append_data(ctx, output_buf, &uri_len, sizeof(int));
            if (uri_len > 0)
                fz_append_data(ctx, output_buf, uri, uri_len);
        }

        unsigned char* total_data = NULL;
        size_t total_len = fz_buffer_storage(ctx, output_buf, &total_data);
        if (fwrite(total_data, 1, total_len, out) != total_len)
            fz_throw(ctx, FZ_ERROR_GENERIC, "failed to write output file");

        fz_drop_buffer(ctx, blocks_buf);
        fz_drop_buffer(ctx, lines_buf);

        fclose(out);
        out = NULL;

    }
    fz_always(ctx)
    {
        if (out)
            fclose(out);
        if (combined_dev)
            fz_drop_device(ctx, combined_dev);
        if (stext_dev)
            fz_drop_device(ctx, stext_dev);
        if (page_links)
            fz_drop_link(ctx, page_links);
        if (stext)
            fz_drop_stext_page(ctx, stext);
        if (page)
            fz_drop_page(ctx, page);
        if (edges_buf)
            fz_drop_buffer(ctx, edges_buf);
        if (output_buf)
            fz_drop_buffer(ctx, output_buf);
    }
    fz_catch(ctx)
    {
        status = -1;
    }

    return status;
}

/* extract_page_range helper removed: superseded by forked workers using round-robin distribution */
char* extract_all_pages(const char* pdf_path)
{
    struct timespec t0, t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (!pdf_path)
        return NULL;

    char* temp_dir = malloc(256);
    if (!temp_dir)
        return NULL;

    snprintf(temp_dir, 256, "/tmp/fibrum_pdf_%ld_%u_XXXXXX", (long)time(NULL), (unsigned)getpid());
    if (!mkdtemp(temp_dir)) {
        free(temp_dir);
        return NULL;
    }

    fz_context* ctx = fz_new_context(NULL, NULL, FZ_STORE_SIZE);

    if (!ctx) {
        cleanup_shared_font_cache();
        free(temp_dir);
        return NULL;
    }

    fz_set_warning_callback(ctx, mupdf_warning_callback, NULL);
    fz_set_error_callback(ctx, mupdf_error_callback, NULL);

    fz_document* doc = NULL;
    int page_count = 0;
    int error = 0;

    fz_try(ctx)
    {
        fz_register_document_handlers(ctx);
        doc = fz_open_document(ctx, pdf_path);
        page_count = fz_count_pages(ctx, doc);
    }
    fz_catch(ctx)
    {
        error = 1;
    }

    if (error || page_count == 0) {
        if (doc)
            fz_drop_document(ctx, doc);
        fz_drop_context(ctx);
        cleanup_shared_font_cache();        free(temp_dir);
        return NULL;
    }

    int num_workers = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_workers <= 0)
        num_workers = 4;

    if (num_workers > page_count)
        num_workers = page_count;

    int target_workers = (page_count + 2) / 3;
    if (page_count >= 2 && target_workers < 2)
        target_workers = 2;
    if (target_workers > 0 && target_workers < num_workers)
        num_workers = target_workers;
    if (page_count < 64 && num_workers > 8)
        num_workers = 8;

    int threshold = 2;
    if (page_count < threshold) {
        num_workers = 1;  /* force sequential */
    }

    if (num_workers == 1) {
        for (int p = 0; p < page_count; p++) {
            char filename[512];
            snprintf(filename, sizeof(filename), "%s/page_%03d.raw", temp_dir, p + 1);
            if (extract_page_to_file(ctx, doc, p, filename) != 0) {
                fprintf(stderr, "Warning: failed to extract page %d\n", p + 1);
            }
        }

        if (doc)
            fz_drop_document(ctx, doc);
        fz_drop_context(ctx);
        return temp_dir;
    }

    if (init_shared_font_cache() != 0) {
        if (doc)
            fz_drop_document(ctx, doc);
        fz_drop_context(ctx);
        free(temp_dir);
        return NULL;
    }

    pid_t* pids = calloc(num_workers, sizeof(pid_t));
    if (!pids) {
        if (doc)
            fz_drop_document(ctx, doc);
        fz_drop_context(ctx);
        cleanup_shared_font_cache();        free(temp_dir);
        return NULL;
    }
    int created = 0;

    for (int i = 0; i < num_workers; i++) {
        int start = i;        if (start >= page_count)
            break;

        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork");
            continue;
        }
        if (pid == 0) {
            /* CHILD: open its own context/document and process pages in round-robin */
            fz_context* child_ctx = fz_new_context(NULL, NULL, FZ_STORE_SIZE);
            if (!child_ctx)
                _exit(1);
            fz_set_warning_callback(child_ctx, mupdf_warning_callback, NULL);
            fz_set_error_callback(child_ctx, mupdf_error_callback, NULL);

            fz_document* child_doc = NULL;
            fz_try(child_ctx) {
                fz_register_document_handlers(child_ctx);
                child_doc = fz_open_document(child_ctx, pdf_path);
            }
            fz_catch(child_ctx) {
                if (child_doc)
                    fz_drop_document(child_ctx, child_doc);
                fz_drop_context(child_ctx);
                _exit(1);
            }

            int pages_processed = 0;


            for (int p = start; p < page_count; p += num_workers) {
                char filename[512];
                snprintf(filename, sizeof(filename), "%s/page_%03d.raw", temp_dir, p + 1);
                if (extract_page_to_file(child_ctx, child_doc, p, filename) != 0)
                    fprintf(stderr, "Warning: failed to extract page %d\n", p + 1);
                pages_processed++;
            }

            if (child_doc)
                fz_drop_document(child_ctx, child_doc);
            fz_drop_context(child_ctx);
            _exit(0);        }
        pids[created++] = pid;
    }

    /* Using round-robin forked workers; no pipe writes necessary. Parent simply waits for children. */

    for (int i = 0; i < created; i++) {
        int wstatus;
        waitpid(pids[i], &wstatus, 0);
    }

   if (doc)
        fz_drop_document(ctx, doc);
    fz_drop_context(ctx);

    cleanup_shared_font_cache();
    free(pids);
    
    return temp_dir;
}

int read_page(const char* filepath, page_data* out)
{
    if (!filepath || !out)
        return -1;

    memset(out, 0, sizeof(page_data));
    FILE* in = fopen(filepath, "rb");
    if (!in)
        return -1;

    fz_rect bounds;
    int edge_count, link_count;
    if (fread(&out->page_number, sizeof(int), 1, in) != 1 || fread(&bounds, sizeof(fz_rect), 1, in) != 1 ||
        fread(&out->block_count, sizeof(int), 1, in) != 1 || fread(&out->line_count, sizeof(int), 1, in) != 1 ||
        fread(&out->char_count, sizeof(int), 1, in) != 1 || fread(&edge_count, sizeof(int), 1, in) != 1 ||
        fread(&link_count, sizeof(int), 1, in) != 1)
    {
        fclose(in);
        return -1;
    }

    out->page_x0 = bounds.x0;
    out->page_y0 = bounds.y0;
    out->page_x1 = bounds.x1;
    out->page_y1 = bounds.y1;
    out->edge_count = edge_count;
    out->link_count = link_count;

    out->blocks = malloc(out->block_count ? out->block_count * sizeof(fblock) : 1);
    out->lines  = malloc(out->line_count ? out->line_count * sizeof(fline) : 1);
    out->chars  = malloc(out->char_count ? out->char_count * sizeof(fchar) : 1);
    out->edges  = malloc(out->edge_count ? out->edge_count * sizeof(edge) : 1);
    out->links  = malloc(out->link_count ? out->link_count * sizeof(flink) : 1);

    if (!out->blocks || !out->lines || !out->chars || !out->edges || !out->links)
    {
        free_page(out);
        fclose(in);
        return -1;
    }

    if (fread(out->blocks, sizeof(fblock), out->block_count, in) != (size_t)out->block_count ||
        fread(out->lines, sizeof(fline), out->line_count, in) != (size_t)out->line_count ||
        fread(out->chars, sizeof(fchar), out->char_count, in) != (size_t)out->char_count)
    {
        free_page(out);
        fclose(in);
        return -1;
    }

    if (edge_count > 0 && fread(out->edges, sizeof(edge), edge_count, in) != (size_t)edge_count)
    {
        free_page(out);
        fclose(in);
        return -1;
    }

    for (int i = 0; i < link_count; i++)
    {
        float rect_x0, rect_y0, rect_x1, rect_y1;
        int uri_len;

        if (fread(&rect_x0, sizeof(float), 1, in) != 1 || fread(&rect_y0, sizeof(float), 1, in) != 1 ||
            fread(&rect_x1, sizeof(float), 1, in) != 1 || fread(&rect_y1, sizeof(float), 1, in) != 1 ||
            fread(&uri_len, sizeof(int), 1, in) != 1)
        {
            free_page(out);
            fclose(in);
            return -1;
        }

        out->links[i].rect_x0 = rect_x0;
        out->links[i].rect_y0 = rect_y0;
        out->links[i].rect_x1 = rect_x1;
        out->links[i].rect_y1 = rect_y1;

        if (uri_len > 0)
        {
            out->links[i].uri = malloc(uri_len + 1);
            if (!out->links[i].uri || fread(out->links[i].uri, 1, uri_len, in) != (size_t)uri_len)
            {
                free_page(out);
                fclose(in);
                return -1;
            }
            out->links[i].uri[uri_len] = '\0';
        }
        else
        {
            out->links[i].uri = malloc(1);
            if (out->links[i].uri)
                out->links[i].uri[0] = '\0';
        }
    }

    fclose(in);
    return 0;
}

void free_page(page_data* data)
{
    if (!data)
        return;
    free(data->blocks);
    free(data->lines);
    free(data->chars);
    free(data->edges);
    if (data->links)
    {
        for (int i = 0; i < data->link_count; i++)
            free(data->links[i].uri);
        free(data->links);
    }
    memset(data, 0, sizeof(page_data));
}
