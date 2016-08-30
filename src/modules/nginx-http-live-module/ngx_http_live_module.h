
/*
 * Copyright (C) Brother Wolf
 */

#ifndef _NGX_HTTP_LIVE_H_INCLUDED_
#define _NGX_HTTP_LIVE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_MAX_NAME           256

typedef enum {
    LIVE_FLV_HEADER = 0,
    LIVE_META,
    LIVE_AAC_HEADER,
    LIVE_AVC_HEADER,
    LIVE_AUDIO,
    LIVE_VIDEO
} ngx_http_live_data_type_t;


typedef struct ngx_http_live_srv_conf_s ngx_http_live_srv_conf_t;
typedef struct ngx_http_live_loc_conf_s ngx_http_live_loc_conf_t;

typedef struct ngx_http_live_ctx_s ngx_http_live_ctx_t;
typedef struct ngx_http_live_stream_s ngx_http_live_stream_t;


struct ngx_http_live_ctx_s {
    ngx_http_request_t                 *r;
    ngx_http_live_stream_t             *stream;
    ngx_http_live_ctx_t                *next;
    unsigned                            publishing:1;
    ngx_event_t                         close;
    
    // for publisher
    ngx_chain_t                        *flv_header;
    ngx_chain_t                        *aac_header;
    ngx_chain_t                        *avc_header;
    ngx_chain_t                        *meta;
    
    size_t                              gop_pos, gop_last;
    size_t                              gop_queue;
    size_t                              gop_size;
    ngx_chain_t                       **gop;
    
    // for subscriber
    unsigned                            flv_header_sent:1;
    unsigned                            aac_header_sent:1;
    unsigned                            avc_header_sent:1;
    unsigned                            meta_sent:1;
    unsigned                            gop_sent:1;
    
    /* circular buffer of HTTP message pointers */
    ngx_msec_t                          timeout;
    unsigned                            out_buffer:1;
    size_t                              out_cork;
    ngx_chain_t                        *out_chain;
    u_char                             *out_bpos;
    size_t                              out_pos, out_last;
    size_t                              out_queue;
    ngx_chain_t                        *out[0];
};

struct ngx_http_live_stream_s {
    u_char                              name[NGX_HTTP_MAX_NAME];
    ngx_http_live_stream_t             *next;
    ngx_http_live_ctx_t                *ctx;
    ngx_msec_t                          epoch;
    unsigned                            publishing:1;
};

struct ngx_http_live_loc_conf_s {
    ngx_int_t                           nbuckets;
    ngx_http_live_stream_t            **streams;
    ngx_flag_t                          live;
    ngx_flag_t                          idle_streams;
    ngx_pool_t                         *pool;
    ngx_http_live_stream_t             *free_streams;
    size_t                              out_cork;
    size_t                              out_queue;
    size_t                              gop_queue;
    size_t                              gop_size;
};

struct ngx_http_live_srv_conf_s {
    ngx_pool_t                         *pool;
    ngx_chain_t                        *free;           // chain reuse
    ngx_int_t                           chunk_size;
};

ngx_int_t ngx_http_live_join(ngx_http_request_t *r, u_char *name, unsigned publisher);
ngx_int_t ngx_http_live_av(ngx_http_request_t *r, ngx_chain_t *in, ngx_int_t type, ngx_int_t key_frame);
void ngx_http_live_close_stream(ngx_http_request_t *r);

/* asynchronous close http close */
void ngx_http_live_close_request(ngx_http_request_t *r);

extern ngx_module_t  ngx_http_live_module;


/*  nginx reused buffer */
#define NGX_HTTP_REFCOUNT_TYPE              uint32_t
#define NGX_HTTP_REFCOUNT_BYTES             sizeof(NGX_HTTP_REFCOUNT_TYPE)

#define ngx_http_ref(b)                     \
*((NGX_HTTP_REFCOUNT_TYPE*)(b) - 1)

#define ngx_http_ref_set(b, v)              \
ngx_http_ref(b) = v

#define ngx_http_ref_get(b)                 \
++ngx_http_ref(b)

#define ngx_http_ref_put(b)                 \
--ngx_http_ref(b)

ngx_chain_t * ngx_http_live_alloc_shared_buf(ngx_http_live_srv_conf_t *lscf);
void ngx_http_live_free_shared_chain(ngx_http_live_srv_conf_t *lscf, ngx_chain_t *in);
ngx_chain_t * ngx_http_live_append_shared_bufs(ngx_http_live_srv_conf_t *lscf,
                                               ngx_chain_t *head, ngx_chain_t *in);

#define ngx_http_acquire_shared_chain(in)   \
ngx_http_ref_get(in);                   \

/* Sending messages */
void ngx_http_live_recv(ngx_event_t *rev);
void ngx_http_live_send(ngx_event_t *wev);
ngx_int_t ngx_http_live_send_message(ngx_http_request_t *r, ngx_chain_t *out,
                                     ngx_uint_t priority);

#endif /* _NGX_HTTP_LIVE_H_INCLUDED_ */






