
/*
 * Copyright (C) Brother Wolf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_MAX_NAME           256

typedef struct ngx_http_live_srv_conf_s ngx_http_live_srv_conf_t;
typedef struct ngx_http_live_loc_conf_s ngx_http_live_loc_conf_t;

typedef struct ngx_http_live_ctx_s ngx_http_live_ctx_t;
typedef struct ngx_http_live_stream_s ngx_http_live_stream_t;


struct ngx_http_live_stream_s {
    u_char                              name[NGX_HTTP_MAX_NAME];
    ngx_http_live_stream_t             *next;
    ngx_http_live_ctx_t                *ctx;
/*    ngx_rtmp_bandwidth_t                bw_in;
    ngx_rtmp_bandwidth_t                bw_in_audio;
    ngx_rtmp_bandwidth_t                bw_in_video;
    ngx_rtmp_bandwidth_t                bw_out;*/
    ngx_msec_t                          epoch;
   // unsigned                            active:1;
    unsigned                            publishing:1;
};

struct ngx_http_live_ctx_s {
    ngx_http_request_t                 *r;
    ngx_http_live_stream_t             *stream;
    ngx_http_live_ctx_t                *next;
    unsigned                            publishing:1;
    
    ngx_buf_t                          *buf;
};

struct ngx_http_live_loc_conf_s {
    ngx_int_t                           nbuckets;
    ngx_http_live_stream_t            **streams;
    ngx_flag_t                          live;
    //ngx_flag_t                          idle_streams;
    //ngx_msec_t                          buflen;
    ngx_pool_t                         *pool;
    ngx_http_live_stream_t             *free_streams;
    
};

struct ngx_http_live_srv_conf_s {
    ngx_pool_t                         *pool;
    size_t                              out_cork;
};



