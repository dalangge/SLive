
/*
 * Copyright (C) Brother Wolf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_http_live_module.h"

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
//static ngx_rtmp_stream_begin_pt         next_stream_begin;
//static ngx_rtmp_stream_eof_pt           next_stream_eof;

typedef struct  {
    ngx_flag_t              hflv;
    
    
} ngx_rtmp_hflv_app_conf_t;

typedef struct {
    ngx_rtmp_session_t     *s;
    ngx_http_request_t     *r;
    
    u_char                  header[16];
    ngx_buf_t               bh;
    ngx_chain_t             ch;
    u_char                  tail[8];
    ngx_buf_t               bt;
    ngx_chain_t             ct;
    
    unsigned                flv_header_sent:1;
    unsigned                meta_sent:1;
    
} ngx_rtmp_hflv_ctx_t;


static void * ngx_rtmp_hflv_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hflv_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_rtmp_hflv_postconfiguration(ngx_conf_t *cf);

static ngx_command_t  ngx_rtmp_hflv_commands[] = {
    
    { ngx_string("hflv"),
        NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_RTMP_APP_CONF_OFFSET,
        offsetof(ngx_rtmp_hflv_app_conf_t, hflv),
        NULL },
    
    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hflv_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_hflv_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_hflv_create_app_conf,          /* create app configuration */
    ngx_rtmp_hflv_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_hflv_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hflv_module_ctx,              /* module context */
    ngx_rtmp_hflv_commands,                 /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_hflv_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hflv_app_conf_t      *hacf;
    
    hacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hflv_app_conf_t));
    if (hacf == NULL) {
        return NULL;
    }
    
    hacf->hflv = NGX_CONF_UNSET;
    
    return hacf;
}

static char *
ngx_rtmp_hflv_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hflv_app_conf_t *prev = parent;
    ngx_rtmp_hflv_app_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->hflv, prev->hflv, 0);
    //ngx_conf_merge_str_value(conf->hflv_host, prev->hflv_host, "dlg");
    
    return NGX_CONF_OK;
}

static ngx_http_request_t *
ngx_rtmp_hflv_create_request(ngx_rtmp_session_t *s, u_char *vhost, u_char *path)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **pcscf;
    ngx_uint_t                  i;
    size_t                      len;
    
    c = ngx_palloc(s->connection->pool, sizeof(ngx_http_connection_t));
    if (c == NULL) {
        return NULL;
    }
    
    r = ngx_palloc(s->connection->pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        return NULL;
    }
    
    r->ctx = ngx_pcalloc(s->connection->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        return NULL;
    }
    
    // as a virtual request, we only assign required parameters
    ngx_str_set(&c->addr_text, "local");
    r->connection = c;
    c->pool = s->connection->pool;
    c->log = s->connection->log;
    
    len = ngx_strlen(vhost);
    
    cmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_core_module);
    pcscf  = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; ++i) {
        // match the first server name
        if (len == pcscf[i]->server_name.len &&
            0 == ngx_strncasecmp(vhost, pcscf[i]->server_name.data, len)) {
            r->main_conf = pcscf[i]->ctx->main_conf;
            r->srv_conf = pcscf[i]->ctx->srv_conf;
            r->loc_conf = pcscf[i]->ctx->loc_conf;
            break;
        }
    }
    
    if (r->main_conf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                       "hflv: can't find matched server, vhost='%s' path='%s'", vhost, path);
        return NULL;
    }
    
    r->uri.len = ngx_strlen(path);
    r->uri.data = ngx_pnalloc(c->pool, r->uri.len);
    if (r->uri.data == NULL) {
        return NULL;
    }
    ngx_memcpy(r->uri.data, path, r->uri.len);
    
    if (ngx_http_core_find_location(r) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                       "hflv: can't find matched location, vhost='%s' path='%s'", vhost, path);
        return NULL;
    }
    
    return r;
}

static ngx_int_t
ngx_rtmp_hflv_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_hflv_ctx_t            *ctx;
    ngx_rtmp_hflv_app_conf_t       *hacf;
    u_char                          name[NGX_RTMP_MAX_URL];
    ngx_int_t                       rc;
    ngx_http_request_t             *r;
    
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hflv_module);
    if (hacf == NULL || !hacf->hflv) {
        goto next;
    }
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hflv_module);
    if (ctx && ctx->r) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hflv: already joined, '%s'", v->name);
        goto next;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hflv_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hflv_module);
    }
    
    ngx_memzero(ctx, sizeof(*ctx));
    *ngx_sprintf(name, "/%V/%s%s", &s->app, v->name, ".flv") = 0;
    
    r = ngx_rtmp_hflv_create_request(s, (u_char *)"localhost", name);
    if (r == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "hflv: create request failed, vhost=%s, path=%s", "localhost", name);
        goto next;
    }
    
    rc = ngx_http_live_join(r, name, 1);
    if (rc != NGX_OK) {
        goto next;
    }
    
    ctx->s = s;
    ctx->r = r;
    
next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_hflv_write_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in, ngx_int_t type, ngx_int_t key_frame)
{
    ngx_rtmp_hflv_ctx_t         *ctx;
    u_char                     *p, *ph;
    uint32_t                    timestamp, tag_size;
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hflv_module);
    if (ctx == NULL || ctx->r == NULL) {
        return NGX_ERROR;
    }
    
    // flv support all tag timestamp 0
    timestamp = h->timestamp;
    
    ph = ctx->header;
    
    *ph++ = (u_char)h->type;
    
    p = (u_char*)&h->mlen;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    
    p = (u_char*)&timestamp;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];
    
    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;
    
    ctx->bh.pos = ctx->bh.start = ctx->header;
    ctx->bh.end = ctx->bh.start + sizeof(ctx->header);
    ctx->bh.last = ph;
    
    tag_size = (ph - ctx->header) + h->mlen;
    
    ph = ctx->tail;
    p = (u_char*)&tag_size;
    
    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    
    ctx->bt.pos = ctx->bt.start = ctx->tail;
    ctx->bt.end = ctx->bt.start + sizeof(ctx->tail);
    ctx->bt.last = ph;
    ctx->bt.memory = 1;

    // link chain
    ctx->ch.buf = &ctx->bh;
    ctx->ch.next = in;
    
    while (in->next) {
        in = in->next;
    }
    in->next = &ctx->ct;
    
    ctx->ct.buf = &ctx->bt;
    ctx->ct.next = NULL;
    
    ngx_http_live_av(ctx->r, &ctx->ch, type, key_frame);
    
    // reset origina tail pointer
    in->next = NULL;
    return NGX_OK;
}

/*
static size_t
ngx_rtmp_hflv_get_chain_mlen(ngx_chain_t *in)
{
    size_t      ret;
    for (ret = 0; in; in = in->next) {
        ret += (in->buf->last - in->buf->pos);
    }
    return ret;
}*/

static ngx_int_t
ngx_rtmp_hflv_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_hflv_ctx_t        *ctx;
    ngx_rtmp_codec_ctx_t       *codec_ctx;
    ngx_int_t                   codec_header;
    
    static u_char   flv_header[] = {
        0x46, /* 'F' */
        0x4c, /* 'L' */
        0x56, /* 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00,
        0x00,
        0x00,
        0x09, /* header size */
        0x00,
        0x00,
        0x00,
        0x00  /* PreviousTagSize0 (not actually a header) */
    };

    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hflv_module);
    if (ctx == NULL || ctx->r == NULL) {
        return NGX_OK;
    }
    
    // send flv header at first
    if (!ctx->flv_header_sent) {
        ctx->bh.start = ctx->bh.pos = flv_header;
        ctx->bh.end = ctx->bh.last = ctx->bh.start + sizeof(flv_header);
        ctx->ch.buf = &ctx->bh;
        ctx->ch.next = NULL;
        
        ngx_http_live_av(ctx->r, &ctx->ch, LIVE_FLV_HEADER, 0);
        ctx->flv_header_sent = 1;
    }
    
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (codec_ctx == NULL) {
        return NGX_OK;
    }

    codec_header = 0;
    if (h->type == NGX_RTMP_MSG_VIDEO) {
        if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
            ngx_rtmp_is_codec_header(in)) {
            codec_header = 1;
        }
        
        ngx_rtmp_hflv_write_frame(s, h, in,
                                  codec_header ? LIVE_AVC_HEADER : LIVE_VIDEO,
                                  ngx_rtmp_get_video_frame_type(in) == NGX_RTMP_VIDEO_KEY_FRAME);
    }
    else if(h->type == NGX_RTMP_MSG_AUDIO) {
        if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
            ngx_rtmp_is_codec_header(in)) {
            codec_header = 1;
        }
        
        ngx_rtmp_hflv_write_frame(s, h, in,
                                  codec_header ? LIVE_AAC_HEADER : LIVE_AUDIO,
                                  0);
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hflv_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hflv_ctx_t    *ctx;
    
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hflv_module);
    
    if (ctx == NULL || ctx->r == NULL) {
        goto next;
    }
    
    ngx_http_live_close_stream(ctx->r);
    ctx->r = NULL;
    
next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_hflv_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    
    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);
    
    /* register raw event handlers */
    
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hflv_av;
    
    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hflv_av;
    
    /* chain handlers */
    
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hflv_publish;
    
    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hflv_close_stream;
    
    //next_stream_begin = ngx_rtmp_stream_begin;
    //ngx_rtmp_stream_begin = ngx_rtmp_hflv_stream_begin;
    
    //next_stream_eof = ngx_rtmp_stream_eof;
    //ngx_rtmp_stream_eof = ngx_rtmp_hflv_stream_eof;
    
    return NGX_OK;

}





