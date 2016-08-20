
/*
 * Copyright (C) Brother Wolf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_live_module.h"


static void * ngx_http_live_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_live_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void * ngx_http_live_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char * ngx_http_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_live_commands[] = {
    
    { ngx_string("live"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_live,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_loc_conf_t, live),
        NULL },
    
    /*{ ngx_string("stream_buckets"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_live_loc_conf_t, nbuckets),
        NULL },*/
    
    ngx_null_command
};


static ngx_http_module_t  ngx_http_live_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_http_live_create_srv_conf,         /* create server configuration */
    ngx_http_live_merge_srv_conf,          /* merge server configuration */
    ngx_http_live_create_loc_conf,         /* create location configuration */
    ngx_http_live_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_live_module = {
    NGX_MODULE_V1,
    &ngx_http_live_module_ctx,             /* module context */
    ngx_http_live_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_live_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_live_srv_conf_t    *conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    /*conf->chunk_size = NGX_CONF_UNSET;
    conf->out_cork = NGX_CONF_UNSET_SIZE;
    conf->out_queue = NGX_CONF_UNSET_SIZE;*/
    
    //lscf->nbuckets = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_live_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_srv_conf_t *prev = parent;
    ngx_http_live_srv_conf_t *conf = child;
    
    //ngx_conf_merge_value(conf->chunk_size, prev->chunk_size, 4096);
    //ngx_conf_merge_size_value(conf->out_queue, prev->out_queue, 256);
    //ngx_conf_merge_size_value(conf->out_cork, prev->out_cork, conf->out_queue / 8);
    
    ngx_conf_merge_size_value(conf->out_cork, prev->out_cork, 256 / 8);

    
    /*if (prev->pool == NULL) {
        prev->pool = ngx_create_pool(4096, &cf->cycle->new_log);
        if (prev->pool == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    conf->pool = prev->pool;*/
    
    return NGX_CONF_OK;
}

static void *
ngx_http_live_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_live_loc_conf_t    *conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_live_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conf->live = NGX_CONF_UNSET;
    conf->nbuckets = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_live_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_live_loc_conf_t    *prev = parent;
    ngx_http_live_loc_conf_t    *conf = child;
    
    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    
    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (conf->pool == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conf->streams = ngx_pcalloc(cf->pool,
                                sizeof(ngx_http_live_stream_t *) * conf->nbuckets);
    return NGX_CONF_OK;
}

static ngx_http_live_stream_t **
ngx_http_live_get_stream(ngx_http_request_t *r, u_char *name, int create)
{
    ngx_http_live_loc_conf_t       *llcf;
    ngx_http_live_stream_t        **stream;
    size_t                          len;
    
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    if (llcf == NULL) {
        return NULL;
    }
    
    len = ngx_strlen(name);
    stream = &llcf->streams[ngx_hash_key(name, len) % llcf->nbuckets];
    
    for (; *stream; stream = &(*stream)->next) {
        if (ngx_strcmp(name, (*stream)->name) == 0) {
            return stream;
        }
    }
    
    if (!create) {
        return NULL;
    }
    
    // create new stream
    if (llcf->free_streams) {
        *stream = llcf->free_streams;
        llcf->free_streams = llcf->free_streams->next;
    } else {
        *stream = ngx_palloc(llcf->pool, sizeof(ngx_http_live_stream_t));
    }
    ngx_memzero(*stream, sizeof(ngx_http_live_stream_t));
    ngx_memcpy((*stream)->name, name,
               ngx_min(sizeof((*stream)->name) - 1, len));
    (*stream)->epoch = ngx_current_msec;
    
    return stream;
}



static ngx_int_t
ngx_http_live_join(ngx_http_request_t *r, u_char *name, unsigned publisher)
{
    ngx_http_live_ctx_t            *ctx;
    ngx_http_live_stream_t        **stream;
    ngx_http_live_loc_conf_t       *llcf;
    
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    if (llcf == NULL) {
        return NGX_ERROR;
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (ctx && ctx->stream) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "http_live: %s already joined", name);
        return NGX_ERROR;
    }
    
    if (ctx == NULL) {
        ctx = ngx_palloc(r->connection->pool, sizeof(ngx_http_live_ctx_t));
        ngx_http_set_ctx(r, ctx, ngx_http_live_module);
    }
    
    ngx_memzero(ctx, sizeof(*ctx));
    
    ctx->r = r;
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_live: join %s", name);
    
    stream = ngx_http_live_get_stream(r, name, publisher);
    
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_live: stream not found");
        return NGX_ERROR;
    }
    
/*    if (publisher) {
        if ((*stream)->publishing) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_live: already publishing");
            return NGX_ERROR;
        }
        
        (*stream)->publishing = 1;
    }
  */
    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;
    
    (*stream)->ctx = ctx;
    
    if(1){
        ctx->buf = ngx_create_temp_buf(r->connection->pool, 10*1024*1024);
        FILE * fp = fopen("/root/workspace/stream/qianqian_h264_aac.flv",
                          "rb+");
        while (!feof(fp)) {
            ctx->buf->last += fread(ctx->buf->last, 1, 1024, fp);
        }
        fclose(fp);
    }
    
    return NGX_OK;
}

static void
ngx_http_live_close_stream(ngx_http_request_t *r)
{
    ngx_http_live_ctx_t            *ctx, **cctx;//, *pctx;
    ngx_http_live_stream_t        **stream;
    ngx_http_live_loc_conf_t        *llcf;
    
    llcf = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (llcf == NULL) {
        return;
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http_live: not joined");
        return;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_live: leave '%s'", ctx->stream->name);
    
    if (ctx->stream->publishing && ctx->publishing) {
        ctx->stream->publishing = 0;
    }
    
    for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }
    
    if (ctx->publishing) {
        /*if (!lacf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
                    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                                   "live: no publisher");
                    ngx_rtmp_finalize_session(ss);
                }
            }
        }*/
    }
    
    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        return;
    }
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_live: delete empty stream '%s'",
                   ctx->stream->name);
    
    stream = ngx_http_live_get_stream(r, ctx->stream->name, 0);
    if (stream == NULL) {
        return;
    }
    *stream = (*stream)->next;
    
    ctx->stream->next = llcf->free_streams;
    llcf->free_streams = ctx->stream;
    ctx->stream = NULL;
    
    return;
}

static void
ngx_http_live_close(ngx_http_request_t *r, ngx_int_t rc)
{
    // close stream here
    
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_live: close stream");
    
    ngx_http_live_close_stream(r);
    
    ngx_http_finalize_request(r, rc);
}

static void
ngx_http_live_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_int_t                   n;
    ngx_http_live_ctx_t        *ctx;
    ngx_buf_t                  *buf;
    
    c = wev->data;
    r = c->data;
    
    if (c->destroyed) {
        return;
    }
    
    if (c->timedout) {
        ngx_http_live_close(r, NGX_HTTP_OK);
        return;
    }
    
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    buf = ctx->buf;
    
    while (buf->pos < buf->last) {
        n = c->send(c, buf->pos, buf->last - buf->pos);
        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, 3000);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_http_live_close(r, NGX_HTTP_OK);
            }
            return;
        }
        
        if (n < 0) {
            ngx_http_live_close(r, NGX_HTTP_OK);
            return;
        }
        
        buf->pos += n;
    }
    return;
}

static void
ngx_http_live_recv(ngx_event_t *rev)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    static int                  x = 1;
    
    u_char buf[2];
    
    c = rev->data;
    r = c->data;
    
    rc = c->recv(c, buf, 1);
    if (rc == 0 || (rc == -1 && ngx_socket_errno != NGX_EAGAIN)) {
        ngx_http_live_close(r, NGX_HTTP_OK);
        printf("aaaa %d %d\n", (int)rc, x++);
    }
}

//r->connection->write->handler = ngx_http_live_send;

static ngx_int_t
ngx_http_live_handler(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_live_loc_conf_t   *llcf;
    u_char                      name[NGX_HTTP_MAX_NAME];

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_ERROR;
    }
    
    llcf =ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    if (llcf == NULL) {
        return NGX_ERROR;
    }

    // don't use chunked and postpone
    if (clcf->chunked_transfer_encoding || clcf->postpone_output) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "http_live: chunked_transfer_encoding=%d, postpone_output=%d",
                      clcf->chunked_transfer_encoding, clcf->postpone_output);
        return NGX_ERROR;
    }
    
    if (!llcf->live) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http_live: live off");
        return NGX_HTTP_NOT_ALLOWED;
    }
    
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "http_live: xxx %V %V %V", &r->exten, &r->uri,
                  &r->args);
    
    ngx_memzero(name, sizeof(name));
    ngx_memcpy(name, r->uri.data, ngx_min(r->uri.len, sizeof(name)-1));
    
    rc = ngx_http_live_join(r, name, 1);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    
    r->headers_out.status = NGX_HTTP_OK;
    // r->headers_out.content_length_n = 0;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    // header has been sent
    // rewrite the handler, body will not use nginx body filter chain but our own send
    r->connection->write->handler = ngx_http_live_send;
    r->connection->read->handler = ngx_http_live_recv;
    r->main->count++;
    
    if (!r->connection->write->active) {
        ngx_http_live_send(r->connection->write);
    }
    
    return NGX_DONE;
 }

static char *
ngx_http_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_live_handler;
    
    return ngx_conf_set_flag_slot(cf, cmd, conf);
}








