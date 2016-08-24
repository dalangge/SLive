
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
    
    conf->chunk_size = NGX_CONF_UNSET;
    conf->out_cork = NGX_CONF_UNSET_SIZE;
    conf->out_queue = NGX_CONF_UNSET_SIZE;
    
    //lscf->nbuckets = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_live_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_live_srv_conf_t *prev = parent;
    ngx_http_live_srv_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->chunk_size, prev->chunk_size, 4096);
    ngx_conf_merge_size_value(conf->out_queue, prev->out_queue, 2560);
    ngx_conf_merge_size_value(conf->out_cork, prev->out_cork, conf->out_queue / 8);

    
    if (prev->pool == NULL) {
        prev->pool = ngx_create_pool(4096, &cf->cycle->new_log);
        if (prev->pool == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    conf->pool = prev->pool;
    
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
    conf->idle_streams = NGX_CONF_UNSET;
    
    return conf;
}

static char *
ngx_http_live_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_live_loc_conf_t    *prev = parent;
    ngx_http_live_loc_conf_t    *conf = child;
    
    ngx_conf_merge_value(conf->live, prev->live, 0);
    ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);
    ngx_conf_merge_value(conf->idle_streams, prev->idle_streams, 1);
    
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



/*static*/ ngx_int_t
ngx_http_live_join(ngx_http_request_t *r, u_char *name, unsigned publisher)
{
    ngx_http_live_ctx_t            *ctx;
    ngx_http_live_stream_t        **stream;
    ngx_http_live_srv_conf_t       *lscf;
    ngx_http_live_loc_conf_t       *llcf;
    
    lscf = ngx_http_get_module_srv_conf(r, ngx_http_live_module);
    if (lscf == NULL) {
        return NGX_ERROR;
    }
    
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    if (llcf == NULL || !llcf->live) {
        return NGX_ERROR;
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (ctx && ctx->stream) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "http_live: already joined, %s", name);
        return NGX_ERROR;
    }
    
    if (ctx == NULL) {
        ctx = ngx_palloc(r->connection->pool, sizeof(ngx_http_live_ctx_t) +
                         sizeof(ngx_chain_t *) * lscf->out_queue);
        ngx_http_set_ctx(r, ctx, ngx_http_live_module);
    }
    
    ngx_memzero(ctx, sizeof(*ctx));
    
    ctx->r = r;
    ctx->out_queue = lscf->out_queue;
    ctx->out_cork = lscf->out_cork;
    ctx->out_buffer = 1;
    ctx->timeout = 30000;
    
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_live: join %s", name);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "http_live: join %s", name);
    
    stream = ngx_http_live_get_stream(r, name, publisher);
    
    if (stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http_live: stream not found");
        return NGX_ERROR;
    }
    
    if (publisher) {
        if ((*stream)->publishing) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "http_live: already publishing");
            return NGX_ERROR;
        }
        
        (*stream)->publishing = 1;
    }
  
    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;
    
    (*stream)->ctx = ctx;
    
    return NGX_OK;
}

ngx_int_t
ngx_http_live_av(ngx_http_request_t *r, ngx_chain_t *in, ngx_int_t type, ngx_int_t key_frame)
{
    ngx_http_live_ctx_t             *ctx, *pctx;
    ngx_http_live_srv_conf_t        *lscf;
    ngx_http_live_loc_conf_t        *llcf;
    ngx_chain_t                     *rpkt;
    ngx_int_t                        i;
    
    lscf = ngx_http_get_module_srv_conf(r, ngx_http_live_module);
    if (lscf == NULL) {
        return NGX_ERROR;
    }
    
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    if (lscf == NULL) {
        return NGX_ERROR;
    }
    
    if (!llcf->live || in == NULL || in->buf == NULL) {
        return NGX_OK;
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }
    
    if (ctx->publishing == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                       "http_live: from non-publisher");
        return NGX_OK;
    }
    
    rpkt = ngx_http_live_append_shared_bufs(lscf, NULL, in);
    
    if (type == LIVE_FLV_HEADER) {
        if (ctx->flv_header) {
            ngx_http_live_free_shared_chain(lscf, ctx->flv_header);
        }
        ngx_http_acquire_shared_chain(rpkt);
        ctx->flv_header = rpkt;
    }
    else if (type == LIVE_AAC_HEADER) {
        ngx_http_acquire_shared_chain(rpkt);
        ctx->aac_header = rpkt;
    }
    else if (type == LIVE_AVC_HEADER) {
        ngx_http_acquire_shared_chain(rpkt);
        ctx->avc_header = rpkt;
    }
    
    if (type == LIVE_VIDEO && key_frame) {
        for (i = 0; i < 1000; ++i) {
            if (ctx->gop[i]) {
                ngx_http_live_free_shared_chain(lscf, ctx->gop[i]);
            }
        }
        ngx_memzero(ctx->gop, sizeof(ngx_chain_t*)*1000);
    }
    
    // add to gop
    if (type == LIVE_AUDIO || type == LIVE_VIDEO) {
        for (i = 0; i < 1000; ++i) {
            if (!ctx->gop[i]) {
                ngx_http_acquire_shared_chain(rpkt);
                ctx->gop[i] = rpkt;
                break;
            }
        }
    }
    
    /* broadcast to all subscribers */
    
    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx) {
            continue;
        }
        
        if (!pctx->flv_header_sent && ctx->flv_header) {
            
            if (ngx_http_live_send_message(pctx->r, ctx->flv_header, 0) != NGX_OK) {
                continue;
            }
            
            pctx->flv_header_sent = 1;
            continue;
        }
        
        if (!pctx->aac_header_sent && ctx->aac_header) {
            
            if (ngx_http_live_send_message(pctx->r, ctx->aac_header, 0) != NGX_OK) {
                continue;
            }
            
            pctx->aac_header_sent = 1;
            continue;
        }
        
        if (!pctx->avc_header_sent && ctx->avc_header) {
            
            if (ngx_http_live_send_message(pctx->r, ctx->avc_header, 0) != NGX_OK) {
                continue;
            }
            
            pctx->avc_header_sent = 1;
            continue;
        }
        
        if (!pctx->gop_sent) {
            
            for (i = 0; i < 1000; ++i) {
                if (ctx->gop[i]) {
                    ngx_http_live_send_message(pctx->r, ctx->gop[i], 0);
                }
            }
            
            pctx->gop_sent = 1;
            continue;
        }
        
        // send the current package
        
        ngx_http_live_send_message(pctx->r, rpkt, 0);
    }
    
    if (rpkt) {
        ngx_http_live_free_shared_chain(lscf, rpkt);
    }
    
    return NGX_OK;
}

/*static*/ void
ngx_http_live_close_stream(ngx_http_request_t *r)
{
    ngx_http_live_ctx_t            *ctx, **cctx, *pctx;
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
        if (1 || !llcf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    //ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                    //               "live: no publisher");
                    
                    printf("close no publisher\n");
                    ngx_http_live_close_request(pctx->r);
                }
            }
        }
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
ngx_http_live_close_request_handler(ngx_event_t *e)
{
    ngx_connection_t      *c;
    ngx_http_request_t         *r;
    
    c = e->data;
    r = c->data;
    printf("ngx_http_live_close_request_handler\n");
    
    ngx_http_live_close_stream(r);
    ngx_http_finalize_request(r, NGX_OK);
}


void
ngx_http_live_close_request(ngx_http_request_t *r)
{
    ngx_http_live_ctx_t        *ctx;
    ngx_event_t                *e;
    ngx_connection_t           *c;
    
    printf("ngx_http_live_close_request\n");
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    if (ctx == NULL) {
        return;
    }
    
    c = r->connection;
    c->destroyed = 1;
    
    e = &ctx->close;
    e->data = c;
    e->handler = ngx_http_live_close_request_handler;
    e->log = c->log;
    
    ngx_post_event(e, &ngx_posted_events);
}

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
    
    /*rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }*/
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "http_live: xxx %V %V %V", &r->exten, &r->uri,
                  &r->args);
    
    ngx_memzero(name, sizeof(name));
    ngx_memcpy(name, r->uri.data, ngx_min(r->uri.len, sizeof(name)-1));
    
    rc = ngx_http_live_join(r, name, 0);
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








