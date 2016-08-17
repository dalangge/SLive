
/*
 * Copyright (C) Brother Wolf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_live_module.h"

struct ngx_http_live_ctx_s {
    
};

struct ngx_http_live_srv_conf_s {
    ngx_pool_t             *pool;
    size_t                  out_cork;
};

struct ngx_http_live_loc_conf_s {
    ngx_flag_t              live;
};

typedef struct ngx_http_live_srv_conf_s ngx_http_live_srv_conf_t;
typedef struct ngx_http_live_loc_conf_s ngx_http_live_loc_conf_t;

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
    
    return conf;
}

static char *
ngx_http_live_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_live_loc_conf_t    *prev = parent;
    ngx_http_live_loc_conf_t    *conf = child;
    
    ngx_conf_merge_value(conf->live, prev->live, 0);
    
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_live_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t* b;
    ngx_chain_t * out;
    ngx_http_live_loc_conf_t* hlcf;
    
    ngx_str_t ss = ngx_string("hello world");
     
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_live_module);
    
    if (hlcf == NULL || !hlcf->live) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_live: not config live");
        return NGX_HTTP_FORBIDDEN;
    }
    
    out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (out == NULL)
        return NGX_ERROR;
     
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
        return NGX_ERROR;
     
    b->pos = ss.data;
    b->last = ss.data + ss.len;
    b->memory = 1;
    b->last_buf = 1;
     
    out->buf = b;
    out->next = NULL;
    
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char*)"text/plain";
     
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ss.len;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
     
    return ngx_http_output_filter(r, out);
}

static char *
ngx_http_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_live_handler;
    
    return ngx_conf_set_flag_slot(cf, cmd, conf);
}








