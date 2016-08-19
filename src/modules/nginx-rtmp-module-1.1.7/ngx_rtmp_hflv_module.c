
/*
 * Copyright (C) Brother Wolf
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_http_live_module.h"

static ngx_rtmp_publish_pt              next_publish;
//static ngx_rtmp_close_stream_pt         next_close_stream;
//static ngx_rtmp_stream_begin_pt         next_stream_begin;
//static ngx_rtmp_stream_eof_pt           next_stream_eof;

typedef struct  {
    ngx_flag_t              hflv;
    
} ngx_rtmp_hflv_app_conf_t;


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

static ngx_int_t
ngx_rtmp_hflv_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hflv : publish %s",
                  v->name);
 
    ngx_rtmp_hflv_app_conf_t * hacf;
    
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hflv_module);
    
    if (!hacf->hflv) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "hflv : publish %s no flv subscribe",
                      v->name);
    }
    
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_hflv_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    return NGX_OK;
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
    
    //next_close_stream = ngx_rtmp_close_stream;
    //ngx_rtmp_close_stream = ngx_rtmp_hflv_close_stream;
    
    //next_stream_begin = ngx_rtmp_stream_begin;
    //ngx_rtmp_stream_begin = ngx_rtmp_hflv_stream_begin;
    
    //next_stream_eof = ngx_rtmp_stream_eof;
    //ngx_rtmp_stream_eof = ngx_rtmp_hflv_stream_eof;
    
    return NGX_OK;

}





