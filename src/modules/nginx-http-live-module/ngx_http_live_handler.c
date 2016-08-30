
/*
 * Copyright (C) Brother Wolf
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_live_module.h"

void
ngx_http_live_recv(ngx_event_t *rev)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    
    u_char buf[1024];
    
    c = rev->data;
    r = c->data;
    
    if (c->destroyed) {
        return;
    }
    
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    
    // discard recv data
    rc = c->recv(c, buf, 1024);
    printf("ngx_http_live_recv    %d\n", (int)rc);
    if (rc == NGX_ERROR || rc == 0) {
        printf("ngx_http_live_recv\n");
        ngx_http_live_close_request(r);
        return;
    }
    
    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_live_close_request(r);
        }
    }
}

void
ngx_http_live_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_int_t                   n;
    ngx_http_live_srv_conf_t   *lscf;
    ngx_http_live_ctx_t        *ctx;
    
    c = wev->data;
    r = c->data;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    
    if (c->destroyed) {
        return;
    }
    
    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;
        ngx_http_live_close_request(r);
        return;
    }
    
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    
    if (ctx->out_chain == NULL && ctx->out_pos != ctx->out_last) {
        ctx->out_chain = ctx->out[ctx->out_pos];
        ctx->out_bpos = ctx->out_chain->buf->pos;
    }
    
    while (ctx->out_chain) {
        n = c->send(c, ctx->out_bpos, ctx->out_chain->buf->last - ctx->out_bpos);
        
        if (n == NGX_AGAIN || n == 0) {
            ngx_add_timer(c->write, ctx->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_http_live_close_request(r);
            }
            return;
        }
        
        if (n < 0) {
            ngx_http_live_close_request(r);
            return;
        }
        
        ctx->out_bpos += n;
        if (ctx->out_bpos == ctx->out_chain->buf->last) {
            ctx->out_chain = ctx->out_chain->next;
            if (ctx->out_chain == NULL) {
                lscf = ngx_http_get_module_ctx(r, ngx_http_live_module);
                ngx_http_live_free_shared_chain(lscf, ctx->out[ctx->out_pos]);
                ++ctx->out_pos;
                ctx->out_pos %= ctx->out_queue;
                if (ctx->out_pos == ctx->out_last) {
                    break;
                }
                ctx->out_chain = ctx->out[ctx->out_pos];
            }
            ctx->out_bpos = ctx->out_chain->buf->pos;
        }
    }
    
    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }
    
    //ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


ngx_int_t
ngx_http_live_send_message(ngx_http_request_t *r, ngx_chain_t *out,
                      ngx_uint_t priority)
{
    ngx_uint_t                      nmsg;
    ngx_http_live_ctx_t            *ctx;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_live_module);
    
    nmsg = (ctx->out_queue + ctx->out_last - ctx->out_pos) % ctx->out_queue + 1;
    
    if (priority > 3) {
        priority = 3;
    }
    
    /* drop packet?
     * Note we always leave 1 slot free */
    if (nmsg + priority * ctx->out_queue / 4 >= ctx->out_queue) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http_live: drop message bufs=%ui, priority=%ui",
                       nmsg, priority);
        return NGX_AGAIN;
    }
    
    ctx->out[ctx->out_last++] = out;
    ctx->out_last %= ctx->out_queue;
    
    ngx_http_acquire_shared_chain(out);
    
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http_live: send nmsg=%ui, priority=%ui #%ui",
                   nmsg, priority, ctx->out_last);
       
    if (priority && ctx->out_buffer && nmsg < ctx->out_cork) {
        return NGX_OK;
    }
    
    if (!r->connection->write->active) {
        ngx_http_live_send(r->connection->write);
        /*return ngx_add_event(s->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT);*/
    }
    
    return NGX_OK;
}


