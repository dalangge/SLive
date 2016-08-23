
/*
 * Copyright (C) Brother Wolf
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_live_module.h"

ngx_chain_t *
ngx_http_live_alloc_shared_buf(ngx_http_live_srv_conf_t *lscf)
{
    u_char                     *p;
    ngx_chain_t                *out;
    ngx_buf_t                  *b;
    size_t                      size;
    
    if (lscf->free) {
        out = lscf->free;
        lscf->free = out->next;
        
    } else {
        
        size = lscf->chunk_size /*+ NGX_RTMP_MAX_CHUNK_HEADER*/;
        
        p = ngx_pcalloc(lscf->pool, NGX_HTTP_REFCOUNT_BYTES
                        + sizeof(ngx_chain_t)
                        + sizeof(ngx_buf_t)
                        + size);
        if (p == NULL) {
            return NULL;
        }
        
        p += NGX_HTTP_REFCOUNT_BYTES;
        out = (ngx_chain_t *)p;
        
        p += sizeof(ngx_chain_t);
        out->buf = (ngx_buf_t *)p;
        
        p += sizeof(ngx_buf_t);
        out->buf->start = p;
        out->buf->end = p + size;
    }
    
    out->next = NULL;
    b = out->buf;
    b->pos = b->last = b->start /*+ NGX_RTMP_MAX_CHUNK_HEADER*/;
    b->memory = 1;
    
    /* buffer has refcount =1 when created! */
    ngx_http_ref_set(out, 1);
    
    return out;
}


void
ngx_http_live_free_shared_chain(ngx_http_live_srv_conf_t *lscf, ngx_chain_t *in)
{
    ngx_chain_t        *cl;
    
    if (ngx_http_ref_put(in)) {
        return;
    }
    
    for (cl = in; ; cl = cl->next) {
        if (cl->next == NULL) {
            cl->next = lscf->free;
            lscf->free = in;
            return;
        }
    }
}


ngx_chain_t *
ngx_http_live_append_shared_bufs(ngx_http_live_srv_conf_t *lscf,
                                 ngx_chain_t *head, ngx_chain_t *in)
{
    ngx_chain_t                    *l, **ll;
    u_char                         *p;
    size_t                          size;
    
    ll = &head;
    p = in->buf->pos;
    l = head;
    
    if (l) {
        for(; l->next; l = l->next);
        ll = &l->next;
    }
    
    for ( ;; ) {
        
        if (l == NULL || l->buf->last == l->buf->end) {
            l = ngx_http_live_alloc_shared_buf(lscf);
            if (l == NULL || l->buf == NULL) {
                break;
            }
            
            *ll = l;
            ll = &l->next;
        }
        
        while (l->buf->end - l->buf->last >= in->buf->last - p) {
            l->buf->last = ngx_cpymem(l->buf->last, p,
                                      in->buf->last - p);
            in = in->next;
            if (in == NULL) {
                goto done;
            }
            p = in->buf->pos;
        }
        
        size = l->buf->end - l->buf->last;
        l->buf->last = ngx_cpymem(l->buf->last, p, size);
        p += size;
    }
    
done:
    *ll = NULL;
    
    return head;
}
