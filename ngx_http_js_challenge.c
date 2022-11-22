#include <ngx_http.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DEFAULT_SECRET "changeme"
#define SHA1_MD_LEN 20
#define SHA1_STR_LEN 40

#define JS_SOLVER_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html>" \
        "<head>" \
        "<meta charset='UTF-8'>" \
        "<title>%s</title>" \
        "</head>" \
        "<body>" \
        "<script>" \
        "window.onload=function(){!function(){function t(t){t?(f[0]=f[16]=f[1]=f[2]=f[3]=f[4]=f[5]=f[6]=f[7]=f[8]=f[9]=f[10]=f[11]=f[12]=f[13]=f[14]=f[15]=0,this.blocks=f):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],this.h0=1732584193,this.h1=4023233417,this.h2=2562383102,this.h3=271733878,this.h4=3285377520,this.block=this.start=this.bytes=this.hBytes=0,this.finalized=this.hashed=!1,this.first=!0}var h=\"object\"==typeof window?window:{},s=!h.JS_SHA1_NO_NODE_JS&&\"object\"==typeof process&&process.versions&&process.versions.node;s&&(h=global);var i=!h.JS_SHA1_NO_COMMON_JS&&\"object\"==typeof module&&module.exports,e=\"function\"==typeof define&&define.amd,r=\"0123456789abcdef\".split(\"\"),o=[-2147483648,8388608,32768,128],n=[24,16,8,0],a=[\"hex\",\"array\",\"digest\",\"arrayBuffer\"],f=[],u=function(h){return function(s){return new t(!0).update(s)[h]()}},c=function(){var h=u(\"hex\");s&&(h=p(h)),h.create=function(){return new t},h.update=function(t){return h.create().update(t)};for(var i=0;i<a.length;++i){var e=a[i];h[e]=u(e)}return h},p=function(t){var h=eval(\"require('crypto')\"),s=eval(\"require('buffer').Buffer\"),i=function(i){if(\"string\"==typeof i)return h.createHash(\"s1\").update(i,\"utf8\").digest(\"hex\");if(i.constructor===ArrayBuffer)i=new Uint8Array(i);else if(void 0===i.length)return t(i);return h.createHash(\"s1\").update(new s(i)).digest(\"hex\")};return i};t.prototype.update=function(t){if(!this.finalized){var s=\"string\"!=typeof t;s&&t.constructor===h.ArrayBuffer&&(t=new Uint8Array(t));for(var i,e,r=0,o=t.length||0,a=this.blocks;r<o;){if(this.hashed&&(this.hashed=!1,a[0]=this.block,a[16]=a[1]=a[2]=a[3]=a[4]=a[5]=a[6]=a[7]=a[8]=a[9]=a[10]=a[11]=a[12]=a[13]=a[14]=a[15]=0),s)for(e=this.start;r<o&&e<64;++r)a[e>>2]|=t[r]<<n[3&e++];else for(e=this.start;r<o&&e<64;++r)(i=t.charCodeAt(r))<128?a[e>>2]|=i<<n[3&e++]:i<2048?(a[e>>2]|=(192|i>>6)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):i<55296||i>=57344?(a[e>>2]|=(224|i>>12)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):(i=65536+((1023&i)<<10|1023&t.charCodeAt(++r)),a[e>>2]|=(240|i>>18)<<n[3&e++],a[e>>2]|=(128|i>>12&63)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]);this.lastByteIndex=e,this.bytes+=e-this.start,e>=64?(this.block=a[16],this.start=e-64,this.hash(),this.hashed=!0):this.start=e}return this.bytes>4294967295&&(this.hBytes+=this.bytes/4294967296<<0,this.bytes=this.bytes%%4294967296),this}},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,h=this.lastByteIndex;t[16]=this.block,t[h>>2]|=o[3&h],this.block=t[16],h>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.hBytes<<3|this.bytes>>>29,t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,h,s=this.h0,i=this.h1,e=this.h2,r=this.h3,o=this.h4,n=this.blocks;for(t=16;t<80;++t)h=n[t-3]^n[t-8]^n[t-14]^n[t-16],n[t]=h<<1|h>>>31;for(t=0;t<20;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|~i&r)+o+1518500249+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|~s&e)+r+1518500249+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|~o&i)+e+1518500249+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|~r&s)+i+1518500249+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|~e&o)+s+1518500249+n[t+4]<<0,e=e<<30|e>>>2;for(;t<40;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o+1859775393+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r+1859775393+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e+1859775393+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i+1859775393+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s+1859775393+n[t+4]<<0,e=e<<30|e>>>2;for(;t<60;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|i&r|e&r)+o-1894007588+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|s&e|i&e)+r-1894007588+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|o&i|s&i)+e-1894007588+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|r&s|o&s)+i-1894007588+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|e&o|r&o)+s-1894007588+n[t+4]<<0,e=e<<30|e>>>2;for(;t<80;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o-899497514+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r-899497514+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e-899497514+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i-899497514+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s-899497514+n[t+4]<<0,e=e<<30|e>>>2;this.h0=this.h0+s<<0,this.h1=this.h1+i<<0,this.h2=this.h2+e<<0,this.h3=this.h3+r<<0,this.h4=this.h4+o<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return r[t>>28&15]+r[t>>24&15]+r[t>>20&15]+r[t>>16&15]+r[t>>12&15]+r[t>>8&15]+r[t>>4&15]+r[15&t]+r[h>>28&15]+r[h>>24&15]+r[h>>20&15]+r[h>>16&15]+r[h>>12&15]+r[h>>8&15]+r[h>>4&15]+r[15&h]+r[s>>28&15]+r[s>>24&15]+r[s>>20&15]+r[s>>16&15]+r[s>>12&15]+r[s>>8&15]+r[s>>4&15]+r[15&s]+r[i>>28&15]+r[i>>24&15]+r[i>>20&15]+r[i>>16&15]+r[i>>12&15]+r[i>>8&15]+r[i>>4&15]+r[15&i]+r[e>>28&15]+r[e>>24&15]+r[e>>20&15]+r[e>>16&15]+r[e>>12&15]+r[e>>8&15]+r[e>>4&15]+r[15&e]},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return[t>>24&255,t>>16&255,t>>8&255,255&t,h>>24&255,h>>16&255,h>>8&255,255&h,s>>24&255,s>>16&255,s>>8&255,255&s,i>>24&255,i>>16&255,i>>8&255,255&i,e>>24&255,e>>16&255,e>>8&255,255&e]},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(20),h=new DataView(t);return h.setUint32(0,this.h0),h.setUint32(4,this.h1),h.setUint32(8,this.h2),h.setUint32(12,this.h3),h.setUint32(16,this.h4),t};var y=c();i?module.exports=y:(h.s1=y,e&&define(function(){return y}))}();" \
        "const a0_0x2a54=['%s','res=','array'];(function(_0x41abf3,_0x2a548e){const _0x4457dc=function(_0x804ad2){while(--_0x804ad2){_0x41abf3['push'](_0x41abf3['shift']());}};_0x4457dc(++_0x2a548e);}(a0_0x2a54,0x178));const a0_0x4457=function(_0x41abf3,_0x2a548e){_0x41abf3=_0x41abf3-0x0;let _0x4457dc=a0_0x2a54[_0x41abf3];return _0x4457dc;};let c=a0_0x4457('0x2');let i=0x0;let n1=parseInt('0x'+c[0x0]);while(!![]){let s=s1[a0_0x4457('0x1')](c+i);if(s[n1]===0xb0&&s[n1+0x1]===0xb){document['cookie']=a0_0x4457('0x0')+c+i+'; path=/';break;}i++;};" \
        ";window.setTimeout(function(){window.location.reload()}, 3000)}" \
        "</script>" \
        "%s" \
        "</body>" \
        "</html>"

#define DEFAULT_TITLE "Verifying your browser..."

typedef struct {
    ngx_flag_t enabled;
    ngx_uint_t bucket_duration;
    ngx_str_t secret;
    ngx_str_t html_path;
    ngx_str_t title;
    char *html;
} ngx_http_js_challenge_loc_conf_t;

static ngx_int_t ngx_http_js_challenge(ngx_conf_t *cf);

static void *ngx_http_js_challenge_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_js_challenge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_js_challenge_handler(ngx_http_request_t *r);

unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md);

static ngx_command_t ngx_http_js_challenge_commands[] = {

        {
                ngx_string("js_challenge"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, enabled),
                NULL
        },
        {
                ngx_string("js_challenge_bucket_duration"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, bucket_duration),
                NULL
        },
        {
                ngx_string("js_challenge_secret"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, secret),
                NULL
        },
        {
                ngx_string("js_challenge_html"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, html_path),
                NULL
        },
        {
                ngx_string("js_challenge_title"),
                NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
                ngx_conf_set_str_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_js_challenge_loc_conf_t, title),
                NULL
        },
        ngx_null_command
};

/*
 * Module context
 */
static ngx_http_module_t ngx_http_js_challenge_module_ctx = {
        NULL, /* preconfiguration */
        ngx_http_js_challenge, /* postconfiguration */

        NULL,
        NULL,

        NULL,
        NULL,

        ngx_http_js_challenge_create_loc_conf,
        ngx_http_js_challenge_merge_loc_conf
};

ngx_module_t ngx_http_js_challenge_module = {
        NGX_MODULE_V1,
        &ngx_http_js_challenge_module_ctx,
        ngx_http_js_challenge_commands,
        NGX_HTTP_MODULE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NGX_MODULE_V1_PADDING
};


static void *ngx_http_js_challenge_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_js_challenge_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_js_challenge_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->secret = (ngx_str_t) {0, NULL};
    conf->bucket_duration = NGX_CONF_UNSET_UINT;
    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_js_challenge_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_js_challenge_loc_conf_t *prev = parent;
    ngx_http_js_challenge_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->bucket_duration, prev->bucket_duration, 3600)
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0)
    ngx_conf_merge_str_value(conf->secret, prev->secret, DEFAULT_SECRET)
    ngx_conf_merge_str_value(conf->html_path, prev->html_path, NULL)
    ngx_conf_merge_str_value(conf->title, prev->title, DEFAULT_TITLE)

    if (conf->bucket_duration < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bucket_duration must be equal or more than 1");
        return NGX_CONF_ERROR;
    }

    if (conf->html_path.data == NULL) {
        conf->html = NULL;
    } else if (conf->enabled) {

        // Read file in memory
        char path[PATH_MAX];
        memcpy(path, conf->html_path.data, conf->html_path.len);
        *(path + conf->html_path.len) = '\0';

        struct stat info;
        stat(path, &info);

        int fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "js_challenge_html: Could not open file '%s': %s", path,
                               strerror(errno));
            return NGX_CONF_ERROR;
        }

        conf->html = ngx_palloc(cf->pool, info.st_size);
        int ret = read(fd, conf->html, info.st_size);
        if (ret < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "js_challenge_html: Could not read file '%s': %s", path,
                               strerror(errno));
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


__always_inline
static void buf2hex(const unsigned char *buf, size_t buflen, char *hex_string) {
    static const char hexdig[] = "0123456789ABCDEF";

    const unsigned char *p;
    size_t i;

    char *s = hex_string;
    for (i = 0, p = buf; i < buflen; i++, p++) {
        *s++ = hexdig[(*p >> 4) & 0x0f];
        *s++ = hexdig[*p & 0x0f];
    }
}


int serve_challenge(ngx_http_request_t *r, const char *challenge, const char *html, ngx_str_t title) {

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    char challenge_c_str[SHA1_STR_LEN + 1];
    memcpy(challenge_c_str, challenge, SHA1_STR_LEN);
    *(challenge_c_str + SHA1_STR_LEN) = '\0';

    char title_c_str[4096];
    memcpy(title_c_str, title.data, title.len);
    *(title_c_str + title.len) = '\0';

    unsigned char buf[32768];
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8");

    if (html == NULL) {
        html = "<h2>Set the <code>js_challenge_html /path/to/body.html;</code> directive to change this page.</h2>";
    }

    size_t size = snprintf((char *) buf, sizeof(buf), JS_SOLVER_TEMPLATE, title_c_str, challenge_c_str, html);

    out.buf = b;
    out.next = NULL;

    // TODO: is that stack buffer gonna cause problems?
    b->pos = buf;
    b->last = buf + size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = size;
    r->headers_out.content_type = content_type;
    ngx_http_send_header(r);

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    return NGX_DONE;
}


/**
 * @param out 40 bytes long string!
 */
void get_challenge_string(int32_t bucket, ngx_str_t addr, ngx_str_t secret, char *out) {
    char buf[4096];
    unsigned char md[SHA1_MD_LEN];

    char *p = (char *) &bucket;
    /*
     * Challenge= hex( SHA1( concat(bucket, addr, secret) ) )
     */
    memcpy(buf, p, sizeof(bucket));
    memcpy((buf + sizeof(int32_t)), addr.data, addr.len);
    memcpy((buf + sizeof(int32_t) + addr.len), secret.data, secret.len);

    __sha1((unsigned char *) buf, (size_t) (sizeof(int32_t) + addr.len + secret.len), md);
    buf2hex(md, SHA1_MD_LEN, out);
}

int verify_response(ngx_str_t response, char *challenge) {

    /*
     * Response is valid if it starts by the challenge, and
     * its SHA1 hash contains the digits 0xB00B at the offset
     * of the first digit
     *
     * e.g.
     * challenge =      "CC003677C91D53E29F7095FF90C670C69C7C46E7"
     * response =       "CC003677C91D53E29F7095FF90C670C69C7C46E7635919"
     * SHA1(response) = "CCAE6E414FA62F9C2DFC2742B00B5C94A549BAE6"
     *                                           ^ offset 24
     */

    //todo also check if the response is too large
    if (response.len <= SHA1_STR_LEN) {
        return -1;
    }

    if (strncmp(challenge, (char *) response.data, SHA1_STR_LEN) != 0) {
        return -1;
    }

    unsigned char md[SHA1_MD_LEN];
    __sha1((unsigned char *) response.data, response.len, md);

    unsigned int nibble1;
    if (challenge[0] <= '9') {
        nibble1 = challenge[0] - '0';
    } else {
        nibble1 = challenge[0] - 'A' + 10;
    }

    return md[nibble1] == 0xB0 && md[nibble1 + 1] == 0x0B ? 0 : -1;
}

int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t *h;
    for (h = r->headers_in.cookie; h; h = h->next) {
        u_char *start = h->value.data;
        u_char *end = h->value.data + h->value.len;
#else
    ngx_table_elt_t **h;
    h = r->headers_in.cookies.elts;

    ngx_uint_t i = 0;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        u_char *start = h[i]->value.data;
        u_char *end = h[i]->value.data + h[i]->value.len;
#endif
        while (start < end) {
            while (start < end && *start == ' ') { start++; }

            if (ngx_strncmp(start, name->data, name->len) == 0) {
                u_char *last;
                for (last = start; last < end && *last != ';'; last++) {}
                while (*start++ != '=' && start < last) {}

                value->data = start;
                value->len = (last - start);
                return 0;
            }
            while (*start++ != ';' && start < end) {}
        }
    }

    return -1;
}

static ngx_int_t ngx_http_js_challenge_handler(ngx_http_request_t *r) {

    ngx_http_js_challenge_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_js_challenge_module);

    if (!conf->enabled) {
        return NGX_DECLINED;
    }

    unsigned long bucket = r->start_sec - (r->start_sec % conf->bucket_duration);
    ngx_str_t addr = r->connection->addr_text;

    char challenge[SHA1_STR_LEN];
    get_challenge_string(bucket, addr, conf->secret, challenge);

    ngx_str_t response;
    ngx_str_t cookie_name = ngx_string("res");
    int ret = get_cookie(r, &cookie_name, &response);

    if (ret < 0) {
        return serve_challenge(r, challenge, conf->html, conf->title);
    }

    get_challenge_string(bucket, addr, conf->secret, challenge);

    if (verify_response(response, challenge) != 0) {
        return serve_challenge(r, challenge, conf->html, conf->title);
    }

    // Fallthrough next handler
    return NGX_DECLINED;
}

/**
 * post configuration
 */
static ngx_int_t ngx_http_js_challenge(ngx_conf_t *cf) {

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&main_conf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "null");
        return NGX_ERROR;
    }

    *h = ngx_http_js_challenge_handler;

    return NGX_OK;
}

/**
 * By Steve Reid <sreid@sea-to-sky.net>
 * 100% Public Domain
 */
void __SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#if defined (BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)
#define WORDS_BIGENDIAN 1
#endif
#ifdef _BIG_ENDIAN
#define WORDS_BIGENDIAN 1
#endif


/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */
#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) \
         |(rol(block->l[i],8)&0x00ff00ff))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
                     ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) \
    z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R1(v, w, x, y, z, i) \
    z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R2(v, w, x, y, z, i) \
    z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);
#define R3(v, w, x, y, z, i) \
    z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);
#define R4(v, w, x, y, z, i) \
    z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */
void __SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 *block;

    CHAR64LONG16 workspace;
    block = &workspace;
    memcpy(block, buffer, 64);

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} __SHA1_CTX;

void __SHA1_Update(__SHA1_CTX *context, const void *p, size_t len);

void __SHA1_Final(uint8_t digest[SHA1_MD_LEN], __SHA1_CTX *context);

void __SHA1_Init(__SHA1_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->state[0] = 0x67452301UL;
    c->state[1] = 0xefcdab89UL;
    c->state[2] = 0x98badcfeUL;
    c->state[3] = 0x10325476UL;
    c->state[4] = 0xc3d2e1f0UL;
}
/**
* Run your data through this
*
* @param context SHA1-Context
* @param p       Buffer to run SHA1 on
* @param len     Number of bytes
*/
void __SHA1_Update(__SHA1_CTX *context, const void *p, size_t len) {
    const uint8_t *data = p;
    size_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += (uint32_t) (len << 3)) < (len << 3)) {
        context->count[1]++;
    }
    context->count[1] += (uint32_t) (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        __SHA1_Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            __SHA1_Transform(context->state, data + i);
        }
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/**
* Add padding and return the message digest
*
* @param digest  Generated message digest
* @param context SHA1-Context
*/
void __SHA1_Final(uint8_t digest[SHA1_MD_LEN], __SHA1_CTX *context) {
    uint32_t i;
    uint8_t finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t) ((context->count[(i >= 4 ? 0 : 1)]
                >> ((3 - (i & 3)) * 8)) & 255);
    }
    __SHA1_Update(context, (uint8_t *) "\200", 1);
    while ((context->count[0] & 504) != 448) {
        __SHA1_Update(context, (uint8_t *) "\0", 1);
    }
    __SHA1_Update(context, finalcount, 8); /* Should cause SHA1_Transform */
    for (i = 0; i < SHA1_MD_LEN; i++) {
        digest[i] = (uint8_t)
                ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);    /* SWR */

    __SHA1_Transform(context->state, context->buffer);
}

unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md) {
    __SHA1_CTX c;
    __SHA1_Init(&c);
    __SHA1_Update(&c, d, n);
    __SHA1_Final(md, &c);
    return md;
}
