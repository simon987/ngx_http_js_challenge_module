#include <stdio.h>
#include "ngx_http.c"

static ngx_int_t ngx_http_hello_world(ngx_conf_t *cf);

static char *setup1(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_hello_world_commands[] = {

        {ngx_string("hello_world"),

                // NGX_CONF_TAKE1, for 1 arg etc
                // NGX_CONF_FLAG for boolean
         NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_NOARGS,


         setup1, /* configuration setup function */
         0, /* No offset. Only one context is supported. */
         0, /* No offset when storing the module configuration on struct. */
         NULL},

        ngx_null_command /* command termination */
};

/* The hello world string. */
//static u_char ngx_hello_world[] = HELLO_WORLD;

/* The module context. */
static ngx_http_module_t ngx_http_hello_world_module_ctx = {
        NULL, /* preconfiguration */
        ngx_http_hello_world, /* postconfiguration */

        NULL, /* create main configuration */
        NULL, /* init main configuration */

        NULL, /* create server configuration */
        NULL, /* merge server configuration */

        NULL, /* create location configuration */
        NULL /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_hello_world_module = {
        NGX_MODULE_V1,
        &ngx_http_hello_world_module_ctx, /* module context */
        ngx_http_hello_world_commands, /* module directives */
        NGX_HTTP_MODULE, /* module type */
        NULL, /* init master */
        NULL, /* init module */
        NULL, /* init process */
        NULL, /* init thread */
        NULL, /* exit thread */
        NULL, /* exit process */
        NULL, /* exit master */
        NGX_MODULE_V1_PADDING
};

__always_inline
void buf2hex(const unsigned char *buf, size_t buflen, char *hex_string) {
    static const char hexdig[] = "0123456789ABCDEF";

    const unsigned char *p;
    size_t i;

    char *s = hex_string;
    for (i = 0, p = buf; i < buflen; i++, p++) {
        *s++ = hexdig[(*p >> 4) & 0x0f];
        *s++ = hexdig[*p & 0x0f];
    }
}

#define SHA1_MD_LEN 20
#define SHA1_STR_LEN 40

const int JS_SOLVER_CHALLENGE_OFFSET = 84 + 8 + 13;
//static const u_char JS_SOLVER[] = "Hello, workd";
static const u_char JS_SOLVER[] =
        "<script src='https://cdn.jsdelivr.net/gh/emn178/js-sha1/build/sha1.min.js'></script>"
        "<script>"
        "    let c = '0000000000000000000000000000000000000000';"
        "    let i = 0;"
        "    let n1 = parseInt('0x' + c[0]);"
        "    while (true) {"
        "        let s = sha1.array(c + i);"
        "        if (s[n1] === 0xB0 && s[n1 + 1] === 0x0B && (s[n1 + 2] & 0xF0) === 0x50) {"
        "            document.cookie = 'res=' + c + i + ';';"
        "            window.location.reload();"
        "            break;"
        "        };"
        "        i++;"
        "    }"
        "</script>Hello";

int serve_challenge(ngx_http_request_t *r, const char *challenge) {

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    unsigned char buf[9000];
    memcpy(buf, JS_SOLVER, sizeof(JS_SOLVER));
    memcpy(buf + JS_SOLVER_CHALLENGE_OFFSET, challenge, SHA1_STR_LEN);

    out.buf = b;
    out.next = NULL;

    // TODO: is that stack buffer gonna cause problems?
    b->pos = buf;
    b->last = buf + sizeof(JS_SOLVER) - 1;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sizeof(JS_SOLVER) - 1;
    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
}

/**
 * @param bucket
 * @param addr
 * @param secret
 * @param out 40 bytes long string!
 */
void get_challenge_string(int32_t bucket, ngx_str_t addr, const char *secret, char *out) {
    char buf[4096];
    unsigned char md[SHA1_MD_LEN];

    /*
     * Challenge= hex( SHA1( concat(bucket, addr, secret) ) )
     */
    *((int32_t *) buf) = bucket;
    memcpy((buf + sizeof(int32_t)), addr.data, addr.len);
    memcpy((buf + sizeof(int32_t) + addr.len), secret, strlen(secret));

    SHA1((unsigned char *) buf, (size_t) (sizeof(int32_t) + addr.len + strlen(secret)), md);
    buf2hex(md, SHA1_MD_LEN, out);
}

int verify_response(int32_t bucket, ngx_str_t addr, const char *secret, ngx_str_t response, char *challenge) {

    /*
     * Response is valid if it starts by the challenge, and
     * its SHA1 hash contains the digits 0xB00B5 at the offset
     * of the first digit
     *
     * e.g.
     * challenge =      "CC003677C91D53E29F7095FF90C670C69C7C46E7"
     * response =       "CC003677C91D53E29F7095FF90C670C69C7C46E7635919"
     * SHA1(response) = "CCAE6E414FA62F9C2DFC2742B00B5C94A549BAE6"
     *                                           ^ offset 24
     */

    if (response.len <= SHA1_STR_LEN) {
        return -1;
    }

    if (strncmp(challenge, (char *) response.data, SHA1_STR_LEN) != 0) {
        return -1;
    }

    unsigned char md[SHA1_MD_LEN];
    SHA1((unsigned char *) response.data, response.len, md);

    unsigned int nibble1 = challenge[0] & 0xF0;

    return md[nibble1] == 0 && md[nibble1 + 1] == 0;
}

int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
    ngx_table_elt_t **h;

    h = r->headers_in.cookies.elts;

    for (ngx_uint_t i = 0; i < r->headers_in.cookies.nelts; i++) {
        u_char *start = h[i]->value.data;
        u_char *end = h[i]->value.data + h[i]->value.len;

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

static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t *r) {

    //TODO: If the bucket is less than 5sec away from the next one, accept both current and latest bucket

    //TODO: argument
    const char *secret = "my secret";

    //TODO: argument
    const long bucketSize = 30;

    long bucket = r->start_sec - (r->start_sec % bucketSize);
    ngx_str_t addr = r->connection->addr_text;

    // Use real-ip ?
    char challenge[SHA1_STR_LEN];
    get_challenge_string(bucket, addr, secret, challenge);

    ngx_str_t response;
    int ret = get_cookie(r, &((ngx_str_t) ngx_string("res")), &response);

    //TODO: remove debug msg
    char msg[4096];

    sprintf(msg, "TS=%lu BUCKET=%lu SECRET=%s CHALLENGE=%s RET=%d COOKIE=%s",
            r->start_sec, bucket, secret, challenge, ret, response.data);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, msg);

    get_challenge_string(bucket, addr, secret, challenge);

    if (ret == NGX_DECLINED || verify_response(bucket, addr, secret, response, challenge) != 0) {
        //Serve challenge
        return serve_challenge(r, challenge);
    }

    return NGX_DECLINED;
}

//ngx_conf_set_flag_slot: translates "on" or "off" to 1 or 0
//ngx_conf_set_str_slot: saves a string as an ngx_str_t
//ngx_conf_set_num_slot: parses a number and saves it to an int
//ngx_conf_set_size_slot: parses a data size ("8k", "1m", etc.) and saves it to a size_t


static char *setup1(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
//    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
//    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
//    clcf->handler = ngx_http_hello_world_handler;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_hello_world(ngx_conf_t *cf) {

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "null");
        return NGX_ERROR;
    }

    *h = ngx_http_hello_world_handler;

    return NGX_OK;
}

