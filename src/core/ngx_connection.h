
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text;

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

    ngx_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


//(��������)��ʾ�ͻ�����������ģ�Nginx�������������ܵ�TCP����
//���������ⴴ���� ��������ӳ��л�ȡ�ö���
struct ngx_connection_s {
    void               *data;   //����δʹ��ʱ��data��Ա���ڳ䵱���ӳ��п������������е�nextָ�롣
                                //�����ӱ�ʹ��ʱ��data��������ʹ������nginxģ�����������HTTP����У�dataָ��ngx_http_request_t����
    ngx_event_t        *read;   //���Ӷ�Ӧ�Ķ��¼�
    ngx_event_t        *write;  //���Ӷ�Ӧ��д�¼�

    ngx_socket_t        fd;     //���Ӷ�Ӧ���׽��־��

    //����4����Ա�Է���ָ�����ʽ���֣� ˵��ÿ�����Ӷ����Բ��ò�ͬ�Ľ��շ����� ÿ���¼�����ģ�鶼�������ؾ�������Ϊ��
    //��ͬ���¼�����������Ҫʹ�õĽ��ա����ͷ�������ǲ�һ���ġ�
    ngx_recv_pt         recv;   //ֱ�ӽ��������ַ����ķ���������ϵͳ�����Ĳ�ָͬ��ͬ�ĺ���
    ngx_send_pt         send;   //ֱ�ӷ��������ַ����ķ���������ϵͳ�����Ĳ�ָͬ��ͬ�ĺ���
    ngx_recv_chain_pt   recv_chain; //��ngx_chain_t����Ϊ���������������ֽ����ķ���
    ngx_send_chain_pt   send_chain; //��ngx_chain_t����Ϊ���������������ֽ����ķ���

    ngx_listening_t    *listening;  //���Ӷ�Ӧ��ngx_listening_t�������󣬴�������listening�����˿ڵ��¼�����

    off_t               sent;   //�������Ѿ����ͳ�ȥ���ֽ���

    ngx_log_t          *log;    //���Լ�¼��־��ngx_log_t����

    ngx_pool_t         *pool;   //�ڴ�ء� һ����acceptһ��������ʱ�ᴴ��һ���ڴ�أ�����������ӽ���ʱ�������ڴ�ء�
                                //����ڴ�صĴ�С���������listening���������е�pool_size��Ա����
                                //ע�⣬ ������˵��������ָ�ɹ�������TCP���ӣ� ���е�ngx_connection_t�ṹ�嶼��Ԥ����ġ� 

    int                 type;

    struct sockaddr    *sockaddr;   //���ӿͻ��˵�sockaddr�ṹ��		
    socklen_t           socklen;    //sockaddr�ṹ��ĳ���		
    ngx_str_t           addr_text;  //���ӿͻ����ַ�����ʽ��ip��ַ	

    ngx_str_t           proxy_protocol_addr;
    in_port_t           proxy_protocol_port;

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr; //�����ļ����˿ڶ�Ӧ��sockaddr�ṹ�壬Ҳ����listening���������е�sockaddr��Ա
    socklen_t           local_socklen;

    ngx_buf_t          *buffer; //���ڽ��ա�����ͻ��˷������ֽ�����ÿ���¼�����ģ������ɾ��������ӳ��з�����Ŀռ�����ֶΡ�
                                //���磬��HTTPģ���У����Ĵ�С������client_header_buffer_size������	

    ngx_queue_t         queue;  //��������ǰ������˫������Ԫ�ص���ʽ��ӵ�ngx_cycle_t���Ľṹ���reuseable_connections_queue˫�������У���ʾ�������õ�����

    ngx_atomic_uint_t   number; //����ʹ�ô�����ngx_connection_t�ṹ��ÿ�ν���һ�����Կͻ��˵����ӣ����������������˷�������������ʱ(ngx_peer_connection_sҲʹ����)��number����� 1

    ngx_uint_t          requests;   //������������

    unsigned            buffered:8; //�����е�ҵ�����͡� �κ��¼�����ģ�鶼�����Զ�����Ҫ�ı�־λ�����buffered�ֶ���8λ�� ������ͬʱ��ʾ8����ͬ��ҵ�� 
                                    //������ģ�����Զ���buffered��־λʱע�ⲻҪ�����ʹ�õ�ģ�鶨��ı�־λ��ͻ�� 
                                    //Ŀǰopensslģ�鶨����һ����־λ��#define NGX_SSL_BUFFERED 0x01
                                    //HTTP�ٷ�ģ�鶨�������±�־λ��#define NGX_HTTP_LOWLEVEL_BUFFERED 0xf0 #define NGX_HTTP_WRITE_BUFFERED 0x10 #define NGX_HTTP_GZIP_BUFFERED 0x20
                                    //#define NGX_HTTP_SSI_BUFFERED 0x01 #define NGX_HTTP_SUB_BUFFERED 0x02 #define NGX_HTTP_COPY_BUFFERED 0x04 #define NGX_HTTP_IMAGE_BUFFERED 0x08
                                    //ͬʱ������HTTPģ����ԣ�buffered�ĵ�4λҪ���ã���ʵ�ʷ�����Ӧ��ngx_http_write_filter_module����ģ���У���4λ��־λΪ1����ζ��Nginx��һֱ��Ϊ��
                                    //HTTPģ�黹��Ҫ����������� ����ȴ�HTTPģ�齫��4λȫ��Ϊ0�Ż������������� ����4λ�ĺ����£�#define NGX_LOWLEVEL_BUFFERED 0x0f

    unsigned            log_error:3;    //�����Ӽ�¼��־ʱ�ļ���, ��ngx_connection_log_error_eö�ٱ�ʾ  
    unsigned            timedout:1;     //��־λ��Ϊ 1ʱ��ʾ�����ѳ�ʱ
    unsigned            error:1;        //��־λ��Ϊ 1ʱ��ʾ���Ӵ�������г��ִ���
    unsigned            destroyed:1;    //��־λ��Ϊ 1ʱ��ʾ�����Ѿ����١����������ָ����TCP���ӣ�������ngx_connection_t�ṹ�塣
	                                    //��destroyedΪ 1ʱ���ṹ����Ȼ���ڣ������Ӧ���׽��֡��ڴ�ص��Ѿ�������

    unsigned            idle:1;         //��־λ��Ϊ 1ʱ��ʾ���Ӵ��ڿ���״̬����keepalive��������������֮���״̬
    unsigned            reusable:1;     //��־λ��Ϊ 1ʱ��ʾ���ӿ����ã����������queue�ֶ��Ƕ�Ӧʹ�õ�
    unsigned            close:1;        //��־λ��Ϊ 1ʱ��ʾ���ӹر�
    unsigned            shared:1;

    unsigned            sendfile:1;     //��־λ��Ϊ 1ʱ��ʾ�����ļ��е����ݷ������ӵ���һ��
    unsigned            sndlowat:1;     //��־λ��Ϊ 1ʱ��ʾֻ���������׽��ֶ�Ӧ�ķ��ͻ�������������������õĴ�С��ֵʱ���¼�����ģ��Ż�ַ����¼���
                                        //��ngx_handle_write_event�����е�lowat�����Ƕ�Ӧ�ġ��Ƿ����ø����ӵķ��͵�ˮλ��־�������ù��������ظ�����
    unsigned            tcp_nodelay:2;  //��־λ����ʾ���ʹ��TCP��nodelay���ԡ� ����ȡֵ��Χ��ngx_connection_tcp_nodelay_eö������
    unsigned            tcp_nopush:2;   //��־λ����ʾ���ʹ��TCP��nopush���ԡ� ����ȡֵ��Χ��ngx_connection_tcp_nopush_eö������

    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_conf_t *cf, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
