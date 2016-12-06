
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

//当使用长连接与上游服务器通信时，可通过该方法由连接池中获取一个新连接
typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,       
    void *data);
//当使用长连接与上游服务器通信时，通过该方法将使用完毕的连接释放给连接池
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
typedef void (*ngx_event_notify_peer_pt)(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);


//(主动连接)Nginx主动向其他上游服务器建立链接，并以此连接与上游服务器通信
struct ngx_peer_connection_s {
    ngx_connection_t                *connection;    //一个主动连接实际上也需要ngx_connection_t结构体中的大部分成员，并且出于重用的考虑而定义了connection成员
                                                    //不可以随意创建， 必须从连接池中获取该对象

    struct sockaddr                 *sockaddr;  //远端服务器socket地址
    socklen_t                        socklen;   //sockaddr地址长度
    ngx_str_t                       *name;      //远端服务器的名称

    ngx_uint_t                       tries; //在连接一个远端服务器时，当前连接出现异常失败后可以重试的次数，也就是允许的最多失败次数
    ngx_msec_t                       start_time;

    ngx_event_get_peer_pt            get;   //获取连接的方法，如果使用长连接构成的连接池，那么必须要实现get方法	
    ngx_event_free_peer_pt           free;  //与get方法对应的释放连接的方法	      
    ngx_event_notify_peer_pt         notify;
    void                            *data;  //这个data指针仅用于和上面的get、free方法配合传递参数，它的具体含义与实现get方法、free方法的模块相关，
                                            //可参照ngx_event_get_peer_pt和ngx_event_free_peer_pt方法原型中的data参数

#if (NGX_SSL || NGX_COMPAT)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    ngx_addr_t                      *local; //本机地址信息

    int                              type;
    int                              rcvbuf;    //套接字的接收缓冲区大小

    ngx_log_t                       *log;   //记录日志的ngx_log_t对象

    unsigned                         cached:1;  //标志位，为 1时表示上面的connection连接已经缓存
    unsigned                         transparent:1;

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;   //本连接记录日志时的级别, 由ngx_connection_log_error_e枚举表示  

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
