
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx;
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections;     //可用连接池，与free_connection_n配合使用
    ngx_uint_t                free_connection_n;    //可用连接池中连接的总数

    ngx_module_t            **modules;
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;

    ngx_array_t               listening;
    ngx_array_t               paths;

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    ngx_list_t                open_files;
    ngx_list_t                shared_memory;

    ngx_uint_t                connection_n; //当前进程中所有连接对象的总数，与connections成员配合使用
    ngx_uint_t                files_n;

    ngx_connection_t         *connections;  //预分配的connection_n个连接。每个连接所需要的读/写事件都以相同的数组序号对应着read_events、write_events读/写事件数组，相同序号下这3个数组中的元素是配合使用的
    ngx_event_t              *read_events;  //预分配的connection_n个读事件
    ngx_event_t              *write_events; //预分配的connection_n个写事件

    ngx_cycle_t              *old_cycle;

    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
    ngx_str_t                 prefix;
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


typedef struct {
    ngx_flag_t                daemon;   //是否以守护进程的方式运行Nginx。守护进程是脱离终端并且在后台允许的进程
    ngx_flag_t                master;   //是否以master/worker方式工作。
                                        //如果关闭了master_process工作方式，就不会fork出worker子进程来处理请求，而是用master进程自身来处理请求

    ngx_msec_t                timer_resolution; //系统调用gettimeofday的执行频率
                                                //默认情况下，每次内核的事件调用(如epoll)返回时，都会执行一次getimeofday，实现用内核时钟来更新Nginx中的缓存时钟，
                                                //若设置timer_resolution则定期更新Nginx中的缓存时钟             

    ngx_int_t                 worker_processes; //工作进程的个数
    ngx_int_t                 debug_points; //Nginx在一些关键的错误逻辑中设置了调试点。
                                            //如果设置了debug_points为NGX_DEBUG_POINTS_STOP，那么Nginx执行到这些调试点时就会发出SIGSTOP信号以用于调试
                                            //如果设置了debug_points为NGX_DEBUG_POINTS_ABORT，那么Nginx执行到这些调试点时就会产生一个coredump文件，可以使用gdb来查看Nginx当时的各种信息

    ngx_int_t                 rlimit_nofile;    //每个工作进程的打开文件数的最大值限制(RLIMIT_NOFILE)
    off_t                     rlimit_core;  //coredump核心转储文件的最大大小。在Linux系统中，当进程发生错误或收到信号而终止时，系统会将进程执行时的内存内容(核心映像)
                                            //写入一个文件(core文件)，以作调试之用，这就是所谓的核心转储(core dump)

    int                       priority; //指定Nginx worker进程的nice优先级

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;   //cpu_affinity数组元素个数
    ngx_cpuset_t             *cpu_affinity; //uint64_t类型的数组，每个元素表示一个工作进程的CPU亲和性掩码

    char                     *username; //用户名(work进程)
    ngx_uid_t                 user;     //用户UID(work进程)
    ngx_gid_t                 group;    //用户GID(work进程)

    ngx_str_t                 working_directory;    //指定进程当前工作目录
    ngx_str_t                 lock_file;    //lock文件的路径

    ngx_str_t                 pid;  //保存master进程ID的pid文件存放路径
    ngx_str_t                 oldpid;

    ngx_array_t               env;  //ngx_str_t类型的动态数组, 存储环境变量
    char                    **environment;
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
