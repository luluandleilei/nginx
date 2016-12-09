
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
    ngx_connection_t         *free_connections;     //�������ӳأ���free_connection_n���ʹ��
    ngx_uint_t                free_connection_n;    //�������ӳ������ӵ�����

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

    ngx_uint_t                connection_n; //��ǰ�������������Ӷ������������connections��Ա���ʹ��
    ngx_uint_t                files_n;

    ngx_connection_t         *connections;  //Ԥ�����connection_n�����ӡ�ÿ����������Ҫ�Ķ�/д�¼�������ͬ��������Ŷ�Ӧ��read_events��write_events��/д�¼����飬��ͬ�������3�������е�Ԫ�������ʹ�õ�
    ngx_event_t              *read_events;  //Ԥ�����connection_n�����¼�
    ngx_event_t              *write_events; //Ԥ�����connection_n��д�¼�

    ngx_cycle_t              *old_cycle;

    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
    ngx_str_t                 prefix;
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


typedef struct {
    ngx_flag_t                daemon;   //�Ƿ����ػ����̵ķ�ʽ����Nginx���ػ������������ն˲����ں�̨����Ľ���
    ngx_flag_t                master;   //�Ƿ���master/worker��ʽ������
                                        //����ر���master_process������ʽ���Ͳ���fork��worker�ӽ������������󣬶�����master������������������

    ngx_msec_t                timer_resolution; //ϵͳ����gettimeofday��ִ��Ƶ��
                                                //Ĭ������£�ÿ���ں˵��¼�����(��epoll)����ʱ������ִ��һ��getimeofday��ʵ�����ں�ʱ��������Nginx�еĻ���ʱ�ӣ�
                                                //������timer_resolution���ڸ���Nginx�еĻ���ʱ��             

    ngx_int_t                 worker_processes; //�������̵ĸ���
    ngx_int_t                 debug_points; //Nginx��һЩ�ؼ��Ĵ����߼��������˵��Ե㡣
                                            //���������debug_pointsΪNGX_DEBUG_POINTS_STOP����ôNginxִ�е���Щ���Ե�ʱ�ͻᷢ��SIGSTOP�ź������ڵ���
                                            //���������debug_pointsΪNGX_DEBUG_POINTS_ABORT����ôNginxִ�е���Щ���Ե�ʱ�ͻ����һ��coredump�ļ�������ʹ��gdb���鿴Nginx��ʱ�ĸ�����Ϣ

    ngx_int_t                 rlimit_nofile;    //ÿ���������̵Ĵ��ļ��������ֵ����(RLIMIT_NOFILE)
    off_t                     rlimit_core;  //coredump����ת���ļ�������С����Linuxϵͳ�У������̷���������յ��źŶ���ֹʱ��ϵͳ�Ὣ����ִ��ʱ���ڴ�����(����ӳ��)
                                            //д��һ���ļ�(core�ļ�)����������֮�ã��������ν�ĺ���ת��(core dump)

    int                       priority; //ָ��Nginx worker���̵�nice���ȼ�

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;   //cpu_affinity����Ԫ�ظ���
    ngx_cpuset_t             *cpu_affinity; //uint64_t���͵����飬ÿ��Ԫ�ر�ʾһ���������̵�CPU�׺�������

    char                     *username; //�û���(work����)
    ngx_uid_t                 user;     //�û�UID(work����)
    ngx_gid_t                 group;    //�û�GID(work����)

    ngx_str_t                 working_directory;    //ָ�����̵�ǰ����Ŀ¼
    ngx_str_t                 lock_file;    //lock�ļ���·��

    ngx_str_t                 pid;  //����master����ID��pid�ļ����·��
    ngx_str_t                 oldpid;

    ngx_array_t               env;  //ngx_str_t���͵Ķ�̬����, �洢��������
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
