
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
    void                     *data; //�����ڴ��ض�����,������˹����ڴ��ģ������	
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init; //�����ڴ��ض���ʼ������
    void                     *tag;  //�����ڴ��ǩ�����ڱ����ù����ڴ������ĸ�ģ��
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct ngx_cycle_s {
    void                  ****conf_ctx; //���������к���ģ������ýṹ���ָ��
    ngx_pool_t               *pool; //�ڴ��

    ngx_log_t                *log;  //��־ģ�����ṩ�����ɻ���ngx_log_t��־����Ĺ��ܣ������logʵ�������ڻ�û��ִ��ngx_init_cycle����ǰ��Ҳ���ǻ�û�н�������ǰ��
                                    //���������Ҫ�������־���ͻ���ʱʹ��log���������������Ļ����ngx_init_cycle����ִ�к󣬽������nginx.conf�����ļ��е������
                                    //�������ȷ����־�ļ�����ʱ���log���¸�ֵ
    ngx_log_t                 new_log;  //��nginx.conf�����ļ���ȡ����־�ļ�·���󣬽���ʼ��ʼ��error_log��־�ļ�������log���������������־����Ļ��
                                        //��ʱ����new_log������ʱ�Ե����log��־������ʼ���ɹ��󣬻���new_log�ĵ�ַ���������logָ��

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;    //����poll��rtsig�������¼�ģ�飬������Ч�ļ��������Ԥ�Ƚ�����Щngx_connection_t�ṹ�壬�Լ����¼����ռ����ַ���
                                        //��ʱfiles�ͻᱣ������ngx_connection_t��ָ����ɵ����飬files_n����ָ������������ļ������ֵ��������files�����Ա
    ngx_connection_t         *free_connections;     //�������ӳأ���free_connection_n���ʹ��
    ngx_uint_t                free_connection_n;    //�������ӳ������ӵ�����

    ngx_module_t            **modules;
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;   //ngx_connection_t���͵�˫��������������ʾ���ظ�ʹ�õ����ӵĶ���

    ngx_array_t               listening;    //ngx_listening_t���͵Ķ�̬���飬��ʾ�����˿ڼ���ز���
    ngx_array_t               paths;    //ngx_path_t*���͵Ķ�̬���飬������Nginx����Ҫ����������Ŀ¼�������Ŀ¼�����ڣ�������Ŀ¼ʧ�ܻᵼ��Nginx����ʧ�ܡ�
                                        //���磬�ϴ��ļ�����ʱĿ¼Ҳ��pathes�У����û��Ȩ�޴�������ᵼ��Nginx�޷�����

    ngx_array_t               config_dump;  //ngx_conf_dump_t���͵�����
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    ngx_list_t                open_files;   //ngx_open_file_t ���͵ĵ�������ʾNginx�Ѿ��򿪵������ļ�����ʵ�ϣ�Nginx��ܲ�����open_files����������ļ��������ɸ���Ȥ��ģ������������ļ�·������Nginx��ܻ���ngx_init_cycle�����д���Щ�ļ�
    ngx_list_t                shared_memory;    //ngx_shm_zone_t ���͵ĵ������洢����ģ�����Ĺ����ڴ�

    ngx_uint_t                connection_n; //��ǰ�������������Ӷ������������connections��Ա���ʹ��
    ngx_uint_t                files_n;  //�������files��Ա���ʹ�ã�ָ��files������Ԫ�ص�����

    ngx_connection_t         *connections;  //Ԥ�����connection_n�����ӡ�ÿ����������Ҫ�Ķ�/д�¼�������ͬ��������Ŷ�Ӧ��read_events��write_events��/д�¼����飬��ͬ�������3�������е�Ԫ�������ʹ�õ�
    ngx_event_t              *read_events;  //Ԥ�����connection_n�����¼�
    ngx_event_t              *write_events; //Ԥ�����connection_n��д�¼�

    ngx_cycle_t              *old_cycle;    //�ɵ�ngx_cycle_t��������������һ��ngx_cycle_t�����еĳ�Ա�����磬ngx_init_cycle������
                                            //���������ڣ���Ҫ����һ����ʱ��ngx_cycle_t���󱣴�һЩ�������ٵ���ngx_init_cycle����
                                            //ʱ�Ϳ��԰Ѿɵ�ngx_cycle_t���󴫵ݽ�ȥ������ʱold_cycle����ͻᱣ�����ǰ�ڵ�ngx_cycle_t����

    ngx_str_t                 conf_file;    //�����ļ�(һ����nginx.conf)����ڰ�װĿ¼��·������  //�����ļ�(һ����nginx.conf)�ľ���·��
    ngx_str_t                 conf_param;   //Nginx���������ļ�ʱ��Ҫ���⴦�������Я���Ĳ�����һ����-gѡ��Я���Ĳ���
    ngx_str_t                 conf_prefix;  //Nginx�����ļ�·����ǰ׺
    ngx_str_t                 prefix;   //Nginx��װĿ¼��·����ǰ׺
    ngx_str_t                 lock_file;    //���ڽ��̼�ͬ�����ļ�������
    ngx_str_t                 hostname; //ʹ��gethostnameϵͳ���õõ���������
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
