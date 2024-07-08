#ifndef _THREAD_POOL_H 
#define _THREAD_POOL_H

typedef struct thread_pool_t thread_pool_t;
typedef void (*handler_pt) (void *);

typedef struct task_s {
    handler_pt func;    // 任务执行函数
    void *arg;  // 任务上下文
} task_t;

typedef struct task_queue_s {
    uint32_t head;  // 队列头
    uint32_t tail;  // 队列尾
    uint32_t count; // 队列任务数量
    task_t *queue;  //队列数量
} task_queue_t;

class thread_pool {
    public:
        thread_pool_t *thread_pool_create(int thrd_count, int queue_size);  // 创建线程池
        int thread_pool_post(thread_pool_t *pool, handler_pt func, void *arg);  // 抛出任务
        int thread_pool_destroy(thread_pool_t *pool);   // 销毁线程池
        int wait_all_donw(thread_pool_t *pool); // 等待所有线程退出

    private:
        pthread_mutex_t mutex;
        pthread_cond_t condition;
        pthread_t *threads;
        task_queue_t task_queue;

        int closed; // 线程池退出标记
        int started;    // 当前运行的线程数
        int thrd_count; // 线程的数量
        int queue_size; // 队列长度
};
#endif