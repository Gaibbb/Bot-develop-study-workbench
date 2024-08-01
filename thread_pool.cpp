#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "thread_pool.h"

// 任务结点
typedef struct task_s {
    handler_pt func;    // 任务的执行函数
    void * arg;         // 任务的上下文
} task_t;

// 任务队列
typedef struct task_queue_s {
    uint32_t head;  // 队列的头指针
    uint32_t tail;  // 队列的尾指针
    uint32_t count; // 队列中的任务结点数量
    task_t *queue;  // 队列数组
} task_queue_t;

// 线程池
struct thread_pool_t {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t *threads;
    task_queue_t task_queue;

    int closed;     // 退出标记
    int started;    // 当前运行的线程数

    int thrd_count; // 线程的数量
    int queue_size; // 队列的长度，设置数组，一次性分配内存，不使用内存池
};

static void * thread_worker(void *thrd_pool);
static void thread_pool_free(thread_pool_t *pool);

// 创建线程池
thread_pool_t* thread_pool_create(int thrd_count, int queue_size) {
    thread_pool_t *pool;

    if (thrd_count <= 0 || queue_size <= 0) {
        return NULL;
    }

    // 线程池分配内存
    pool = (thread_pool_t*) malloc(sizeof(*pool));
    if (pool == NULL) {
        return NULL;
    }

    // 初始化线程池
    // 为什么不直接用thrd_count赋值？而是选择从0开始计数
    // 每当成功创建1个线程，计数+1，避免线程创建失败造成计数混乱
    pool->thrd_count = 0;
    pool->queue_size = queue_size;
    pool->task_queue.head = 0;
    pool->task_queue.tail = 0;
    pool->task_queue.count = 0;
    pool->started = pool->closed = 0; 

    // 创建任务队列
    pool->task_queue.queue = (task_t*)malloc(sizeof(task_t)*queue_size);
    if (pool->task_queue.queue == NULL) {
        // TODO: free pool
        return NULL;
    }

    // 创建线程
    pool->threads = (pthread_t*) malloc(sizeof(pthread_t) * thrd_count);
    if (pool->threads == NULL) {
        // TODO: free pool
        return NULL;
    }
    // 依次创建好线程
    int i = 0;
    for (; i < thrd_count; ++i) {
        if (pthread_create(&(pool->threads[i]), NULL, thread_worker, (void*)pool) != 0) {
            // TODO: free pool
            return NULL;
        }
        pool->thrd_count++;
        pool->started++;
    }
    return pool;
}

// 生产者抛出任务
int thread_pool_post(thread_pool_t *pool, handler_pt func, void *arg) {
    if (pool == NULL || func == NULL) {
        return -1;
    }

    task_queue_t *task_queue = &(pool->task_queue);

    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        return -2;
    }
    
    // 判断线程池是否关闭
    if (pool->closed) {
        pthread_mutex_unlock(&(pool->mutex));
        return -3;
    }

    // 判断任务队列是否已满
    if (task_queue->count == pool->queue_size) {
        pthread_mutex_unlock(&(pool->mutex));
        return -4;
    }

    // 1、主线程（生产者线程）构造任务，放入任务队列
    // 队列的操作，使用自旋锁
    task_queue->queue[task_queue->tail].func = func;
    task_queue->queue[task_queue->tail].arg = arg;
    task_queue->tail = (task_queue->tail + 1) % pool->queue_size;
    task_queue->count++;

    // 2、唤醒线程池中的线程
    if (pthread_cond_signal(&(pool->condition)) != 0) {
        pthread_mutex_unlock(&(pool->mutex));
        return -5;
    }
    pthread_mutex_unlock(&(pool->mutex));
    return 0;
}

// 释放线程池空间
static void thread_pool_free(thread_pool_t *pool) {
    if (pool == NULL || pool->started > 0) {
        return;
    }

    if (pool->threads) {
        free(pool->threads);
        pool->threads = NULL;

        pthread_mutex_lock(&(pool->mutex));
        pthread_mutex_destroy(&pool->mutex);
        pthread_cond_destroy(&pool->condition);
    }

    if (pool->task_queue.queue) {
        free(pool->task_queue.queue);
        pool->task_queue.queue = NULL;
    }
    free(pool);
}

// 等待所有线程的退出
int wait_all_done(thread_pool_t *pool) {
    int i, ret = 0;
    for (i = 0; i < pool->thrd_count; i++) {
        if (pthread_join(pool->threads[i], NULL) != 0) {
            ret = 1;
        }
    }
    return ret;
}

// 3、销毁线程池
int thread_pool_destroy(thread_pool_t *pool) {
    if (pool == NULL) {
        return -1;
    }

    // 阻止产生新的任务
    if (pthread_mutex_lock(&(pool->mutex)) != 0) {
        return -2;
    }

    // 判断是否已经退出，防止重复释放空间
    if (pool->closed) {
        thread_pool_free(pool);
        return -3;
    }

    // 标记线程池退出
    pool->closed = 1;

    // 让所有阻塞在cond上的线程唤醒，并释放互斥锁
    if (pthread_cond_broadcast(&(pool->condition)) != 0 || 
            pthread_mutex_unlock(&(pool->mutex)) != 0) {
        thread_pool_free(pool);
        return -4;
    }

    // 等待所有线程退出
    wait_all_done(pool);

    thread_pool_free(pool);
    return 0;
}

// 线程池中的线程（消费者）该干的事儿
static void* thread_worker(void *thrd_pool) {
    thread_pool_t *pool = (thread_pool_t*)thrd_pool;
    task_queue_t *que;
    task_t task;

    for (;;) {
        pthread_mutex_lock(&(pool->mutex));
        que = &pool->task_queue;
        
        // 虚假唤醒问题
        // while 判断：没有任务而且线程池没有关闭
        while (que->count == 0 && pool->closed == 0) {
            // pthread_mutex_unlock(&(pool->mutex))
            // 阻塞在 condition
            // ===================================
            // 解除阻塞
            // pthread_mutex_lock(&(pool->mutex));
            pthread_cond_wait(&(pool->condition), &(pool->mutex));
        }
        // 线程池关闭
        if (pool->closed == 1) break;
        
        // 获取任务
        task = que->queue[que->head];
        que->head = (que->head + 1) % pool->queue_size;
        que->count--;
        pthread_mutex_unlock(&(pool->mutex));
        
        // 执行任务
        (*(task.func))(task.arg);
    }

    // 销毁该线程
    pool->started--;
    pthread_mutex_unlock(&(pool->mutex));
    pthread_exit(NULL);
    return NULL;
}