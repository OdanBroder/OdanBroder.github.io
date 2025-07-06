#include <pthread.h>
#include <stdio.h>

int products = 0;                 
pthread_mutex_t lock;             

void *producer(void *arg)
{
    while (products < 100)
    {
        pthread_mutex_lock(&lock);  
        products++;                
        printf("+------------------+\n");
        printf("|Produced a product|\tTotal products: %d\n", products);
        pthread_mutex_unlock(&lock); 
    }
    return NULL;
}

void *consumer(void *arg)
{
    while (products > 0)
    {
        pthread_mutex_lock(&lock); 
        products--;                 
        printf("+------------------+\n");
        printf("|Consumed a product|\tTotal products: %d\n", products);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main()
{
    pthread_t producer_thread, consumer_thread;

    pthread_mutex_init(&lock, NULL);

    pthread_create(&producer_thread, NULL, producer, NULL);
    pthread_create(&consumer_thread, NULL, consumer, NULL);

    pthread_join(producer_thread, NULL);
    pthread_join(consumer_thread, NULL);

    pthread_mutex_destroy(&lock);

    return 0;
}