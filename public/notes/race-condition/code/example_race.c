#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

int products = 0;

void *producer(void *arg)
{
    while (products < 100)
    {
        products++;
        printf("+------------------+\n");
        printf("|Produced a product|\tTotal products: %d\n", products);
    }
    return NULL;
}

void *consumer(void *arg)
{
    while (products > 0)
    {
        products--;
        printf("+------------------+\n");
        printf("|Consumed a product|\tTotal products: %d\n", products);
    }
    return NULL;
}

int main()
{
    pthread_t prod_thread, cons_thread;

    pthread_create(&prod_thread, NULL, producer, NULL);
    pthread_create(&cons_thread, NULL, consumer, NULL);

    pthread_join(prod_thread, NULL);
    pthread_join(cons_thread, NULL);

    return 0;
}
