#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

int balance = 1000;
int depositAmount = 500;
int withdrawAmount = 300;

void *deposit(void *arg)
{
    int amount = *(int *)arg;
    int temp = balance;
    usleep(1);
    balance = temp + amount;
    printf("Deposit: +%d, New Balance: %d\n", amount, balance);
    return NULL;
}

void *withdraw(void *arg)
{
    int amount = *(int *)arg;
    if (balance >= amount)
    {
        int temp = balance;
        usleep(1);
        balance = temp - amount;
        printf("Withdraw: -%d, New Balance: %d\n", amount, balance);
    }
    else
    {
        printf("Withdraw: -%d, Insufficient funds! Current Balance: %d\n", amount, balance);
    }
    return NULL;
}

int main()
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, deposit, &depositAmount);
    pthread_create(&t2, NULL, withdraw, &withdrawAmount);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Final Balance: %d\n", balance);
    return 0;
}
