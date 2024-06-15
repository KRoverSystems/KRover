#include<stdio.h>
#include<signal.h>
#include<unistd.h>

// void sig_handler(int signo, siginfo_t *info, void* ucontext)
void sig_handler(int signo)
{
    // unsigned long rdi;
    // asm volatile ("movq %%rdi, %0; \n\t"
    //         :"=m"(rdi)::);
    // printf ("rdi: %lx\n", rdi);
    // printf ("address of signo: %p, %d\n", &signo, signo);
    // printf ("address of siginfo: %p\n", info);
    // printf ("address of ucontext: %p\n", ucontext);
    // if (signo == SIGINT)
    printf("received SIGINT\n");
    return;
        // printf ("current stack: %lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n%lx\n");
        // unsigned long rsp;
        // unsigned long* stack_ptr;
        // asm volatile("movq %%rsp, %0; \n\t"
        //        :"=m"(rsp)::); 
        // stack_ptr = (unsigned long*) rsp;

        // int i = 0;
        // for (i = 0; i < 100; i ++)
        // {
        //     printf ("address: %p, content: %lx\n", stack_ptr, *stack_ptr);
        //     stack_ptr ++;
        // }

}

// void (*sig_handler) (int);
int main(void)
{
    printf ("pid: %d\n", getpid());
    struct sigaction *act;
    act = malloc (sizeof(struct sigaction));
    printf ("sizeof sigaction: %lx\n", sizeof(struct sigaction));
    act->sa_handler = &sig_handler;
    act->sa_flags = 0;
    printf ("pid: %d\n", getpid());
    printf ("address of act: %p\n", act);
    printf ("addr of sa_handler: %p\n", act->sa_handler);
    printf ("addr of sa_restorer: %p\n", act->sa_restorer);
    printf ("addr of sa_handler: %p\n", &(act->sa_handler));
    printf ("addr of sa_restorer: %p\n", &(act->sa_restorer));
    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\ncan't catch SIGINT\n");
    // A long long wait so that we can easily issue a signal to this process
    // while(1) 
    //     sleep(1);
    sleep (10000);
    return 0;
}

