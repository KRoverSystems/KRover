#include<stdio.h>
// #include<signal.h>
// #include<unistd.h>
#define user_sigflag_address 0x7ff020804000
// struct sig_flag
// {
//     void* handler;
//     int flag;
// };
// struct sig_flag sig_array[64];

// // int sig_array[64];
// 
// int dummy_handler(int signo)
// {
//     // int sig_array[64];
//     int *p;
//     // p = (int*) 0x7ff020900000;
//     p = (int*) user_sigflag_address;
//     p[signo] += 1;
//     // sig_array[signo] += 1;
//     return 0;
// }

// int sig_array[64];

int main(int signo)
{
    // int sig_array[64];
    int *p;
    // p = (int*) 0x7ff020900000;
    p = (int*) user_sigflag_address;
    // p = &sig_array[0];
    p[signo] += 1;
    // sig_array[signo] += 1;
    return 0;
}
