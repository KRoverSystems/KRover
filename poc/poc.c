/*POC target program to be executed on target VM*/

#include <stdio.h>
#include <unistd.h>

void export_target_thread_to_onsite(){

    /*this hypercall will be intercepted by oasis-kernel(KVM),
    and the target state information will be used to construct the onsite envoronment*/
    asm volatile (
            "movq $0xabababababababab, %%rax; \n\t"
            "vmcall; \n\t"
            :::"%rax");

    /*We add a small delay, allowing the user to exctute the oasis-launcher,
    after the above hypercall*/
    sleep(0x5);

    /*This is to issue an onsite analysis request, The current thread will be
    captured by oasis-kernel(KVM) and dispatched to be executed in onsite env.*/
    asm volatile(
         "movq $0xcdcdcdcd, %%rax; \n\t"
         "vmcall; \n\t"
         :::"%rax", "%rdi");
}

int getpriority_asm(){
    
	int ret;

    asm volatile(
        "movq $140, %%rax; \n\t"
        "movq $0, %%rdi; \n\t"
        "movq $0, %%rsi; \n\t"
        "syscall; \n\t"
        "movq %%rax, %0; \n\t"
        :"=m"(ret)::"%rax","%rdi","%rsi");
	return ret;
}

int main (void)
{
    int ret;

    export_target_thread_to_onsite(); /*The target thread will be exported to onsite environment when %RIP is within this function*/
    ret = getpriority_asm(); /*issue a syscall*/

    /*printf ("ret of getpriority: %d \n", ret);*/
    
    return 1;
}