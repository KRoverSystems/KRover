#compile the KVM module and deploy it 
make -j`nproc` modules /<PATH-TO>/oasis/kernel/linux-hwe-5.3.18/arch/x86/kvm/
sudo cp arch/x86/kvm/{kvm.ko,kvm-intel.ko} /lib/modules/5.3.18+/kernel/arch/x86/kvm/
sync 
sudo rmmod kvm-intel && sudo rmmod kvm
sudo modprobe kvm && sudo modprobe kvm-intel
