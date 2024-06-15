virsh start ubuntu18.04
# sleep 5
# ssh beverly@192.168.122.46
# ssh -X -f beverly@192.168.122.46 Documents/nme-test/nme_target 
# expect "assword:"
# send ".\r"
# interact
# until "ssh -X -f beverly@192.168.122.46 Documents/nme-test/nme_target &"
until ssh -X beverly@192.168.122.46 "sh -c 'cd Documents/nme-test; nohup ./nme_target > /dev/null 2>&1 &'"
do 
    echo "guest VM not ready, ssh failed"
done
# sleep 2
echo "start klee & onsite"
~/Documents/klee-pspa/klee-exploit-build/bin/klee ~/Documents/klee-pspa/klee-exploit/example/Pointer_SE_sample/tt.bc
echo "about to shutdown guest VM"
virsh shutdown ubuntu18.04
# ssh -X beverly@192.168.122.46 sh -c cd Documents/nme-test; nohup ./nme_target > /dev/null 2>&1 &
