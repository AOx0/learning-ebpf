echo "./mkfc.sh <namefile> "
  
# echo "'$0'  '$@' '$<'" 

if [[ $@ == "" ]]; then
   echo " No se especifico archivo "
   echo "Correr como: mkfc.sh <namefile>" 
   echo "NO agregar la extension del archivo"
   echo "Generará el ejecutable en el directorio .\ejecutables\<namefile>.o"
   exit 1
elif ! [[ -f ./$1.c ]]; then
     echo "Unable to find the file '$1'.c in ./"
else 
     echo /usr/include/y$(uname -m)-linux-gnu
     exit 0
     :compilar      
        sudo clang -target bpf \
           -g \
           -I/usr/include/y$(uname -m)-linux-gnu \
           -O2 -c ./$1.c  -o ./ejecutables/$1.o
        ls -la ./ejecutables/$1.o
     inspectObj:
        echo " Inspecting an eBPF Object File ==>"
        file ./ejecutables/$1.o
        echo " eBPF instructions ==>"
        llvm-objdump -S ./ejecutables/$1.o
     loadkernel:
        echo "Loading the Program into the Kernel ==>"
        #sudo bpftool prog load ./ejecutables/$1.o /sys/fs/bpf/$1 
        sudo ls -la /sys/fs/bpf/$1
     ispectLoad:
        echo " Inspecting the Loaded Program  ==>"
        sudo bpftool prog list | grep -i $1 -4 
        # sudo bpftool prog list | grep -i "gpl" -4         
     showbycode:
        echo " The Translated Bytecode   ==>" 
        sudo bpftool prog dump xlated name $1 
     showenasam:
        echo "  The JIT-Compiled Machine Code ==>"   
        sudo bpftool prog dump jited name $1
     addevent:
        echo " Attaching to an Event  =>"  
        # sudo bpftool net attach xdp id 540 dev eth0 
     eBPFinnet:
        echo " View all the network-attached eBPF programs==>"
        sudo bpftool net list       
     exit 0
fi 
#--target=<value>     Generate code for the given target
# -I-                 Restrict all prior -I flags to double-quoted
#                     inclusion and remove current directory from
#                     include path
# -g                  Generate source-level debug information
# -o <file>           Write output to <file>
# -c                  Only run preprocess, compile, and assemble steps
 
