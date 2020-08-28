#!/bin/bash
trap "" 0 1 2 3 9 13 15

# User configuration
BUILDROOT_IMAGES_PATH="/home/rhydon/workspace/buildroot-2020.02.4/output/images"
VM_USERNAME="root"
VM_PASSWORD="123456"
VM_SNAPSHOT="first_snapshot"
KERNEL_MODULE_NAME="main"

CWD=`pwd`
REMOTE_DIR="/root/"`basename $CWD`
SSH_PORT=5555

cd $BUILDROOT_IMAGES_PATH

echo "Starting the vm"
setsid qemu-system-x86_64 -enable-kvm -cpu host -s -kernel bzImage -m 2048 -hda rootfs.qcow2 -append "root=/dev/sda rw nokaslr" -net nic,model=virtio -net user,hostfwd=tcp::$SSH_PORT-:22 -loadvm $VM_SNAPSHOT &

# Busy loop for waiting for the vm to startup and setup ssh
until sshpass -p "$VM_PASSWORD" ssh -p $SSH_PORT -q $VM_USERNAME@localhost exit
do 
echo "Waiting for vm setup"
done

echo "Moving the driver to the vm"
sshpass -p "$VM_PASSWORD" scp -P $SSH_PORT -r $CWD $VM_USERNAME@localhost:$REMOTE_DIR

sshpass -p "$VM_PASSWORD" ssh -p $SSH_PORT $VM_USERNAME@localhost "insmod $REMOTE_DIR/$KERNEL_MODULE_NAME.ko"

rm -f ~/.gdbinit
text_address=`sshpass -p "$VM_PASSWORD" ssh -p $SSH_PORT $VM_USERNAME@localhost cat /sys/module/$KERNEL_MODULE_NAME/sections/.text`
#data_address=`sshpass -p "$VM_PASSWORD" ssh -p $SSH_PORT $VM_USERNAME@localhost cat /sys/module/$KERNEL_MODULE_NAME/sections/.data`
#bss_address=`sshpass -p "$VM_PASSWORD" ssh -p $SSH_PORT $VM_USERNAME@localhost cat /sys/module/$KERNEL_MODULE_NAME/sections/.bss`
#echo "add-symbol-file $KERNEL_MODULE_NAME.ko $text_address -s .data $data_address -s .bss $bss_address" > ~/.gdbinit

echo "add-symbol-file $KERNEL_MODULE_NAME.ko $text_address" > ~/.gdbinit
echo "file ./$KERNEL_MODULE_NAME.ko" >> ~/.gdbinit