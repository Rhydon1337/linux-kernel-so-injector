obj-m	:= kernel_injector.o
kernel_injector-y := main.o device_handlers.o ioctl.o so_injector.o file.o utils.o elf.o so_shellcode_loader.o
 
KERNELDIR ?= ~/workspace/buildroot-2020.02.4/output/build/linux-4.19.91
PWD       := $(shell pwd)
 
all: debug
 
release:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

ccflags-y := -g -Og -O0
debug:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions debug
