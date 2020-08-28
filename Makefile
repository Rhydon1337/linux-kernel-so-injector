MODULE_NAME = kernel_injector

SRCS = ioctl.c main.c device_handlers.c

OBJS =  $(SRCS:.c=.o)

obj-m += $(MODULE_MAME).o
$(MODULE_MAME)-y = $(OBJS)

KERNELDIR ?= ~/workspace/buildroot-2020.02.4/output/build/linux-4.19.91
PWD       := $(shell pwd)
 
all: debug
 
release:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

debug:
	CFLAGS=-g
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions debug
