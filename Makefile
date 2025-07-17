ifneq ($(KERNELRELEASE),)
   obj-m := cper_dump.o
else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
# KERNELDIR ?= /home/aadiraju/Desktop/src/linux-3.11.1/

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
