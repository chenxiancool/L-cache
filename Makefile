obj-m := l_cache.o
l_cache-objs := cache.o sys.o job.o block.o hash.o

KERNELBUILD := /lib/modules/`uname -r`/build

default :
	make -C $(KERNELBUILD) M=$(shell pwd) modules

clean :
	rm -rf *.o *.mod.c *.order *.symvers .*.cmd .tmp*
