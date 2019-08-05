
KERNEL_DIR:=/lib/modules/$(shell uname -r)/build
obj-m := block_test.o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
#	rm -rf Module.markers modules.order Module.symvers
