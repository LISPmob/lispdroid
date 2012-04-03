EXTRA_CFLAGS += -Wno-strict-prototypes

obj-m += lisp.o 

lisp-objs += ./lib/patricia/patricia.o lisp_mod.o tables.o lisp_input.o lisp_ipc.o lisp_output.o lisp_slab.o

INCLUDE_DIR += $(KERNEL_DIR)/include
all:
	make -C $(KERNEL_DIR) ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE) clean
	@rm -f *.o *.a *~ *.~* core .depend dep 
