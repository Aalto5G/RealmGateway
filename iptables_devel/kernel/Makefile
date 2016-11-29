obj-m += xt_MARKDNAT.o
obj-m += xt_DF.o
obj-m += xt_MARKCLASSIFY.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install_DF:
	cp xt_DF.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter
	depmod

uninstall_DF:
	rmmod xt_DF
	rm /lib/modules/$(shell uname -r)/kernel/net/netfilter/xt_DF.ko
	depmod

install_MARKCLASSIFY:
	cp xt_MARKCLASSIFY.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter
	depmod

uninstall_MARKCLASSIFY:
	rmmod xt_MARKCLASSIFY
	rm /lib/modules/$(shell uname -r)/kernel/net/netfilter/xt_MARKCLASSIFY.ko
	depmod

install_MARKDNAT:
	cp xt_MARKDNAT.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter
	depmod

uninstall_MARKDNAT:
	rmmod xt_MARKDNAT
	rm /lib/modules/$(shell uname -r)/kernel/net/netfilter/xt_MARKDNAT.ko
	depmod

install:  install_DF install_MARKCLASSIFY install_MARKDNAT

uninstall:  uninstall_DF uninstall_MARKCLASSIFY uninstall_MARKDNAT
