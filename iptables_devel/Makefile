obj-m += xt_MARKDNAT.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install_MARKDNAT:
	cp xt_MARKDNAT.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter
	depmod

uninstall_MARKDNAT:
	rmmod xt_MARKDNAT
	rm /lib/modules/$(shell uname -r)/kernel/net/netfilter/xt_MARKDNAT.ko
	depmod

install:  install_MARKDNAT

uninstall:  uninstall_MARKDNAT
