LINUX := $(CURDIR)/../linux

obj-m += load.o

all:
	make -C $(LINUX) M=$(CURDIR) modules

clean:
	make -C $(LINUX) M=$(CURDIR) clean