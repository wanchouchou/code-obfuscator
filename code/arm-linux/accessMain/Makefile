ifeq ($(TARGET),1)
ARMADEUS_ROOT := /usr/local/armadeus/armadeus-3.3/buildroot
CROSS_COMPILE := $(ARMADEUS_ROOT)/build_armv5te/staging_dir/usr/bin/arm-linux-
KERNELDIR := $(ARMADEUS_ROOT)/project_build_armv5te/apf27/linux-2.6.29.6
else
KERNELDIR := /lib/modules/$(shell uname -r)/build
CROSS_COMPILE := 
endif

CC:=$(CROSS_COMPILE)gcc
CFLAGS:=-c -Wall
EXEC=accessMain

all:	
	$(CC) $(EXEC).c -o $(EXEC)

clean:	
	rm -rf $(EXEC).o $(EXEC).d $(EXEC)
