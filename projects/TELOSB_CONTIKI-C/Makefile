CONTIKI = /home/sembei/contiki-2.7
ifndef TARGET
TARGET=sky
endif

CFLAGS += -I include -I src -I resources
CFLAGS += -DPLATFORM_TELOSB
#CFLAGS += -O0

all: hashsig-app -DWATCHDOG_CONF_TIMEOUT -1

include $(CONTIKI)/Makefile.include


