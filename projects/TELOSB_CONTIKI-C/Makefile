CONTIKI = /home/sembei/contiki-2.7
ifndef TARGET
TARGET=sky
endif

CFLAGS += -I include -I src -I resources
CFLAGS += -DPLATFORM_TELOSB

#To change the optimization flag, go to $CONTIKI_HOME/cpu/MSP430/Makefile.msp430 at line 148
# -O3 seems to be the best speed result

PARAMS?=

all: hashsig-app -DWATCHDOG_CONF_TIMEOUT -1 $(PARAMS)

include $(CONTIKI)/Makefile.include

#OPTFLAGS += -O3
