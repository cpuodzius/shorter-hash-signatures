COMPONENT=HashSigAppC

CFLAGS += -I include -I src -I resources
CFLAGS += -DPLATFORM_TELOSB

#
#OPTFLAGS += -O3
#OPTFLAGS += -O1
#OPTFLAGS += -O2 
#OPTFLAGS += -O0 # Too much ROM, bad flag

#CFLAGS += -DREAD_ENERGY

CFLAGS += -DNEW_PRINTF_SEMANTICS
CFLAGS += -I $(TOSDIR)/lib/printf
CFLAGS += -L lib
LDFLAGS += -lhashsigs
#-DPRINTF_BUFFER_SIZE=100

include $(MAKERULES)

