#define NEW_PRINTF_SEMANTICS
#include "printf.h"


configuration HashSigAppC{
}
implementation {
  components MainC, HashSigC, LedsC;
  components new TimerMilliC();
  components PrintfC;
  components SerialStartC;

  HashSigC.Boot -> MainC;
  HashSigC.Timer -> TimerMilliC;
  HashSigC.Leds -> LedsC;

}

