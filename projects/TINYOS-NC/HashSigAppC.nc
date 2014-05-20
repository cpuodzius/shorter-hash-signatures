#ifndef READ_ENERGY 
  #define NEW_PRINTF_SEMANTICS
  #include "printf.h"
#endif

configuration HashSigAppC{
}
implementation {
  components MainC, HashSigC;
  components new TimerMilliC();

#ifndef READ_ENERGY  
  components PrintfC, LedsC;
  components SerialStartC;
  HashSigC.Leds -> LedsC;
#endif

  HashSigC.Boot -> MainC;
  HashSigC.Timer -> TimerMilliC;  

}

