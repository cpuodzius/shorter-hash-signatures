import serial
from sys import exit

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=2, xonxoff=False, rtscts=False, dsrdtr=False)

ser.flushInput()
ser.flushOutput()

while 1:
  data_raw = ser.readline()
  print(data_raw)
  if "DONE" in data_raw:
	  exit(0);
  
