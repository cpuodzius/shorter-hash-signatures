import serial
import os
from sys import exit

for arg in sys.argv:
    if arg = 'make'
		os.system("make clean")
		os.system("make micaz install mib510,/dev/ttyUSB0")
	elif arg = 'run'
		ser = serial.Serial('/dev/ttyUSB0', 57600, timeout=2, xonxoff=False, rtscts=False, dsrdtr=False)

		ser.flushInput()
		ser.flushOutput()

		start_reception = 0
		saida = ""
		while 1:
		  data_raw = ser.readline()
		  if "Starting" in data_raw:
			  start_reception = 1
		  elif "DONE" in data_raw:
			  print(saida)
			  exit(0);
		  elif start_reception == 1:
			  saida += data_raw
			
  
  
