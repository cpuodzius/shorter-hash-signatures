#!/usr/bin/python -tt

import sys
import os

class Handler:

	def __init__(self, inputfile, outputfile):
		self.inputfile = inputfile
		self.outputfile = outputfile

	def run(self, res, idleVolt, tol, tolT):
		try:
			fin = open(self.inputfile)
			fout = open(self.outputfile, "w")
			idleVolt = idleVolt / 1000
			tol = tol / 1000
			tolT = tolT / 1000
			tBegin = 0.00
			tLast = 0.00
			charge = 0.0
			pico = False
			print res, idleVolt, tol, tolT
			for line in fin:
				time, value = line.replace(",", ".").split()
				if time == "NaN" or value == "NaN":
					continue
				time = float(time)
				value = float(value)
				if tol + idleVolt < value:
					if pico == False:
						pico = True
						charge = 0.0
						tBegin = time
					charge += (time - tLast) * value / res
				else:
					if pico == True:
						if time - tBegin > tolT:
							print "Length: " + str(1000*(time - tBegin)) + "ms Charge: " + str(charge) + "mC"
							fout.write("Length: " + str(1000*(time - tBegin)) + "ms Charge: " + str(charge) + "mC")
						pico = False
				tLast = time
			fin.close()
			fout.close()
			return True
		except ValueError as e:
			print(e)
			return False

if __name__ == '__main__':
	main()
