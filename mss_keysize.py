#!/usr/bin/python
# -*- coding: utf-8 -*-

import math

def CalcL(n, w):
	l1 = math.ceil(2 * n / math.log(w, 2))
	#print "l1 = ", l1
	l2 = math.floor(math.log(2, l1 * (w - 1)) / math.log(w, 2)) + 1
	#print "l2 = ",l2
	L = l1 + l2
	#print "L = ", L
	return L

def CalcLl(n, w):
	l1 = math.ceil(n / math.log(w, 2))
	#print "l1' = ", l1
	l2 = math.floor(math.log(2, l1 * (w - 1)) / math.log(w, 2)) + 1
	#print "l2' = ",l2
	L = l1 + l2
	#print "L' = ", L
	return L

def MerkleSigLengthL(n,H,w):
	AuthLen = (H * n) / 8
	Sig_WOTS_Len = (CalcL(n, w) * n) / 8
	return int(AuthLen + Sig_WOTS_Len)

def MerkleSigLengthLl(n,H,w):
	AuthLen = (H * n) / 8
	Sig_WOTS_Len = (CalcLl(n, w) * n) / 8
	return int(AuthLen + Sig_WOTS_Len)

def main(argv=None):
	SEC_LVL = 128
	for W in [2, 4, 8]:
		for H in range(4, 10):
			print "SEC LVL = ", SEC_LVL, "W = ", W, "H = ", H
			print "Merkle Sig Length:", MerkleSigLengthL(SEC_LVL,H,W)
			print "Merkle Sig Length:", MerkleSigLengthLl(SEC_LVL,H,W), " - Novo esquema"
			print "Rate (MSS/ECC):", MerkleSigLengthLl(SEC_LVL,H,W) / (2 * SEC_LVL)


if __name__ =='__main__':main()
