#!/usr/bin/python
# -*- coding: utf-8 -*-

import math

def L(n, w):
	l1 = math.ceil(2 * n / w)
	#print "l1 = ", l1
	l2 = math.floor(math.log(l1 * (2**w - 1), 2) / w) + 1
	#print "l2 = ",l2
	L = l1 + l2
	#print "L = ", L
	return L

def L_Ours(n, w):
	l1 = math.ceil(n / w)
	#print "l1' = ", l1
	l2 = math.floor(math.log(l1 * (2**w - 1), 2) / w) + 1
	#print "l2' = ",l2
	L = l1 + l2
	#print "L' = ", L
	return L

def MerkleSigLength(n,H,w):
	AuthLen = (H * n) / 8
	Sig_WOTS_Len = (L(n, w) * n) / 8
	return int(AuthLen + Sig_WOTS_Len)

def MerkleSigLength_Ours(n,H,w):
	nonceLen = n / 8
	AuthLen = (H * n) / 8
	Sig_WOTS_Len = (L_Ours(n, w) * n) / 8
	return int(nonceLen + AuthLen + Sig_WOTS_Len)

def main(argv=None):
	SEC_LVL = 128
	for W in [2, 4, 8]:
		for H in range(8, 10):
			print "SEC LVL = ", SEC_LVL, "W = ", W, "H = ", H
			print "Merkle Sig Length:", MerkleSigLength(SEC_LVL,H,W)
			print "Merkle Sig Length:", MerkleSigLength_Ours(SEC_LVL,H,W), " - Ours"
			print "Rate (MSS/ECC):", MerkleSigLength_Ours(SEC_LVL,H,W) / (2 * SEC_LVL)


if __name__ =='__main__':main()
