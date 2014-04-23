#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import random

def get_input(basepath):
	benchmarks = []
	benchmark = None
	for line in open(os.path.join(basepath, "bench_input.txt")).readlines():
		if "PLATFORM" in line:
			platform = line[len("PLATFORM: "):].strip()
			if benchmark != None:
				benchmarks.append(benchmark)
			benchmark = {"platform": platform, "params": []}
			benchmarks.append(benchmark)
		else:
			line += ","	# Formatando para facilitar a extração
			param = {"H": None, "K": None, "W": None, "SEC_LVL": None}
			param["H"] = line[line.find("H") + len("H = "): line.find(",", line.find("H"))].strip()
			param["K"] = line[line.find("K") + len("K = "): line.find(",", line.find("K"))].strip()
			param["W"] = line[line.find("W") + len("W = "): line.find(",", line.find("W"))].strip()
			param["SEC_LVL"] = line[line.find("SEC_LVL") + len("SEC_LVL = "): line.find(",", line.find("SEC_LVL"))].strip()
			benchmarks[-1]["params"].append(param)
	return benchmarks

def edit_winternitz_h(includepath, W, SEC_LVL):
	path = os.path.join(includepath, 'winternitz.h')
	f = open(path, 'r+')
	includefile = ""
	for line in f.readlines():
		if "#define WINTERNITZ_SEC_LVL\t" in line:
			line = "#define WINTERNITZ_SEC_LVL\t" + str(SEC_LVL) + "\n"
		elif "#define WINTERNITZ_W\t" in line:
			line = "#define WINTERNITZ_W\t\t" + str(W) + "\n"
		includefile += line
	f.seek(0)
	f.write(includefile)
	f.truncate()
	f.close()

def edit_merkletree_h(includepath, H, K):
	path = os.path.join(includepath, 'merkletree.h')
	f = open(path, 'r+')
	includefile = ""
	for line in f.readlines():
		if "#define MERKLE_TREE_HEIGHT\t" in line:
			line = "#define MERKLE_TREE_HEIGHT\t\t\t" + str(H) + "\n"
		elif "#define MERKLE_TREE_K\t" in line:
			line = "#define MERKLE_TREE_K\t\t\t\t" + str(K) + "\n"
		includefile += line
	f.seek(0)
	f.write(includefile)
	f.truncate()
	f.close()

def main(argv=None):
	benchbasepath = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'benchmark')
	benchmarks = get_input(os.path.abspath(os.path.dirname(__file__)))
	for benchmark in benchmarks:
		platform = benchmark["platform"]
		basepath = os.path.join(os.path.abspath(os.path.dirname(__file__)), platform)
		includepath = os.path.join(basepath, 'include')
		binpath = os.path.join(basepath, 'bin')
		for param in benchmark["params"]:
			edit_merkletree_h(includepath, param["H"], param["K"])
			edit_winternitz_h(includepath, param["W"], param["SEC_LVL"])
			os.chdir(basepath)
			os.system('make clean')
			os.system('make tests')
			fpath = os.path.join(benchbasepath, str(random.randint(50000, 1000000)))
			while(os.path.isfile(fpath)):
				fpath = os.path.join(benchbasepath, str(random.randint(50000, 1000000)))
			f = open(fpath, 'w+')
			subprocess.call([os.path.join(binpath, 'merkle_tree')], stdout=f)
			f.seek(0)
			for line in f.readlines():
				if "Parameters" in line:
					seclvl = line[line.find("SEC_LVL="):line.find(",", line.find("SEC_LVL"))]
					h = line[line.find("H="):line.find(",", line.find("H="))]
					k = line[line.find("K="):line.find(",", line.find("K="))]
				elif "RAM" in line:
					ram = "RAM=" + line[len("RAM total: "):-1]
				elif "elapsed time" in line:
					time = "time=" + line[line.find("elapsed time") + len("elapsed time: "):]
			print seclvl, h, k, ram, time
			f.close()

if __name__ =='__main__':main()
