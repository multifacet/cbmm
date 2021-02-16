#!/usr/bin/env python3

import sys
import csv

if len(sys.argv) == 1:
    print("./script <file>, where <file> is a CSV dump of the Averages sheet.")

FILE = sys.argv[1]

# { (start addr, end addr) : total TLB miss delta }
data = {}

def total_misses(row):
    return float(row["avg dtlb_load_misses.walk_active"]) \
         + float(row["avg dtlb_store_misses.walk_active"])

with open(FILE, 'r') as f:
    reader = csv.DictReader(f, delimiter=',')

    prev_end = 0
    prev_misses = None

    for row in reader:
        # handle the control run specially
        if row["Huge page"] == "none":
            prev_end = 0
            prev_misses = total_misses(row)
            continue

        if row["Huge page"] == "thp":
            continue

        # general case
        end = int(row["Huge page"], base=16)
        misses = total_misses(row)

        diff = prev_misses - misses
        
        if diff > 0:
            data[(prev_end, end)] = diff

        prev_end = end
        prev_misses = misses

        # TODO: convert to misses / page / LTU

datap = [hex(r[0])+" "+hex(r[1])+" "+str(int(count)) for r, count in data.items()]
print("mm_econ", ";".join(datap))
print()
datap = [hex(r[0])+","+hex(r[1])+","+str(int(count)) for r, count in data.items()]
print("runner", ";".join(datap))
