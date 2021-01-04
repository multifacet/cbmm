#!/usr/bin/env python3

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import sys
import re

FILE = sys.argv[1]

REGIONRE = "^.*kbadgerd: \[(.*), (.*)\) .*$"
DATARE = "^.*kbadgerd:\s+((4KB)|(2MB)) ((load)|(store)) misses: (.*)$"

def get_data(fname):
    began = False

    data = []

    start = None
    end = None
    misses_ld_4kb = 0
    misses_st_4kb = 0
    misses_ld_2mb = 0
    misses_st_2mb = 0

    with open(fname) as f:
        for line in f.readlines():
            if "Results of inspection" in line:
                began = True
                continue

            if not began:
                continue

            match = re.search(REGIONRE, line)
            if match is not None:
                if start is not None:
                    data.append((start, end, misses_ld_4kb, misses_st_4kb, misses_ld_2mb, misses_st_2mb))
                    print([hex(x) for x in data[-1]])

                start = int(match.group(1), 16)
                end = int(match.group(2), 16)

                misses_ld_4kb = 0
                misses_st_4kb = 0
                misses_ld_2mb = 0
                misses_st_2mb = 0

                continue

            if "No misses" in line:
                continue

            match = re.search(DATARE, line)
            if match is not None:
                size = match.group(1)
                ldst = match.group(4)
                count = int(match.group(7))

                if (size, ldst) == ("4KB", "load"):
                    misses_ld_4kb = count
                elif (size, ldst) == ("4KB", "store"):
                    misses_st_4kb = count
                elif (size, ldst) == ("2MB", "load"):
                    misses_ld_2mb = count
                elif (size, ldst) == ("2MB", "store"):
                    misses_st_2mb = count
                else:
                    raise Exception("Should never happen.")

                continue

            print(line)

    return data

# raw data in the form of a bunch of tuples:
#   (start, end, counts...)
#
# The ranges may be overlapping though, so we need to handle that case.
data = get_data(FILE)

for (start, end, ld4k, st4k, ld2m, st2m) in data:
    rect = patches.Rectangle((start, 0), end-start, ld4k, facecolor="blue")
    plt.gca().add_patch(rect)
    pass

#plt.plot([1, 2, 3, 4])
#plt.ylabel('some numbers')
#
plt.savefig("/tmp/test.png")


