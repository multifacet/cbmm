#!/usr/bin/env python3

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib.ticker as ticker
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

    return data

# raw data in the form of a bunch of tuples:
#   (start, end, counts...)
#
# The ranges may be overlapping though, so we need to handle that case.
data = sorted(get_data(FILE), key=lambda x: x[0])

for x in data:
    print([hex(v) for v in x])

fig, axs = plt.subplots(4, sharex=True, figsize=(15, 15))

minx = float("inf")
maxx = 0

# The plot is very sparse. Keep track of the gaps and don't draw them.
#   (start, length)
gaps = []

for (start, end, _ld4k, _st4k, _ld2m, _st2m) in data:
    if start > maxx:
        gap = (maxx, start - maxx)
        gaps.append(gap)
        print("gap: %x %x" % (maxx, start))

    minx = min(minx, start)
    maxx = max(maxx, end)

def get_group(x, i):
    return x[i + 2]

def plot_group(i):
    ax = axs[i]

    maxy = max(map(lambda x: get_group(x, i), data))

    gap_idx = 0 # index of the first gap _greater than_ start
    gap_offset = 0 # sum of all gap lengths prior to start
    for x in data:
        start = x[0]
        end = x[1]
        count = get_group(x, i)
        if gap_idx < len(gaps) and gaps[gap_idx][0] < start:
            gap_offset += gaps[gap_idx][1]
            gap_idx += 1

        print("start=%x new=%x" % (start, start-gap_offset))

        rect = patches.Rectangle((start - gap_offset, 0), end-start, count,
                fc=(0,0,1, 0.1), ec="r", linewidth=0.25)
        ax.add_patch(rect)

    label = ""
    if i == 0:
        label = "4KB load misses"
    elif i == 1:
        label = "4KB store misses"
    elif i == 2:
        label = "2MB load misses"
    else:
        label = "2MB store misses"

    ax.set_ylabel(label)
    ax.set_ylim((1, maxy))
    ax.set_yscale("symlog")

    ax.set_xlim((minx, maxx - gap_offset))

    ax.grid(True)

plot_group(0)
plot_group(1)
plot_group(2)
plot_group(3)

def to_hex(x, pos):
    x = int(x)

    offset = 0

    prevs, prevl = None, None
    for ((s, l), (nexts, nextl)) in zip(gaps[:-1], gaps[1:]):
        offset += l
        if x < nexts - offset:
            break

        #print("x=%x s=%x l=%x o=%x" % (x, s, l, offset))
    #print("%x\n" % (x + offset))
    return '%x' % (x + offset)
axs[3].get_xaxis().set_major_formatter(ticker.FuncFormatter(to_hex))
axs[3].get_xaxis().set_major_locator(ticker.MultipleLocator(1<<20))
plt.setp(axs[3].xaxis.get_majorticklabels(), rotation=60)
axs[3].set_xlabel("Address")

plt.tight_layout()

plt.savefig("/tmp/test.pdf")
