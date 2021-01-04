#!/usr/bin/env python3

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import sys
import re

matplotlib.use("Agg")

FILE = sys.argv[1]



def get_data(fname):
    began = False

    with open(fname) as f:
        for line in f.readlines():
            if line.contains("Result of inspection"):
                began = True
                continue

            print(line)

data = get_data(FILE)

plt.plot([1, 2, 3, 4])
plt.ylabel('some numbers')

plt.savefig("/tmp/test.png")


