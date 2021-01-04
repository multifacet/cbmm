#!/usr/bin/env python3

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import sys

matplotlib.use("Agg")

FILE = sys.argv[1]

data = { }

with open(FILE) as f:
    for line in f.readlines():
        print(line)



plt.plot([1, 2, 3, 4])
plt.ylabel('some numbers')

plt.savefig("/tmp/test.png")


