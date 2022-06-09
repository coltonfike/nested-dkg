import csv
import numpy as np

np.set_printoptions(suppress=True,
                    formatter={'float_kind': '{:f}'.format})

def convert(row):
    result = []
    for time in row:
        if time.endswith('ms'):
            result.append(float(time[:-2]))
        elif time.endswith('µs'):
            result.append(float(time[:-2]) / 1000.0)
        elif time.endswith('s'):
            result.append(float(time[:-1]) * 1000.0)
    return result

lines = []
with open('results/optimized_nidkg_dealer_11,11_5,8', 'r') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        lines.append(convert(row))

avgs = np.mean(lines, axis=0)
print(avgs)
