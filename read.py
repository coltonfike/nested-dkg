import numpy as np
import csv

for i in [10, 20, 30, 40, 50]:
    with open('res0/prf_signatures_aggregator_' + str(i)) as f:
        arr = np.loadtxt(f, delimiter=',')
    avg = np.mean(arr, axis=0)
    np.insert(avg, 0, i)
    with open('prf_signatures_aggregator_' + str(i), 'a') as f:
        writer = csv.writer(f)
        writer.writerow(avg)
