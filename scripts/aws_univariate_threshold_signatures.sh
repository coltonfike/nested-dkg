#!/bin/bash

N=$1
T=$2

addrs=(ubuntu@13.59.162.225 ubuntu@18.224.190.229 ubuntu@18.218.212.190 ubuntu@3.14.82.114 ubuntu@18.220.38.215 ubuntu@18.222.153.52 ubuntu@3.18.108.162 ubuntu@3.19.213.83 ubuntu@13.58.250.229 ubuntu@3.129.253.1)

for ((i=0; i<=$N; i++))
do
    addr=${addrs[$((i%10))]}
    ssh $addr "cd nested-dkg; ./target/release/main univariate-threshold-signature -i $i -n $N -t $T -a &" &
done
