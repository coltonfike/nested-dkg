#!/bin/bash

N=$1
T=$2

addrs=(ubuntu@18.191.230.110 ubuntu@18.221.101.113 ubuntu@3.17.55.76 ubuntu@18.189.11.155 ubuntu@18.191.251.152 ubuntu@3.143.170.213 ubuntu@18.119.0.114 ubuntu@3.143.110.61 ubuntu@18.220.13.123 ubuntu@3.143.211.197)

for ((i=0; i<=$N; i++))
do
    addr=${addrs[$((i%10))]}
    ssh $addr "cd nested-dkg; ./target/release/main univariate-threshold-signature -i $i -n $N -t $T -a &" &
done
