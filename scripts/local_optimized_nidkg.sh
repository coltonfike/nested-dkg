#!/bin/bash

N=$1
D=$2
T=$3

./target/release/main ni-dkg-key-pairs -n "$N" -o

for ((i=0; i<$D; i++))
do
    ./target/release/main univariate-ni-dkg -i "$i" -n "$N" -d "$D" -t "$T" -l -o &
done

for ((i=0; i<$N; i++))
do
    ./target/release/main univariate-ni-dkg -i "$i" -n "$N" -d "$D" -t "$T" -o &
done
