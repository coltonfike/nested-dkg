#!/bin/bash

N=$1
T=$2

./target/release/main univariate-share-file -n "$N" -t "$T"

for ((i=0; i<$N; i++))
do
    ./target/release/main univariate-threshold-signature -i "$i" -n "$N" -t "$T" &
done
