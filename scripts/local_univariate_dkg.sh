#!/bin/bash

N=$1
T=$2
for ((i=0; i<$N; i++))
do
    ./target/debug/cli univariate-dkg -i "$i" -n "$N" -t "$T" &
done
