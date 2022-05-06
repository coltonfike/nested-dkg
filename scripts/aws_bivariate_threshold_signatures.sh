#!/bin/bash

N=$1
M=$2
T=$3
P=$4
for ((i=0; i<$N; i++))
do
    for ((j=0; j<$M; j++))
    do
        ./target/release/main bivariate-threshold-signature -i "$i" -j "$j" -n "$N" -m "$M" -t "$T" -p "$P" -a &
    done
done
