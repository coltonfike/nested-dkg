#!/bin/bash

N=$1
M=$2
T=$3
P=$4
for ((i=0; i<$N; i++))
do
    for ((j=0; j<$M; j++))
    do
        ./target/debug/cli bivariate-dkg -i "$i" -j "$j" -n "$N" -m "$M" -t "$T" -p "$P" &
    done
done
