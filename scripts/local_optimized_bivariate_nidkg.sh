#!/bin/bash

N=$1
M=$2
T=$3
P=$4
D=$5

./target/release/main bivariate-ni-dkg-key-pairs -n "$N" -m "$M" -o

for ((i=0; i<$D; i++))
do
    ./target/release/main bivariate-ni-dkg -i "$N" -j "$i" -n "$N" -m "$M" -d "$D" -t "$T" -p "$P" -l -o &
done

for ((i=0; i<$N; i++))
do
    for ((j=0; j<$M; j++))
    do
        ./target/release/main bivariate-ni-dkg -i "$i" -j "$j" -n "$N" -m "$M" -d "$D" -t "$T" -p "$P" -o &
    done
done
