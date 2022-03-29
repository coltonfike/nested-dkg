#!/bin/bash
ssh ubuntu@13.59.162.225 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 0 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 10 -n 15 -t 5 -a &" &
ssh ubuntu@18.224.190.229 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 1 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 11 -n 15 -t 5 -a &" &
ssh ubuntu@18.218.212.190 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 2 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 12 -n 15 -t 5 -a &" &
ssh ubuntu@3.14.82.114 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 3 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 13 -n 15 -t 5 -a &" &
ssh ubuntu@18.220.38.215 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 4 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 14 -n 15 -t 5 -a &" &
ssh ubuntu@18.222.153.52 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 5 -n 15 -t 5 -a &" &
ssh ubuntu@3.18.108.162 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 6 -n 15 -t 5 -a &" &
ssh ubuntu@3.19.213.83 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 7 -n 15 -t 5 -a &" &
ssh ubuntu@13.58.250.229 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 8 -n 15 -t 5 -a &" &
ssh ubuntu@3.129.253.1 "cd nested-dkg; ./target/release/main univariate-threshold-signature -i 9 -n 15 -t 5 -a & ./target/release/main univariate-threshold-signature -i 15 -n 15 -t 5 -a &" &
