# nested-dkg

## Threshold Signatures

### Normal - Implementation found in crates/univariate-dkg.
Steps:
1. Recover secret key/public key from file (assumes dkg already ran)
2. Connect to all nodes over TCP sockets
3. Sign a 32 byte message of all 0’s
4. Verify signature
5. Send signature to all other nodes
6. Wait for t (threshold) signatures, verifying each signature as they are received
7. Once t signatures are received, aggregate them with Lagrange interpolation
8. Verify the aggregated signature

Results (121 nodes, threshold 40, averages over 10 runs):
- Total Time: 36573.827ms
- Sign Time: 3.681ms
- Verify Signature Time: 37.456ms
- Aggregate Time: 132.510ms
- Verify Aggregated Time: 32.278854ms

### Nested - Implementation found in crates/bivariate-dkg.
Steps for node i, j:
1. Recover secret key/public key from file (assumes dkg already ran)
2. Connect to all nodes over TCP sockets
3. Sign a 32 byte message of all 0’s
4. Verify signature
5. Send signature to all other nodes in group i
6. Wait for t’ (threshold) signatures, verifying each signature as they are received
7. Once t’ signatures are received, aggregate them to from a group signature with lagrange interpolation
8. Verify the group signature
9. Randomly select n log (n) nodes in other groups to send the group signature to.
10. Wait for t (threshold) signatures, verifying each signature as they are received
11. Once t’ signatures are received, aggregate them to from a full signature with Lagrange interpolation
12. Verify the full signature

Results (121 nodes, 11x11, threshold t = 5, t’ = 8 averages over 10 runs):
- Total Time: 8394.500ms
- Sign Time: 2.593ms
- Verify Time: 33.229ms
- Aggregate Group Signature Time: 45.055ms
- Verify Group Signature Time: 57.063ms
- Aggregate All Group Signature Time: 14.106ms
- Verify All Group Signature Time: 27.393ms
        

## Basic DKG

***Implementations DO NOT include proofs, encrypting shares, or verification***
    
### Univariate DKG - Implementation found in crates/univariate-dkg
Steps:
1. Every node connects to every other node by TCP socket
2. Node generates local shares and corresponding public polynomial
3. Send shares and polynomial to all other nodes
4. Wait until it has received shares and public polynomial from all nodes
5. Node find the combined public polynomial by summing all polynomials it received
6. Node finds it’s signing key by summing it’s share from all nodes
7. Verify the signing key by signing a message and checking it against the nodes public key given by the public polynomial

Results (121 nodes, threshold 40, average of 10 runs):
- Total Time: 1952.238ms
- Generate Shares Time: 539.286ms
- Combine Shares Time: 167.575ms
- Sign and Verify Time: 35.370ms

### Bivariate DKG - Implementation found in crates/bivariate-dkg
Steps:
1. Every node connects to every other node by TCP socket
2. Node generates local shares and corresponding public polynomial
3. Send shares and polynomial to all other nodes
4. Wait until it has received shares and public polynomial from all nodes
5. Node find the combined public polynomial by summing all polynomials it received
6. Node finds it’s signing key by summing it’s share from all nodes
7. Verify the signing key by signing a message and checking it against the nodes public key given by the public polynomial

Results (121 nodes, 11x11, threshold t = 5, t’ = 8, average of 10 runs):
- Total Time: 1993.970ms
- Generate Shares Time: 675.604ms
- Combine Shares Time: 174.598ms
- Sign and Verify Time: 34.165ms

## NIDKG

### Basic NIDKG - Implementation in crates/nidkg. This implementation uses dfinity to call the functions they use for NiDKG. All code written here is just a sequence of api calls.
Steps for Dealer:
1. Generate shares and public polynomial
2. Encrypt shares with BTE encryption
3. Generate Sharing/Chunking proofs
4. Send dealing (encrypted shares, public polynomial, and proofs) to other dealers
5. Verify all dealings from other dealers are valid by checking proofs
6. Combine all dealings into a transcript by summing the public polynomials and creating a list of the encrypted shares for each node
7. Send transcript to all non dealer nodes

Steps for non dealer:
1. Wait for a dealing
2. Decrypt all shares belonging to node with BTE
3. Sum all shares to get signing key
4. Sign and verify a message with signing key

Results (121 nodes, 4 dealers, threshold 40, averages of 10 runs):
- Total Time Receiver: 62482.044ms
- Time to Recover Key: 50752.148ms
- Total Time Dealer: 15033.247ms
- Time to Generate Dealing: 3341.201ms
- Time to Verify: 4824.868ms
- Time to Combine Dealings: 1974.381ms

### NIDKG With El Gamal Decryption - Implementation in crates/optimized-univar with api implemented in crates/dfinity. This implementation only changes the decryption step of the BTE encryption to use El Gamal rather than BTE. Otherwise, this implementation is the same as the basic NIDKG

Steps for Dealer:
1. Generate shares and public polynomial
2. Encrypt shares with BTE encryption
3. Generate Sharing/Chunking proofs
4. Send dealing (encrypted shares, public polynomial, and proofs) to other dealers
5. Verify all dealings from other dealers are valid by checking proofs
6. Combine all dealings into a transcript by summing the public polynomials and creating a list of the encrypted shares for each node
7. Send transcript to all non dealer nodes

Steps for non dealer:
1. Wait for a dealing
2. Decrypt all shares belonging to node with El Gamal
3. Sum all shares to get signing key
4. Sign and verify a message with signing key

Results (121 nodes, 4 dealers, threshold 40, averages of 10 runs):
- Total Time Receiver: 59073.602ms
- Time to Recover Key: 47757.921ms
- Total Time Dealer: 13995.805ms
- Time to Generate Dealing: 3243.659ms
- Time to Verify: 4100.394ms
- Time to Combine Dealings: 1928.926ms

### Bivariate NIDKG with El Gamal Decryption - Implementation in crates/optimized-nidkg and crates/dfinity. The steps of this implementation are identical to the nidkg with El Gamal Decryption, aside from using bivariate polynomial to generate shares and changing the sharing proof. While generation of the sharing proof is included in the times, the verification of said sharing proof isn’t. The sharing proof is not correct, so its verification is omitted. The verification times only include the chunking proof.
    
Steps for Dealer:
1. Generate bivariate shares and public polynomial
2. Encrypt shares with BTE encryption
3. Generate Chunking proof as before
4. Generate a sharing proof for each group’s shares, giving N sharing proofs
5. Send dealing (encrypted shares, public polynomial, and proofs) to other dealers
6. Verify all dealings from other dealers are valid by checking proofs
7. Combine all dealings into a transcript by summing the public polynomials and creating a list of the encrypted shares for each node
8. Send transcript to all non dealer nodes

Steps for non dealer:
1. Wait for a dealing
2. Decrypt all shares belonging to node with El Gamal
3. Sum all shares to get signing key
4. Sign and verify a message with signing key
    
Results (121 nodes, 11x11, threshold t = 5, t’ = 8, 4 dealers, average of 10 runs):
- Total Time Receiver: 55648.473ms
- Time to Recover Key: 46829.810ms
- Total Time Dealer: 9699.562ms
- Time to Generate Dealing: 3190.658ms
- Time to Verify: 2953.555ms
- Time to Combine Dealings: 3.893ms

The Verify and Combine Dealings times are much lower. For the verify, it’s due to sharing proofs not working. For the combine dealings, I believe it is due to resharing. The NIDKG code does interpolation for resharing purposes and we are skipping that step here because including it didn’t give correct results.


### Description of Codebase
Basic DKG uses dfinity’s remote codebase for signing/aggregating/verifying messages. We use a bls library (same one used by dfinity) for group operations. We wrote our own implementation for polynomials and public coefficients and those implementations are found in crates/types.

The Basic NIDKG uses dfinity’s remote codebase for all operations. We just call api operations they have available.

The NIDKG’s using El Gamal decryption use a local clone of relevant packages from  dfinity needed for the changes. While these cloned packages contain many files, only a handful were modified. These packages are found in crates/dfinity.

El Gamal Decryption Changes
All files relevant to BTE and Proofs are found in [crates/dfinity/fs_ni_dkg/src](https://github.com/coltonfike/nested-dkg/tree/main/crates/dfinity/fs_ni_dkg/src). I did not modify these files in any significant way (I did add some print statements to help with debugging, but those should all be removed now), however I did add a file, [el_gamal.rs](https://github.com/coltonfike/nested-dkg/tree/main/crates/dfinity/fs_ni_dkg/src/el_gamal.rs). el_gamal.rs contains two functions, kgen and dec_chunks. kgen is the key generation function for El Gamal. The BTE Encryption does not directly store the x needed for El Gamal decryption, so we added a new key generation function for it. Key generation is assumed to have already been run on all tests, so this function does not contribute to any of our results. dec_chunks decrypts all chunks using El Gamal rather than the BTE scheme.

Next I needed to add functions that call these new ones. All changes can be found in [crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381](https://github.com/coltonfike/nested-dkg/tree/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381). The first change is adding a new way to call the key gen function, [create_forward_secure_pair_el_gamal](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs#L95). The next change is calling the new decryption function, the change is [compute_threshold_signing_key_univar](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/transcript.rs#L414) and [decrypt_univar](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs#L390) in encryption.rs.

Bivariate Polynomial Changes
There are many changes to make this work, but all are found in [crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs), [crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/transcript.rs](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/transcript.rs), and
[crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/dealing.rs](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/dealing.rs).

Functions that were changed are named the same as the corresponding original function but with an added suffix, like prove_sharing_el_gamal is the changed version for prove_sharing.
Prove Sharing is not correct. The code for sharing proofs is found in [prove_sharing_el_gamal](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs#L475) and [verify_zk_proofs_el_gamal](https://github.com/coltonfike/nested-dkg/blob/main/crates/dfinity/bls12_381/src/ni_dkg/groth20_bls12_381/encryption.rs#L654). There is also a section in [generate_shares_for_nidkg](https://github.com/coltonfike/nested-dkg/blob/main/crates/bivariate-dkg/src/dkg.rs#L32) that was adjusted.
