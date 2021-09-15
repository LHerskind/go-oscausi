# Oscausi

_Disclaimer: This project was written for me to learn GO, so there may be better libraries and ways to do stuff._

Oscausi is a scheme for practical private transactions that does not rely on a trusted setup. This means that there is
no toxic waste. Furthermore, it relies only on well-tested cryptographic assumptions. This means that the individual
parts of the proof are somewhat digestable, especially if compared with ZK-SNARKs (a practical privacy scheme with a
trusted setup).

The project is quite similar to Beams ideas around Lelantus-MW, but have some differences in the specifics around the
proof with respect to space and computation tradeoffs.

## Overview

The scheme consists of two layers. A base-layer, which supports confidential (but not anonymous) transactions, and a
second-layer, which enhance anonymity.

In practice, this is enforced by utilising the **MimbleWimble** scheme as the base-layer. This means that the base-layer
will have similar to that of Grin. If an attacker is to monitor the network, he could build the transaction graph (not
good for us). To combat this, we use the second layer.

The second layer is enhancing privacy, by utilising a set of *shielded* coins. When we perform a transfer, we will then
proof that the coin we are spending is within a large set of shielded coins. In practice, we do so by utilising a
One-Out-Of-Many similar to the one proposed in Lelantus, with some changes to make it compatible with the MimbleWimble
inputs. While this methods sounds very much like what we get in Monero, the set in which we hide (the anonymity set) can
be far greater. For these One-Out-Of-Many proofs, we can hide in a set of $2^16$ other outputs, while keeping the
proof-size around 1.5 kb - neat!

### How does this work?

## Testing MimbleWimble

To make a test of our minimal implementation of the MimbleWimble scheme, here just creating transactions, we perform a
transaction 1 input, and 2 outputs. Say Alice have 25 coins, she wants to send 15 to Bob, and must therefore make a
change output of 10. A -> B, C, where A = 25, B = 15,

## Testing Oscausi

To test the second layer (could also be called the Oscausi layer), we will test 2 scenarios, i) where we spend one
shielded coin, to one non-shielded, and ii) from two shielded to two non-shielded. This is simply to show that it is
possible to spend multiple shielded coins within the same transaction. In practice, we will first initialize a list of
shielded of size $N$, where we own either one or two of these outputs.

## Combining transactions

As the Ethos of MimbleWimble puts an emphasis on pruning, we try our best to follow along. This means that we support
the combination of two transfers into one larger transaction. Furthermore, because it functions on top of MimbleWimble,
we have the same ability to prune intermediates. One should here note, that while a shielded coin is logically an
intermediate, we cannot prune it, as it is technically seen as a "fresh coin".

# Some benchmarking

The benchmarking here is done on the basis of a single spending, here both the mind

| n | m | N | proving | verification |
|---|---|---|---|---|
| 2 | 10 | 1024 | 284 ms | 60 ms |
| 4 | 5 | 1024 | 156 ms | 55 ms |
| 4 | 6 | 4096 | 627 ms | 192 ms |
| 8 | 4 | 4096 | 456 ms | 199 ms |
| 4 | 7 | 16384 | 2.8 s | 733 ms |
| 8 | 5 | 32768 | 4.26 s | 1.46 s|
| 4 | 8 | 65536 | 13.58 s | 3.00 s |
| 16 | 4 | 65536 | 6.95 s | 2.88 s |
| 10 | 5 | 100000 | 13.15 s | 4.9 s|


