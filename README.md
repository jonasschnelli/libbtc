libbtc – A Simple and Effective C Library for Bitcoin Wallets
=============================================================

## You can find the latest version of libbtc in https://github.com/libbtc/libbtc




What is libbtc?
----------------

Libbtc is a simple and portable C library for creating and manipulating bitcoin data structures like creating keys and addresses (HD/bip32) or parsing, creating and signing transactions.

What is the Focus of Libbtc?
----------------

* minimum dependencies (only dependency libsecp256k1)
* optimized for low mem environments like embedded/MCU
* full test coverage
* mem leak free (valgrind check during CI)

How to Build
----------------
```
./autogen.sh
./configure
make check
```
