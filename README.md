# Blockchain
Blockchain text messanger.

Blockchain is inspired by Bitcoin(of course) which stores encrypted or unencrypted text messages between users instead of transactions. Transactions have no fee so this messanger is vulnerable to basically free spam attack.

## Why?
I wrote this back in 2020 (I promise my coding skills improved, I even write comments now :) ) while still in high school as learning project as I wanted to learn how blockchains work. I also didn't want to make just anothet cryptocurrency so i added my own twist and that was storing text messages on blockchain. As I mentioned at the start this idea has some significant drawbacks.

## Usage
> **Warning:** This messenger won't work as the initial peer discovery relies on hardcoed node which is offline (but you can still run your own).

The python [Eel](https://github.com/lixkel/Blockchain) library has to be installed on the system, after that all you have to do is run the main.py with python3. There is also [CLI version](https://github.com/lixkel/Blockchain).

## Technical details

### Block structure
```
00000001 - version (4 Bytes)
0000000000000000000000000000000000000000000000000000000000000000 - previous block (32 Bytes)
9ee453f4661baadf27aa2ad55b9f0916c5af9146b2bc5e30531cf9ead14faab4 - merkle root (32 Bytes)
00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - target (32 Bytes)
6004cc10 - block timestamp (4 Bytes)
00036ac4 - nonce (4 Bytes)
01 - number of transactions (1 Byte)
02 - type of transaction (1 Byte)
0018 - size of the message (2 Bytes)
536ec3a1c48f20746f20627564652066756e676f7661c5a5 - content of the message (variable max 255 Bytes)
6004cc10 - transaction timestamp (4 Bytes)
bb03a30a81630d8447b38c7ebcdd0fbde3c04cb454fb4cad21ce98aaa375a827 - Public key of receiver (32 Bytes)
35f7319b55185034598c724e59999cd971eeec93f48a9d1b3470501e2d8821dd - Public key of sender (32 Bytes)
9014b0b4e7976b641e322e6ec8d4b6c8e2195a4baf8a43ca5d28bb2159379d030e531f2da8e55edb9597e3e959995cdc9b7bc11b6f849e479d9b8536f52d880f - signature (64 Bytes)
```

### Network message structure
```
Header:
12 - command
4 - lenght of payload


Message types:

version:
4 - version
4 - timestamp
4 - best height
4 - address of receiving node
2 - port of transmitter

getheaders:
32 - chainwork
1 - number of header hashes provided not including the stop hash
32x - block hashes
32 - stopping hash

headers:
1 - number of headers
32x - headers

getblocks:
1 - number of headers
32x - headers

block:
variable - block

addr:
2 - number of addresses
4 - ip address
2 - port
4 - timestamp

getaddr:
nothing

active:
nothing
```

### Types of messages (transactions)
```
00
x25519 Diffie-Hellman key exchange:

00 - type of transaction (1 Byte)
29c439c35d03757de49091ad03ddee74626e06164d608cb3a1370ce36681e163 - x25519 public key (32 Bytes)
5F44192B - transaction timestamp (4 Bytes)
bb03a30a81630d8447b38c7ebcdd0fbde3c04cb454fb4cad21ce98aaa375a827 - Public key of receiver (32 Bytes)
35f7319b55185034598c724e59999cd971eeec93f48a9d1b3470501e2d8821dd - Public key of sender (32 Bytes)
22e4502357641236fe8815a6b2708ee1a1261ff136fa3f43cfb048e88ea49b9c8cd3f53c349fafcca6aac6a492767f3df3839bc309c3ca66bb6da143565f3c0e - signature (64 Bytes)


01
message encrypted with Chacha20:

01 - type of transaction (1 Byte)
f24ee471ab278a14bf9f44395fb21ab4 - nonce (16 Bytes)
0018 - size of the message (2 Bytes)
5374726f6ac3a1726e652073c3ba2075c5be20646f6d6121 - content of the message (variable max 255 Bytes)
5F44192B - transaction timestamp (4 Bytes)
bb03a30a81630d8447b38c7ebcdd0fbde3c04cb454fb4cad21ce98aaa375a827 - Public key of receiver (32 Bytes)
35f7319b55185034598c724e59999cd971eeec93f48a9d1b3470501e2d8821dd - Public key of sender (32 Bytes)
22e4502357641236fe8815a6b2708ee1a1261ff136fa3f43cfb048e88ea49b9c8cd3f53c349fafcca6aac6a492767f3df3839bc309c3ca66bb6da143565f3c0e - signature (64 Bytes)


02
unencrypted message:

02 - type of transaction (1 Byte)
0018 - size of the message (2 Bytes)
5374726f6ac3a1726e652073c3ba2075c5be20646f6d6121 - content of the message (variable max 255 Bytes)
5F44192B - transaction timestamp (4 Bytes)
bb03a30a81630d8447b38c7ebcdd0fbde3c04cb454fb4cad21ce98aaa375a827 - Public key of receiver (32 Bytes)
35f7319b55185034598c724e59999cd971eeec93f48a9d1b3470501e2d8821dd - Public key of sender (32 Bytes)
22e4502357641236fe8815a6b2708ee1a1261ff136fa3f43cfb048e88ea49b9c8cd3f53c349fafcca6aac6a492767f3df3839bc309c3ca66bb6da143565f3c0e - signature (64 Bytes)
```