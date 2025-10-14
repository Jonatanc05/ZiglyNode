## ZiglyNode - Zig Lyght Node

#### A Bitcoin light client with minimal dependencies written in Zig

- I like [handmade software](https://handmade.network/)
- I like [Bitcoin](https://btcmaxis.com/)
- I like [Zig](https://ziglang.org/)

## Build Requirements

- Currently building with Zig 0.15.1
    - See https://ziglang.org/download/#release-0.15.1
    - You can use [version-fox](https://vfox.dev/guides/quick-start.html) or [zvm](https://www.zvm.app/) to manage Zig versions

- Windows 11 and Ubuntu WSL are usually tested.

- Optionally add a file called `.privkey` to the your working directory containing a private key to test. Do not use a real key.
    - `echo 0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a2a3a4a0a1a > .privkey`
    - Will be created automatically (with this sample value) if absent

This file should contain hex characters representing the private key to use when signing transactions. **DO NOT USE REAL WALLET INFORMATION WITH THIS SOFTWARE**.

## Features

All features here are implemented (at least almost) from scratch. Using only the standard library and an external RIPEMD hash function.

- Amateur cryptography (ECDSA)
- Bitcoin primitives (Address, Transaction, Block) with serialization
- Signing valid transactions (see https://mempool.space/signet/tx/d5cf8e758abc178121736c9cbb0defe075ef50da4dfb4e736b19f2a2ff66dd14)
- Basic Script interpreter (tested P2PK, P2PKH and P2WPKH)
- Ability to communicate with the Bitcoin network
    - Handshake with other peers
    - Get block headers, check they are valid and write/load them on disk
    - Get neighbour peers to discover the network
- Multi-threaded handshakes for speed

## Screenshots

Example of current output:

```
> zig build run
info: loading block headers from path/to/ZiglyNode/blockheaders.dat

Your address is mwWdV8mUAE2rQugQLtRJdrqxi3rf4R3xbq

################################################

Hello dear hodler, tell me what can I do for you
1. View blockchain state
2. Connect to a new peer
3. List peers (interact)
4. Sign a transaction
5. Exit

1

=== Blockchain State ===
Block headers count: 66001
Latest block hash: 00000000071d7e8a0f4895e60c1073df9311d65a85244be1ee6369c9506281af
========================

2

Enter the IPv4 or IPv6 [without port] [default=127.0.0.1]: 
Enter the port [numeric, default=8333]: 

Connection established successfully with
Peer ID: 1
IP: 127.0.0.1:8333

i 1

What do you want to do?
1. disconnect from peer
2. ask for block headers
3. ask for new peers and connect
2
Requesting for block headers...
Unexpected and unsupported command received
Unexpected and unsupported command received
2000 new blocks received!

1

=== Blockchain State ===
Block headers count: 68001
Latest block hash: 0000000000d991791fdfdbccbbc2a73d2f86ccf78e2d0a7ce7675f40b5986b3e
========================

i 1

What do you want to do?
1. disconnect from peer
2. ask for block headers
3. ask for new peers and connect
3
info: Requesting for new peers and connecting...
Unexpected and unsupported command received
info: Connecting to [2a01:4f8:c2c:5011::1]:8333...
info: Connecting to 62.171.183.58:8333...
info: Connecting to 34.97.22.229:8333...
info: Connecting to 85.158.1.212:8333...
info: Connecting to 99.8.113.140:8333...
info: Connecting to 174.161.123.250:8333...
info: Connecting to 109.87.166.145:8333...
info: Connecting to 76.28.244.128:8333...
info: Connected to [2a01:4f8:c2c:5011::1]:8333
info: Connected to 62.171.183.58:8333
info: Connected to 109.87.166.145:8333
info: Connected to 34.97.22.229:8333
info: Connection to 85.158.1.212:8333 failed: Timeout
info: Connection to 99.8.113.140:8333 failed: Timeout
info: Connection to 76.28.244.128:8333 failed: Timeout
info: Connection to 174.161.123.250:8333 failed: Timeout
info: Connected to 4 new peers

################################################

Hello dear hodler, tell me what can I do for you
1. View blockchain state
2. Connect to a new peer
3. List peers (interact)
4. Sign a transaction
5. Exit

3

======== Peer list ========

1: 127.0.0.1:8333 | /Satoshi:27.1.0/Knots:20240801

2: 3.143.194.71:8333 | /Satoshi:27.1.0/

3: 86.104.228.24:8333 | /Satoshi:27.0.0/

4: 170.253.31.42:8333 | /Satoshi:28.1.0/

5: 66.163.223.69:8333 | /Satoshi:27.1.0/

6: [2a02:22a0:bbb3:dc10:50e1:57ff:fe70:9492]:8333 | /Satoshi:29.0.0/

===========================

Type 'i' followed by a number to interact with a peer (ex.: 'i 2')

5
info: saving data on disk...

```


## TODO

- [ ] Networking improvements
  - [x] Concurrent connect calls
  - [ ] Consume next address immediately after a connection fails (not sure)
- [x] Check difficulty when receiving block headers
- [ ] P2SH
- [ ] SegWit
- [ ] Continous requests (enter synchronization mode)
- [ ] SPV

Issues:
- [ ] We can't seem to receive blocks from `/Satoshi:25.1.0/`
  - Minimum version we know that works is `/Satoshi:27.0.0/`
  - Actually it might not be about version? `/Satoshi:25.0.0/` can work

