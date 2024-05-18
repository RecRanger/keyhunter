keyhunter
=========

A tool to recover lost bitcoin private keys from dead hard drives.

## Usage

```bash
python3 keyhunter.py /dev/sdX
# --or--
./keyhunter.py /dev/sdX
```

The output should list found private keys, in base58 key import format.

To import into bitcoind, use the following command for each key:

```bash
bitcoind importprivkey 5KXXXXXXXXXXXX
bitcoind getbalance
```

DONATIONS --> 1YAyBtCwvZqNF9umZTUmfQ6vvLQRTG9qG
