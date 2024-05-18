keyhunter
=========

A tool to recover lost bitcoin private keys from dead hard drives.

## Usage

```bash
python3 keyhunter.py /dev/sdX

./keyhunter.py /dev/sdX
```

The output should list found private keys, in base58 key import format.

To import into bitcoind, use the following command:

```bash
bitcoind importprivkey 5K????????????? yay
bitcoind getbalance
```

DONATIONS --> 1YAyBtCwvZqNF9umZTUmfQ6vvLQRTG9qG
