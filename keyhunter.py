#!/usr/bin/env python3


import argparse
import hashlib
import logging
import sys
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# bytes to read at a time from file (10 MiB)
READ_BLOCK_SIZE = 10 * 1024 * 1024

MAGIC_BYTES = b"\x01\x30\x82\x01\x13\x02\x01\x01\x04\x20"
MAGIC_BYTES_LEN = len(MAGIC_BYTES)


B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_BASE = len(B58_CHARS)  # literally 58


def b58encode(v):
    """encode v, which is a string of bytes, to base58."""

    long_value = 0
    for i, c in enumerate(v[::-1]):
        long_value += (256**i) * c

    result = ""
    while long_value >= B58_BASE:
        div, mod = divmod(long_value, B58_BASE)
        result = B58_CHARS[mod] + result
        long_value = div
    result = B58_CHARS[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c != 0:
            break
        nPad += 1

    return (B58_CHARS[0] * nPad) + result


def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def EncodeBase58Check(secret):
    hash = Hash(secret)
    return b58encode(secret + hash[0:4])


def find_keys(filename: str | Path) -> set[str]:
    keys = set()
    with open(filename, "rb") as f:
        logger.info(f"Opened file: {filename}")

        # read through target file one block at a time
        while data := f.read(READ_BLOCK_SIZE):
            # look in this block for keys
            pos = 0  # index in the block
            while (pos := data.find(MAGIC_BYTES, pos)) > -1:
                # find the magic number
                key_offset = pos + MAGIC_BYTES_LEN
                key_data = "\x80" + data[key_offset : key_offset + 32]  # noqa: E203
                priv_key_wif = EncodeBase58Check(key_data)
                keys.add(priv_key_wif)
                logger.info(
                    f"Found key at offset {key_offset:,} = 0x{key_offset:02x}: {priv_key_wif}"
                )
                pos += 1

            # are we at the end of the file?
            if len(data) == READ_BLOCK_SIZE:
                logger.info("At end of file. Seeking back 32 bytes.")
                # make sure we didn't miss any keys at the end of the block
                f.seek(f.tell() - (32 + MAGIC_BYTES_LEN))
    return keys


def setup_logging(log_filename: Optional[str | Path] = None):
    # Create a logger object
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Create a console handler and set level to debug
    console_handler = logging.StreamHandler(sys.stdout)  # Using stdout instead of stderr
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Optionally add a file handler
    if log_filename:
        file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def main_keyhunter(haystack_filename: str | Path, log_path: Optional[str | Path] = None):
    setup_logging(log_path)
    logger.info("Starting keyhunter")

    keys = find_keys(haystack_filename)

    logger.info(f"Found {len(keys)} keys: {keys}")

    if len(keys) > 0:
        logger.info("Keys (as base58 WIF private keys):")
        for key in keys:
            print(key)

    logger.info("Finished keyhunter")


def get_args():
    parser = argparse.ArgumentParser(description="Find Bitcoin private keys in a file.")
    parser.add_argument("filename", help="The file to search for keys.")
    parser.add_argument("--log", help="Log file to write logs to.")
    return parser.parse_args()


def main_cli():
    args = get_args()
    main_keyhunter(args.filename, log_path=args.log)


if __name__ == "__main__":
    main_cli()
