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

# magic bytes reference: https://bitcointalk.org/index.php?topic=2745783.msg28084524#msg28084524
MAGIC_BYTES_LIST = [
    bytes.fromhex("01308201130201010420"),  # old, <2012
    bytes.fromhex("01d63081d30201010420"),  # new, >2012
]
MAGIC_BYTES_LEN = 10  # length of each element in MAGIC_BYTES_LIST
assert all(len(magic_bytes) == MAGIC_BYTES_LEN for magic_bytes in MAGIC_BYTES_LIST)


B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_BASE = len(B58_CHARS)  # literally 58


def b58encode(v: bytes) -> str:
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


def sha256d_hash(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def encode_base58_check(secret: bytes) -> str:
    hash = sha256d_hash(secret)
    return b58encode(secret + hash[0:4])


def find_keys(filename: str | Path) -> set[str]:
    """Searches a file for Bitcoin private keys.
    Returns a set of private keys as base58 WIF strings.
    """

    keys = set()
    key_count = 0
    with open(filename, "rb") as f:
        logger.info(f"Opened file: {filename}")

        # read through target file one block at a time
        while block_bytes := f.read(READ_BLOCK_SIZE):
            # look in this block for each key
            for magic_bytes in MAGIC_BYTES_LIST:
                pos = 0  # index in the block
                while (pos := block_bytes.find(magic_bytes, pos)) > -1:
                    # find the magic number
                    key_offset = pos + MAGIC_BYTES_LEN
                    key_data = b"\x80" + block_bytes[key_offset : key_offset + 32]  # noqa: E203
                    priv_key_wif = encode_base58_check(key_data)
                    is_new_key = priv_key_wif not in keys
                    key_count += 1
                    keys.add(priv_key_wif)
                    global_offset = f.tell() - len(block_bytes) + key_offset

                    logger.info(
                        f"Found {('new key' if is_new_key else 'key again')} "
                        f"at offset {global_offset:,} = 0x{global_offset:_x} "
                        f"(using magic bytes {magic_bytes.hex()}): {priv_key_wif} "
                        f"({key_count:,} keys total, {len(keys):,} unique keys)"
                    )
                    pos += 1

            # Make sure we didn't miss any keys at the end of the block.
            # After scanning the block, seek back so that the next block includes the overlap.
            if len(block_bytes) == READ_BLOCK_SIZE:
                f.seek(f.tell() - (32 + MAGIC_BYTES_LEN))

    logger.info(f"Closed file: {filename}")
    return keys


def setup_logging(log_filename: Optional[str | Path] = None) -> logging.Logger:
    # Create a logger object
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Create a console handler and set level to debug
    console_handler = logging.StreamHandler(sys.stderr)
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


def main_keyhunter(
    haystack_file_path: str | Path,
    log_path: Optional[str | Path] = None,
    output_keys_file_path: Optional[str | Path] = None,
):
    setup_logging(log_path)
    logger.info("Starting keyhunter")

    if log_path:
        logger.info(f"Logging to console, and file: {log_path}")
    else:
        logger.info("Logging to console only.")

    if not Path(haystack_file_path).is_file():
        raise FileNotFoundError(f"File not found: {haystack_file_path}")

    keys = find_keys(haystack_file_path)

    keys = sorted(list(keys))
    logger.info(f"Found {len(keys)} keys: {keys}")

    if len(keys) > 0:
        logger.info("Printing keys (as base58 WIF private keys) for easy copying:")
        for key in keys:
            print(key)

    if output_keys_file_path:
        with open(output_keys_file_path, "w") as f:
            for key in keys:
                f.write(key + "\n")

    logger.info(f"Finished keyhunter. Found {len(keys):,} keys.")


def get_args():
    parser = argparse.ArgumentParser(description="Find Bitcoin private keys in a file.")
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        dest="input_file_path",
        help="The input file (disk image, corrupt wallet.dat, etc.) to search for keys.",
    )
    parser.add_argument("-l", "--log", dest="log_path", help="Log file to write logs to.")
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file_path",
        help="Output file to write the WIF write keys to.",
    )
    return parser.parse_args()


def main_cli():
    args = get_args()
    main_keyhunter(
        args.input_file_path,
        log_path=args.log_path,
        output_keys_file_path=args.output_file_path,
    )


if __name__ == "__main__":
    main_cli()
