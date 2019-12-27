#!/usr/bin/env python3

"""
Implementation of the Rich header md5 hash.
"""

import os
import sys
import pefile
import hashlib
import argparse
from struct import pack


def get_rich_hash(file_path=None, data=None):
    """Computes the Rich header hash given a file path or data.

    If the Rich header hash is unable to be computed, returns None.
    Otherwise, returns the computed Rich header hash.

    If both file_path and data are provided, file_path is used by default.
    """

    # Must provide either file path or data
    if file_path is None and data is None:
        raise ValueError("Must provide a file path or data")

    # Attempt to parse PE header
    try:
        pe = pefile.PE(name=file_path, data=data, fast_load=True)
    except pefile.PEFormatError:
        return None

    # Attempt to parse Rich header
    rich_header = pe.parse_rich_header()
    if rich_header is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = rich_header.get("values", None)
    if len(rich_fields) % 2 != 0:
        return None

    # The Rich header hash of a file is computed by computing the md5 of the
    # decoded rich header without the rich magic and the xor key, but with
    # the dans magic. It can be used with yara hash.md5(pe.rich_signature.clear_data)
    md5 = hashlib.md5()
    md5.update(rich_header["clear_data"])
    
    # Close PE file and return RichPE hash digest
    pe.close()
    return md5.hexdigest()


if __name__ == "__main__":

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Rich header hash implementation")
    parser.add_argument("file_paths", type=str, nargs="+",
                        help="A list of file paths")
    args = parser.parse_args()

    # Compute and print Rich header hash of each file
    for file_path in args.file_paths:
        if not os.path.isfile(file_path):
            raise ValueError("Invalid file path: {}".format(file_path))

        rich_hash = get_rich_hash(file_path)
        file_name = os.path.basename(file_path)
        print("{}\t{}".format(file_name, rich_hash))
