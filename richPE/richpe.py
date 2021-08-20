#!/usr/bin/env python3

"""
Implementation of the RichPE metadata hash.
"""

import os
import sys
import pefile
import hashlib
import argparse
from struct import pack


def get_richpe(file_path=None, data=None):
    """Computes the RichPE hash given a file path or data.

    If the RichPE hash is unable to be computed, returns None.
    Otherwise, returns the computed RichPE hash.

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

    # The RichPE hash of a file is computed by computing the md5 of specific
    # metadata within  the Rich header and the PE header
    md5 = hashlib.md5()

    # Update hash using @Comp.IDs and masked counts from Rich header
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        mask = 2 ** (count.bit_length() // 2 + 1) - 1
        count |= mask
        md5.update(pack("<L", compid))
        md5.update(pack("<L", count))

    # Update hash using metadata from the PE header
    md5.update(pack("<L", pe.FILE_HEADER.Machine))
    md5.update(pack("<L", pe.FILE_HEADER.Characteristics))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.Subsystem))
    md5.update(pack("<B", pe.OPTIONAL_HEADER.MajorLinkerVersion))
    md5.update(pack("<B", pe.OPTIONAL_HEADER.MinorLinkerVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorImageVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorImageVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorSubsystemVersion))

    # Close PE file and return RichPE hash digest
    pe.close()
    return md5.hexdigest()


if __name__ == "__main__":

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="RichPE hash implementation")
    parser.add_argument("file_paths", type=str, nargs="+",
                        help="A list of file paths")
    args = parser.parse_args()

    # Compute and print RichPE hash of each file
    for file_path in args.file_paths:
        if not os.path.isfile(file_path):
            raise ValueError("Invalid file path: {}".format(file_path))

        richpe = get_richpe(file_path)
        file_name = os.path.basename(file_path)
        print("{}\t{}".format(file_name, richpe))
